"""STIG Explorer web server (Python standard library only).

Serves the web UI from web/ and a read-only JSON API backed by an in-memory
SQLite FTS5 index built from web/data/stig_data.js at startup.

    python -m stig_explorer.server [--host 127.0.0.1] [--port 8080]

API:
    GET /api/health
    GET /api/stigs
    GET /api/topics
    GET /api/tags
    GET /api/search?q=<fts query>&stig=RHEL_9&severity=high&topic=ssh&nist=AC-7&rev=rev5&tag=fmcc&limit=50&offset=0
    GET /api/rule/<rule id | V-id | STIG id>
"""

from __future__ import annotations

import argparse
from collections import deque
import threading
import time
import json
import os
import re
import signal
import sqlite3
import sys
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import build, tags

WEB = build.ROOT / "web"
MAX_QUERY_LENGTH = 256
MAX_URL_LENGTH = 4096
MAX_FILTER_LENGTH = 256
MAX_CONCURRENT_CLIENTS = 32
SOCKET_TIMEOUT_SECONDS = 10
RATE_LIMIT_PER_MINUTE = 240


class RateLimiter:
    """Bounded, per-address API request rate limiter (proxy limits still advised)."""
    def __init__(self):
        self.lock = threading.Lock()
        self.hits = {}

    def allow(self, address: str) -> bool:
        now = time.monotonic()
        with self.lock:
            if len(self.hits) > 1024:
                self.hits = {ip: hits for ip, hits in self.hits.items() if hits and hits[-1] >= now - 60}
                if len(self.hits) > 1024:
                    self.hits.clear()
            hits = self.hits.setdefault(address, deque())
            while hits and hits[0] < now - 60:
                hits.popleft()
            if len(hits) >= RATE_LIMIT_PER_MINUTE:
                return False
            hits.append(now)
            return True


RATE_LIMITER = RateLimiter()


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    """Prevent unlimited concurrent request-handler threads."""
    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT_CLIENTS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                               "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


class Index:
    def __init__(self, data: dict, tagdata: dict | None = None):
        self.data = tags.apply(data, tagdata)
        self.tag_notes = (tagdata or tags.load())["rules"]
        self.rules = {r["id"]: r for r in data["rules"]}
        self.alias = {}
        for r in data["rules"]:
            self.alias[r["vuln_id"].upper()] = r["id"]
            self.alias[r["stig_id"].upper()] = r["id"]
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.execute(
            "CREATE VIRTUAL TABLE fts USING fts5(rid UNINDEXED, title, ids, settings, body, "
            "tokenize='unicode61 tokenchars ''-_.''')")
        self.db.execute("CREATE TABLE meta(rid TEXT PRIMARY KEY, stig TEXT, severity TEXT, topics TEXT, sort TEXT)")
        rows, meta = [], []
        for r in data["rules"]:
            nist = {rev: sorted({i for c in r["ccis"] for i in data["ccis"].get(c, {}).get(rev, [])})
                    for rev in ("rev3", "rev4", "rev5")}
            r["nist"] = nist
            ids = " ".join([r["id"], r["vuln_id"], r["stig_id"], r["srg"], *r["ccis"], *nist["rev5"], *nist["rev3"]])
            settings = " ".join(f"{s['target']} {s['name']} {s['value']}" for s in r["settings"])
            body = " ".join([r["discussion"], r["check"], r["fix"], r["plain"],
                             *(data["topics"][t]["name"] for t in r["topics"])])
            rows.append((r["id"], r["title"], ids, settings, body))
            meta.append((r["id"], r["stig"], r["severity"], ",".join(r["topics"]), f"{r['stig']}:{r['stig_id']}"))
        self.db.executemany("INSERT INTO fts VALUES (?,?,?,?,?)", rows)
        self.db.executemany("INSERT INTO meta VALUES (?,?,?,?,?)", meta)
        self.db.commit()

    @staticmethod
    def _fts_query(q: str) -> str:
        # Quote every token so user input can't inject FTS syntax; keep "phrases".
        parts = re.findall(r'"([^"]+)"|(\S+)', q)
        toks = []
        for phrase, word in parts:
            t = (phrase or word).replace('"', "")
            if t:
                toks.append(f'"{t}"' + ("" if phrase else "*"))
        return " AND ".join(toks)

    def search(self, params: dict) -> dict:
        if any(len(str(v)) > MAX_FILTER_LENGTH for v in params.values()):
            raise ValueError("Search filter is too long")
        q = params.get("q", "").strip()
        if len(q) > MAX_QUERY_LENGTH:
            raise ValueError("Search query is too long")
        where, args = [], []
        for key, col in (("stig", "m.stig"), ("severity", "m.severity")):
            vals = [v for v in params.get(key, "").split(",") if v]
            if vals:
                where.append(f"{col} IN ({','.join('?' * len(vals))})")
                args += vals
        if tg := params.get("tag"):
            wanted = {t for t in tg.split(",") if t}
            tagged = [rid for rid, r in self.rules.items() if wanted & set(r["tags"])]
            if not tagged:
                return {"total": 0, "offset": 0, "limit": 0, "results": []}
            where.append(f"m.rid IN ({','.join('?' * len(tagged))})")
            args += tagged
        if t := params.get("topic"):
            where.append("(',' || m.topics || ',') LIKE ?")
            args.append(f"%,{t},%")
        rev = params.get("rev") if params.get("rev") in ("rev3", "rev4", "rev5") else "rev5"
        ctl = re.sub(r"\s+", "", params.get("nist", "").upper())
        limit = max(1, min(int(params.get("limit", 50) or 50), 500))
        offset = max(0, int(params.get("offset", 0) or 0))
        if offset > 100_000:
            raise ValueError("Search offset exceeds limit")
        if q:
            sql = ("SELECT m.rid FROM fts JOIN meta m ON m.rid = fts.rid WHERE fts MATCH ?"
                   + "".join(f" AND {w}" for w in where) + " ORDER BY bm25(fts, 0, 10, 8, 4, 1)")
            all_args = [self._fts_query(q), *args]
        else:
            sql = "SELECT m.rid FROM meta m" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY m.sort"
            all_args = args
        try:
            ids = [row[0] for row in self.db.execute(sql, all_args)]
        except sqlite3.OperationalError as exc:
            return {"error": f"bad query: {exc}"}
        if ctl:
            # "AC-1" must match "AC-1 a" but not "AC-12": prefix match not followed by a digit.
            def hit(rid: str) -> bool:
                for idx in self.rules[rid]["nist"][rev]:
                    n = re.sub(r"\s+", "", idx.upper())
                    if n.startswith(ctl) and not n[len(ctl):len(ctl) + 1].isdigit():
                        return True
                return False
            ids = [i for i in ids if hit(i)]
        page = ids[offset:offset + limit]
        return {"total": len(ids), "offset": offset, "limit": limit,
                "results": [self.summary(self.rules[i]) for i in page]}

    def summary(self, r: dict) -> dict:
        return {k: r[k] for k in ("id", "vuln_id", "stig_id", "stig", "severity", "cat", "title", "plain",
                                  "topics", "ccis", "tags")} | {"nist_rev5": r["nist"]["rev5"]}

    def rule(self, key: str) -> dict | None:
        rid = key if key in self.rules else self.alias.get(key.upper())
        if not rid:
            return None
        r = dict(self.rules[rid])
        r["topic_details"] = {t: self.data["topics"][t] for t in r["topics"]}
        r["cci_details"] = {c: self.data["ccis"].get(c, {}) for c in r["ccis"]}
        r["tag_details"] = [self.data["tag_defs"][t] | {"notes": n} for t, n in self.tag_notes.get(rid, [])]
        return r


class Handler(SimpleHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(SOCKET_TIMEOUT_SECONDS)

    index: Index = None  # set in main()
    server_version = "STIGExplorer"
    sys_version = ""

    def end_headers(self):
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        super().end_headers()

    def _json(self, obj, status=HTTPStatus.OK):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if len(self.path) > MAX_URL_LENGTH:
            return self._json({"error": "Request URL is too long"}, HTTPStatus.REQUEST_URI_TOO_LONG)
        url = urlparse(self.path)
        if not url.path.startswith("/api/"):
            return super().do_GET()
        if not RATE_LIMITER.allow(self.client_address[0]):
            return self._json({"error": "API rate limit exceeded"}, HTTPStatus.TOO_MANY_REQUESTS)
        try:
            params = {k: v[-1] for k, v in parse_qs(url.query, max_num_fields=20).items()}
        except ValueError:
            return self._json({"error": "Too many query parameters"}, HTTPStatus.BAD_REQUEST)
        idx = self.index
        try:
            if url.path == "/api/health":
                return self._json({"status": "ok", "rules": len(idx.rules), "generated": idx.data["meta"]["generated"]})
            if url.path == "/api/stigs":
                return self._json(idx.data["stigs"])
            if url.path == "/api/tags":
                return self._json(list(idx.data["tag_defs"].values()))
            if url.path == "/api/topics":
                return self._json(idx.data["topics"])
            if url.path == "/api/search":
                res = idx.search(params)
                return self._json(res, HTTPStatus.BAD_REQUEST if "error" in res else HTTPStatus.OK)
            if url.path.startswith("/api/rule/"):
                r = idx.rule(url.path[len("/api/rule/"):])
                return self._json(r) if r else self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_HEAD(self):  # noqa: N802
        if urlparse(self.path).path.startswith("/api/"):
            self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
            self.end_headers()
            return
        super().do_HEAD()

    def log_message(self, fmt, *args):
        if os.environ.get("STIGX_QUIET") != "1":
            super().log_message(fmt, *args)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Serve STIG Explorer.")
    ap.add_argument("--host", default=os.environ.get("STIGX_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("STIGX_PORT", "8080")))
    ap.add_argument("--data", type=Path, default=build.OUT)
    args = ap.parse_args(argv)

    if not args.data.exists():
        print(f"Data file {args.data} not found. Run: python -m stig_explorer.build", file=sys.stderr)
        return 1
    Handler.index = Index(build.load(args.data))
    handler = partial(Handler, directory=str(WEB))
    httpd = LimitedThreadingHTTPServer((args.host, args.port), handler)
    # Exit promptly on SIGTERM (docker stop) - PID 1 ignores it by default.
    def _stop(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _stop)
    print(f"STIG Explorer: {len(Handler.index.rules)} rules on http://{args.host}:{args.port}/", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
