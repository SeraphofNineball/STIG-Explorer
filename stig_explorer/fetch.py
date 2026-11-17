"""Download the latest DISA STIG releases and the CCI list.

DISA's download page is a JavaScript application, but the files themselves
are served from a stable path:
    https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/<NAME>_V<v>R<r>_STIG.zip

This module probes for the newest V/R of each product and downloads it.
If DISA changes the URL scheme, download the zips manually from
https://public.cyber.mil/stigs/downloads/ and drop them into data/raw/.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import concurrent.futures as cf
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
UA = {"User-Agent": "Mozilla/5.0 (STIG-Explorer)"}

PRODUCTS = [
    "U_RHEL_7",  # sunset by DISA; final release V3R15
    "U_RHEL_8",
    "U_RHEL_9",
    "U_RHEL_10",
    "U_CAN_Ubuntu_18-04_LTS",  # sunset by DISA; final release V2R15
    "U_CAN_Ubuntu_20-04_LTS",
    "U_CAN_Ubuntu_22-04_LTS",
    "U_CAN_Ubuntu_24-04_LTS",
    "U_MS_Windows_10",
    "U_MS_Windows_11",
    "U_MS_Windows_Server_2016",
    "U_MS_Windows_Server_2019",
    "U_MS_Windows_Server_2022",
    "U_MS_Windows_Server_2025",
]

CCI_LIST = "U_CCI_List.zip"
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024


def _exists(url: str) -> bool:
    req = urllib.request.Request(url, method="HEAD", headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status == 200
    except (urllib.error.URLError, TimeoutError):
        return False


def latest(product: str, max_version: int = 6, max_release: int = 20) -> str | None:
    """Return the filename of the newest release of `product`, or None."""
    for v in range(max_version, 0, -1):
        names = [f"{product}_V{v}R{r}_STIG.zip" for r in range(max_release, 0, -1)]
        with cf.ThreadPoolExecutor(max_workers=10) as ex:
            found = [n for n, ok in zip(names, ex.map(lambda n: _exists(BASE + n), names)) if ok]
        if found:
            return found[0]  # names are ordered newest-release first
    return None


def download(name: str, dest: Path, expected_sha256: str | None = None) -> Path:
    """Bound downloads, publish atomically and record a locally observed SHA-256.

    A local hash records integrity/provenance; independent authenticity requires
    comparing it with a digest from a trusted external release source.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.zip", name):
        raise ValueError("Unsafe download filename")
    if expected_sha256 is not None and not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256):
        raise ValueError("Expected SHA-256 must be 64 hexadecimal characters")
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / name
    temp = dest / (name + ".part")
    digest = hashlib.sha256()
    total = 0
    req = urllib.request.Request(BASE + name, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=120) as r, temp.open("wb") as fh:
            length = r.headers.get("Content-Length")
            if length and int(length) > MAX_DOWNLOAD_BYTES:
                raise ValueError("DISA download exceeds maximum allowed size")
            while chunk := r.read(1 << 16):
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise ValueError("DISA download exceeds maximum allowed size")
                digest.update(chunk)
                fh.write(chunk)
        actual = digest.hexdigest()
        if expected_sha256 and actual.lower() != expected_sha256.lower():
            raise ValueError(f"SHA-256 verification failed for {name}")
        os.replace(temp, out)
        (dest / (name + ".sha256")).write_text(f"{actual}  {name}\n", encoding="ascii")
    finally:
        temp.unlink(missing_ok=True)
    return out


def fetch_all(dest: Path, products: list[str] | None = None, clean: bool = True) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    products = products or PRODUCTS
    got = []
    for p in products:
        name = latest(p)
        if not name:
            print(f"  ! no release found for {p}")
            continue
        if (dest / name).exists():
            sidecar = dest / (name + ".sha256")
            if sidecar.exists():
                recorded = sidecar.read_text(encoding="ascii").split()[0]
                actual = hashlib.sha256((dest / name).read_bytes()).hexdigest()
                if recorded.lower() != actual:
                    raise ValueError(f"Cached archive does not match its recorded hash: {name}")
            else:
                print(f"  ! {name} has no recorded SHA-256; verify its source before rebuilding")
            print(f"  = {name} (already present)")
        else:
            print(f"  + {name}")
            download(name, dest)
        if clean:
            for old in dest.glob(f"{p}_V*R*_STIG.zip"):
                if old.name != name:
                    old.unlink()
                    (dest / (old.name + ".sha256")).unlink(missing_ok=True)
        got.append(dest / name)
    print(f"  + {CCI_LIST}")
    got.append(download(CCI_LIST, dest))
    return got


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Download the latest DISA STIG zips and the CCI list.")
    ap.add_argument("--dest", type=Path, default=Path(__file__).resolve().parent.parent / "data" / "raw")
    ap.add_argument("--product", action="append", help="Product prefix, e.g. U_RHEL_9 (repeatable)")
    args = ap.parse_args(argv)
    fetch_all(args.dest, args.product)
    return 0


if __name__ == "__main__":
    sys.exit(main())
