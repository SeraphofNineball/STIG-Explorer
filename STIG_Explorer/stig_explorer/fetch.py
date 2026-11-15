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
import concurrent.futures as cf
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
UA = {"User-Agent": "Mozilla/5.0 (STIG-Explorer)"}

PRODUCTS = [
    "U_RHEL_8",
    "U_RHEL_9",
    "U_RHEL_10",
    "U_MS_Windows_10",
    "U_MS_Windows_11",
    "U_MS_Windows_Server_2016",
    "U_MS_Windows_Server_2019",
    "U_MS_Windows_Server_2022",
    "U_MS_Windows_Server_2025",
]

CCI_LIST = "U_CCI_List.zip"


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


def download(name: str, dest: Path) -> Path:
    out = dest / name
    req = urllib.request.Request(BASE + name, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r, open(out, "wb") as fh:
        while chunk := r.read(1 << 16):
            fh.write(chunk)
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
        if clean:
            for old in dest.glob(f"{p}_V*R*_STIG.zip"):
                if old.name != name:
                    old.unlink()
        if (dest / name).exists():
            print(f"  = {name} (already present)")
        else:
            print(f"  + {name}")
            download(name, dest)
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
