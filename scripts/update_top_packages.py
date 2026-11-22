"""Refresh pkgsentry/data/top_packages.json from the public top-pypi-packages dataset.

Run from the repo root:  .venv/bin/python scripts/update_top_packages.py
"""

import json
from pathlib import Path

import requests

SOURCE_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
KEEP = 5000
OUT = Path(__file__).resolve().parent.parent / "pkgsentry" / "data" / "top_packages.json"


def main() -> None:
    response = requests.get(SOURCE_URL, timeout=30, headers={"User-Agent": "pkgsentry-update/0.1"})
    response.raise_for_status()
    data = response.json()
    rows = ",\n".join(json.dumps([row["project"], row["download_count"]]) for row in data["rows"][:KEEP])
    OUT.write_text(
        "{\n"
        f'"source": {json.dumps(SOURCE_URL)},\n'
        f'"last_update": {json.dumps(data["last_update"])},\n'
        '"window": "downloads in the last 30 days",\n'
        f'"rows": [\n{rows}\n]\n}}\n'
    )
    print(f"Wrote {KEEP} packages (data from {data['last_update']}) to {OUT}")


if __name__ == "__main__":
    main()
