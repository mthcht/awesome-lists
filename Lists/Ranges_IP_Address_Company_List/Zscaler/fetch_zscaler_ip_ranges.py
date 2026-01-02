#!/usr/bin/env python3
import csv
import json
import sys
import ipaddress
import logging
import urllib.request
from pathlib import Path
from typing import Any, Set, Optional

URL = "https://config.zscaler.com/api/zscalertwo.net/cenr/json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("zscaler_ip_fetcher")


def fetch_json(url: str) -> Any:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Zscaler-IP-Fetcher/1.0)"},
    )
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def extract_ranges(obj: Any, out: Set[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "range" and isinstance(v, str):
                s = v.strip()
                if s:
                    out.add(s)
            else:
                extract_ranges(v, out)
    elif isinstance(obj, list):
        for it in obj:
            extract_ranges(it, out)


def normalize_and_validate(cidr: str) -> Optional[str]:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        return str(net)
    except ValueError:
        return None


def write_csv(ranges: list, out_path: Path, metadata_reference: str) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src_ip", "metadata_reference"])
        for r in ranges:
            w.writerow([r, metadata_reference])


def sort_key(c: str):
    n = ipaddress.ip_network(c, strict=False)
    return (n.version, int(n.network_address), n.prefixlen)


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("zscaler_ip_ranges.csv")

    log.info("Fetching JSON: %s", URL)
    data = fetch_json(URL)

    raw: Set[str] = set()
    extract_ranges(data, raw)

    if not raw:
        log.error("No 'range' entries found. JSON schema may have changed.")
        return 2

    valid = []
    invalid = 0
    for s in raw:
        norm = normalize_and_validate(s)
        if norm:
            valid.append(norm)
        else:
            invalid += 1

    valid = sorted(set(valid), key=sort_key)

    if not valid:
        log.error("Found ranges but none were valid CIDRs.")
        return 3

    if invalid:
        log.warning("Skipped %d invalid CIDR-like values", invalid)

    log.info("Writing %d unique CIDRs to %s", len(valid), out)
    write_csv(valid, out, URL)

    log.info("Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
