#!/usr/bin/env python3
import csv
import json
import sys
import ipaddress
import logging
import urllib.request
from pathlib import Path

URL = "https://my.imperva.com/api/integration/v1/ips"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("imperva_ip_fetcher")


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(
        url,
        method="POST",   # Imperva endpoint expects POST
        data=b"",        # empty body
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; Imperva-IP-Fetcher/1.0)",
            "Accept": "application/json,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def normalize_and_validate(items):
    valid = []
    for s in items:
        try:
            net = ipaddress.ip_network(str(s).strip(), strict=False)
            valid.append(str(net))
        except ValueError:
            continue

    def sort_key(x: str):
        n = ipaddress.ip_network(x, strict=False)
        return (n.version, int(n.network_address), n.prefixlen)

    return sorted(set(valid), key=sort_key)


def write_csv(cidrs, out_path: Path, metadata_reference: str):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src_ip", "metadata_reference"])
        for c in cidrs:
            w.writerow([c, metadata_reference])


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("imperva_ip_ranges.csv")

    log.info("Fetching: %s", URL)
    data = fetch_json(URL)

    v4 = data.get("ipRanges") or []
    v6 = data.get("ipv6Ranges") or []

    if not isinstance(v4, list) or not isinstance(v6, list):
        log.error("Unexpected JSON structure (ipRanges/ipv6Ranges not lists)")
        return 2

    cidrs = normalize_and_validate([*v4, *v6])
    if not cidrs:
        log.error("No valid CIDRs found in response")
        return 2

    log.info("Writing %d ranges to %s", len(cidrs), out)
    write_csv(cidrs, out, URL)

    log.info("Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
