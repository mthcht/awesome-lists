#!/usr/bin/env python3
import csv
import json
import sys
import ipaddress
import logging
import urllib.request
from pathlib import Path

URL = "https://www.gstatic.com/ipranges/cloud.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("google_cloud_ip_fetcher")


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; GoogleCloud-IP-Fetcher/1.0)"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read().decode("utf-8", errors="replace")
    return json.loads(data)


def normalize_and_validate(cidr: str):
    s = (cidr or "").strip()
    if not s:
        return None
    try:
        ipaddress.ip_network(s, strict=False)
        return s
    except ValueError:
        return None


def extract_rows(payload: dict):
    prefixes = payload.get("prefixes", []) or []
    rows_map = {}  # cidr -> {"service":..., "scope":...}

    for p in prefixes:
        cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix") or ""
        cidr = normalize_and_validate(cidr)
        if not cidr:
            continue

        service = (p.get("service") or "").strip()
        scope = (p.get("scope") or "").strip()

        # Dedup by CIDR; if duplicates exist, keep the first non-empty fields
        if cidr not in rows_map:
            rows_map[cidr] = {"service": service, "scope": scope}
        else:
            if not rows_map[cidr]["service"] and service:
                rows_map[cidr]["service"] = service
            if not rows_map[cidr]["scope"] and scope:
                rows_map[cidr]["scope"] = scope

    def sort_key(x: str):
        n = ipaddress.ip_network(x, strict=False)
        return (n.version, int(n.network_address), n.prefixlen)

    rows = []
    for cidr in sorted(rows_map.keys(), key=sort_key):
        meta = rows_map[cidr]
        rows.append(
            {
                "src_ip": cidr,
                "service": meta["service"],
                "scope": meta["scope"],
                "metadata_reference": URL,
            }
        )
    return rows


def write_csv(rows, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["src_ip", "service", "scope", "metadata_reference"]
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("google_cloud_ip_ranges.csv")

    log.info("Fetching JSON: %s", URL)
    payload = fetch_json(URL)

    log.info("Extracting prefixes + metadata (service/scope)")
    rows = extract_rows(payload)

    if not rows:
        log.error("No CIDRs found. The JSON format may have changed.")
        return 2

    log.info("Writing %d rows to %s", len(rows), out)
    write_csv(rows, out)

    log.info("Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
