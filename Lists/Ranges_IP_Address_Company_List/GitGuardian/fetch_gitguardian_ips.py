#!/usr/bin/env python3
import csv
import re
import sys
import ipaddress
import logging
import urllib.request
from pathlib import Path

URL = "https://docs.gitguardian.com/internal-monitoring/integrate-sources/monitored-perimeter#allowing-incoming-connections-from-gitguardians-ip-addresses"
CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("gitguardian_ip_fetcher")


def fetch_html(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; GitGuardian-IP-Fetcher/1.0)"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace")


def extract_valid_cidrs(html: str):
    found = set(CIDR_RE.findall(html))
    valid = []
    for s in found:
        try:
            ipaddress.ip_network(s, strict=False)
            valid.append(s)
        except ValueError:
            continue

    def sort_key(x: str):
        n = ipaddress.ip_network(x, strict=False)
        return (n.version, int(n.network_address), n.prefixlen)

    return sorted(valid, key=sort_key)


def write_csv(cidrs, out_path: Path, metadata_reference: str):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src_ip", "metadata_reference"])
        for c in cidrs:
            w.writerow([c, metadata_reference])


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("gitguardian_ip_ranges.csv")

    log.info("Fetching source page: %s", URL)
    html = fetch_html(URL)

    log.info("Extracting CIDRs from page content")
    cidrs = extract_valid_cidrs(html)

    if not cidrs:
        log.error("No CIDRs found. The page format may have changed.")
        return 2

    log.info("Writing %d CIDRs to %s", len(cidrs), out)
    write_csv(cidrs, out, URL)

    log.info("Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
