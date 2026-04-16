#!/usr/bin/env python3
import csv
import re
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
SPAMHAUS_FILE = BASE_DIR / "spamhaus_asn_list.csv"
ASN_RANGES_DIR = BASE_DIR / "ASN_IP_Ranges"
OUT_RESOLVED = BASE_DIR / "spamhaus_asn_list_resolved.csv"
OUT_RANGES_ONLY = BASE_DIR / "spamhaus_asn_list_resolved_only_ip_ranges.csv"


def read_csv(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def detect_asn_column(rows):
    if not rows:
        return None

    headers = list(rows[0].keys())
    preferred = [
        "as_number",
        "asn",
        "asn_number",
        "as",
        "autonomous_system_number",
    ]

    lower_map = {h.lower().strip(): h for h in headers}

    for col in preferred:
        if col in lower_map:
            return lower_map[col]

    for h in headers:
        if "asn" in h.lower() or "as_number" in h.lower():
            return h

    return None


def detect_ip_column(rows):
    if not rows:
        return None

    headers = list(rows[0].keys())
    preferred = [
        "ip_range",
        "prefix",
        "network",
        "cidr",
        "range",
        "ip",
        "dest_ip",
    ]

    lower_map = {h.lower().strip(): h for h in headers}

    for col in preferred:
        if col in lower_map:
            return lower_map[col]

    cidr_re = re.compile(r"^\s*(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\s*$|^\s*[0-9a-fA-F:]+/\d{1,3}\s*$")
    for h in headers:
        for row in rows[:10]:
            v = (row.get(h) or "").strip()
            if cidr_re.match(v):
                return h

    return headers[0] if headers else None


def extract_asn(value: str):
    if not value:
        return None
    m = re.search(r"AS\s*(\d+)|\b(\d+)\b", value, re.IGNORECASE)
    if not m:
        return None
    return next(g for g in m.groups() if g)


def build_asn_file_map(asn_dir: Path):
    mapping = {}
    for file in asn_dir.glob("*.csv"):
        m = re.search(r"AS(\d+)", file.stem, re.IGNORECASE)
        if m:
            mapping[m.group(1)] = file
    return mapping


def main():
    if not SPAMHAUS_FILE.exists():
        raise FileNotFoundError(f"Missing file: {SPAMHAUS_FILE}")

    if not ASN_RANGES_DIR.exists():
        raise FileNotFoundError(f"Missing folder: {ASN_RANGES_DIR}")

    spamhaus_rows = read_csv(SPAMHAUS_FILE)
    if not spamhaus_rows:
        raise ValueError(f"No rows found in: {SPAMHAUS_FILE}")

    asn_col = detect_asn_column(spamhaus_rows)
    if not asn_col:
        raise ValueError("Could not detect ASN column in spamhaus_asn_list.csv")

    asn_file_map = build_asn_file_map(ASN_RANGES_DIR)

    seen_asns = set()
    resolved_rows = []
    ranges_only = []
    seen_pairs = set()
    seen_ranges = set()

    for row in spamhaus_rows:
        asn = extract_asn((row.get(asn_col) or "").strip())
        if not asn or asn in seen_asns:
            continue
        seen_asns.add(asn)

        asn_file = asn_file_map.get(asn)
        if not asn_file or not asn_file.exists():
            continue

        range_rows = read_csv(asn_file)
        if not range_rows:
            continue

        ip_col = detect_ip_column(range_rows)
        if not ip_col:
            continue

        for r in range_rows:
            ip_range = (r.get(ip_col) or "").strip()
            if not ip_range:
                continue

            pair = (f"AS{asn}", ip_range)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                resolved_rows.append({
                    "as_number": f"AS{asn}",
                    "ip_range": ip_range,
                })

            if ip_range not in seen_ranges:
                seen_ranges.add(ip_range)
                ranges_only.append(ip_range)

    with OUT_RESOLVED.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["as_number", "ip_range"])
        writer.writeheader()
        writer.writerows(resolved_rows)

    with OUT_RANGES_ONLY.open("w", encoding="utf-8", newline="") as f:
        for ip_range in ranges_only:
            f.write(ip_range + "\n")

    print(f"Created: {OUT_RESOLVED}")
    print(f"Created: {OUT_RANGES_ONLY}")
    print(f"Resolved ASNs: {len({r['as_number'] for r in resolved_rows})}")
    print(f"Resolved IP ranges: {len(ranges_only)}")


if __name__ == "__main__":
    main()
