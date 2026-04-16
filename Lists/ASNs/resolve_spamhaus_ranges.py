#!/usr/bin/env python3
import csv
import re
import sys
from pathlib import Path


def read_csv(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def find_asn_files(asn_ranges_dir: Path):
    files_by_asn = {}
    for p in asn_ranges_dir.glob("*.csv"):
        m = re.search(r"AS(\d+)", p.stem, re.IGNORECASE)
        if m:
            files_by_asn[m.group(1)] = p
    return files_by_asn


def detect_ip_column(rows):
    if not rows:
        return None

    preferred = [
        "dest_ip",
        "ip_range",
        "network",
        "prefix",
        "cidr",
        "range",
    ]

    fieldnames = list(rows[0].keys())

    for col in preferred:
        if col in fieldnames:
            return col

    for col in fieldnames:
        if not col.lower().startswith("metadata_"):
            return col

    return None


def main():
    base_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
    spamhaus_file = base_dir / "spamhaus_asn_list.csv"
    asn_ranges_dir = base_dir / "ASN_IP_Ranges"

    out_resolved = base_dir / "spamhaus_asn_list_resolved.csv"
    out_ranges_only = base_dir / "spamhaus_asn_list_resolved_only_ip_ranges.csv"

    if not spamhaus_file.exists():
        raise FileNotFoundError(f"Missing file: {spamhaus_file}")

    if not asn_ranges_dir.exists():
        raise FileNotFoundError(f"Missing folder: {asn_ranges_dir}")

    spamhaus_rows = read_csv(spamhaus_file)
    asn_files = find_asn_files(asn_ranges_dir)

    # Deduplicate ASNs from Spamhaus file
    spamhaus_asns = []
    seen_asns = set()
    for row in spamhaus_rows:
        raw_asn = (row.get("as_number") or "").strip()
        asn = re.sub(r"\D", "", raw_asn)
        if asn and asn not in seen_asns:
            seen_asns.add(asn)
            spamhaus_asns.append(asn)

    resolved_rows = []
    ranges_only = []
    seen_pairs = set()
    seen_ranges = set()

    for asn in spamhaus_asns:
        asn_file = asn_files.get(asn)
        if not asn_file:
            continue

        range_rows = read_csv(asn_file)
        ip_col = detect_ip_column(range_rows)
        if not ip_col:
            continue

        for row in range_rows:
            ip_range = (row.get(ip_col) or "").strip()
            if not ip_range:
                continue

            pair = (f"AS{asn}", ip_range)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                resolved_rows.append(
                    {
                        "as_number": f"AS{asn}",
                        "ip_range": ip_range,
                    }
                )

            if ip_range not in seen_ranges:
                seen_ranges.add(ip_range)
                ranges_only.append(ip_range)

    with out_resolved.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["as_number", "ip_range"])
        writer.writeheader()
        writer.writerows(resolved_rows)

    with out_ranges_only.open("w", encoding="utf-8", newline="") as f:
        for ip_range in ranges_only:
            f.write(ip_range + "\n")

    print(f"Created: {out_resolved}")
    print(f"Created: {out_ranges_only}")
    print(f"Resolved ASNs: {len({row['as_number'] for row in resolved_rows})}")
    print(f"Resolved IP ranges: {len(ranges_only)}")


if __name__ == "__main__":
    main()
