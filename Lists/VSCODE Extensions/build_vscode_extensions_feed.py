#!/usr/bin/env python3
"""
Build the VSXSentry feed from Microsoft's RemovedPackages markdown and a local static CSV.

Outputs (all in --output-dir):
  Combined (malicious + risky):
    vsxsentry_feed.csv / .json          — full merged feed
    stats.json                           — aggregated statistics

  Malicious only (categories without risky- prefix):
    vsxsentry_malicious_feed.csv / .json
    ioc_all_extension_ids.txt
    ioc_high_risk_extension_ids.txt
    ioc_block_publishers.txt

  Risky only (categories with risky- prefix):
    vsxsentry_risky_feed.csv / .json
    risky_extension_ids.txt
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.request import Request, urlopen

DEFAULT_REMOVED_URL = "https://raw.githubusercontent.com/microsoft/vsmarketplace/refs/heads/main/RemovedPackages.md"
DEFAULT_REFERENCE_URL = "https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md"

REASON_MAP = {
    "malware": ("critical", "malware"),
    "potentially malicious": ("high", "potentially-malicious"),
    "typo-squatting": ("high", "typo-squatting"),
    "impersonation": ("high", "impersonation"),
    "spam": ("medium", "spam"),
    "untrustworthy": ("medium", "untrustworthy"),
    "copyright violation": ("low", "copyright-violation"),
}

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

EXTENSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$")

RISKY_PREFIX = "risky-"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Entry:
    extension_id: str
    publisher_id: str
    extension_name: str
    metadata_comment: str
    metadata_severity: str
    metadata_category: str
    metadata_source: str
    metadata_reference: str
    metadata_status: str
    removal_date: str = ""
    source_reason: str = ""
    last_updated_utc: str = ""
    merged_sources: str = ""

    def key(self) -> str:
        return self.extension_id.lower()

    def is_risky(self) -> bool:
        return self.metadata_category.lower().startswith(RISKY_PREFIX)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def http_get_text(url: str) -> str:
    req = Request(url, headers={"User-Agent": "VSXSentry Feed Builder/1.0"})
    with urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


def normalize_extension_id(value: str) -> str:
    value = (value or "").strip().strip("`").strip()
    return value


def normalize_reason(reason: str) -> str:
    return " ".join((reason or "").strip().split())


def normalize_date(date_value: str) -> str:
    value = (date_value or "").strip()
    for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%m/%d/%y"):
        try:
            return datetime.strptime(value, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return value


def severity_and_category_for_reason(reason: str) -> tuple[str, str]:
    normalized = normalize_reason(reason).lower()
    return REASON_MAP.get(normalized, ("medium", slugify(normalized or "other")))


def slugify(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "other"


def infer_name_from_id(extension_id: str) -> tuple[str, str]:
    parts = extension_id.split(".", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return "", extension_id


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_markdown_table(text: str) -> List[dict]:
    rows: List[dict] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        parts = [p.strip() for p in line.strip("|").split("|")]
        if len(parts) < 3:
            continue
        if all(set(p) <= {"-", ":"} for p in parts):
            continue
        if "extension" in parts[0].lower() and "date" in parts[1].lower():
            continue
        extension_id, date_value, reason = parts[0], parts[1], parts[2]
        extension_id = normalize_extension_id(extension_id)
        if EXTENSION_ID_RE.match(extension_id):
            rows.append(
                {
                    "extension_id": extension_id,
                    "removal_date": normalize_date(date_value),
                    "reason": normalize_reason(reason),
                }
            )
    return rows


def parse_loose_lines(text: str) -> List[dict]:
    rows: List[dict] = []
    pattern = re.compile(
        r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9][A-Za-z0-9._-]*)\s+(\d{1,2}/\d{1,2}/\d{2,4}|\d{4}-\d{2}-\d{2})\s+(.+?)\s*$"
    )
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        match = pattern.match(line)
        if not match:
            continue
        rows.append(
            {
                "extension_id": normalize_extension_id(match.group(1)),
                "removal_date": normalize_date(match.group(2)),
                "reason": normalize_reason(match.group(3)),
            }
        )
    return rows


def parse_removed_packages(text: str) -> List[dict]:
    rows = parse_markdown_table(text)
    if rows:
        return rows
    rows = parse_loose_lines(text)
    if rows:
        return rows
    raise ValueError("Could not parse RemovedPackages markdown. The upstream format may have changed.")


def load_static_csv(path: Path) -> List[dict]:
    rows: List[dict] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"extension_id", "metadata_comment", "metadata_severity", "metadata_category"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Static CSV is missing required columns: {', '.join(sorted(missing))}")
        for row in reader:
            extension_id = normalize_extension_id(row.get("extension_id", ""))
            if not extension_id:
                continue
            if not EXTENSION_ID_RE.match(extension_id):
                raise ValueError(f"Invalid extension_id in static CSV: {extension_id}")
            rows.append(
                {
                    "extension_id": extension_id,
                    "metadata_comment": (row.get("metadata_comment") or "").strip(),
                    "metadata_severity": (row.get("metadata_severity") or "medium").strip().lower(),
                    "metadata_category": (row.get("metadata_category") or "other").strip().lower(),
                    "metadata_reference": (row.get("metadata_reference") or "").strip(),
                }
            )
    return rows


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def merge_entries(removed_rows: List[dict], static_rows: List[dict], reference_url: str) -> List[Entry]:
    current_ts = now_utc()
    merged: Dict[str, Entry] = {}

    # 1. Microsoft RemovedPackages (baseline)
    for row in removed_rows:
        extension_id = row["extension_id"]
        publisher_id, extension_name = infer_name_from_id(extension_id)
        severity, category = severity_and_category_for_reason(row["reason"])
        comment = f"Removed from VS Marketplace: {row['reason']}."
        entry = Entry(
            extension_id=extension_id,
            publisher_id=publisher_id,
            extension_name=extension_name,
            metadata_comment=comment,
            metadata_severity=severity,
            metadata_category=category,
            metadata_source="microsoft_removed_packages",
            metadata_reference=reference_url,
            metadata_status="removed_marketplace",
            removal_date=row["removal_date"],
            source_reason=row["reason"],
            last_updated_utc=current_ts,
            merged_sources="microsoft_removed_packages",
        )
        merged[entry.key()] = entry

    # 2. Static CSV (analyst-curated: malicious + risky)
    for row in static_rows:
        extension_id = row["extension_id"]
        publisher_id, extension_name = infer_name_from_id(extension_id)
        ref = row.get("metadata_reference") or "local_static_csv"
        existing = merged.get(extension_id.lower())
        if existing:
            # Static overrides comment/severity/category on collision
            existing.metadata_comment = row["metadata_comment"] or existing.metadata_comment
            existing.metadata_severity = row["metadata_severity"] or existing.metadata_severity
            existing.metadata_category = row["metadata_category"] or existing.metadata_category
            if ref and ref != "local_static_csv":
                existing.metadata_reference = ref
            existing.metadata_source = "microsoft_removed_packages,static_list"
            existing.metadata_status = "removed_marketplace,listed_static"
            existing.merged_sources = "microsoft_removed_packages,static_list"
            existing.last_updated_utc = current_ts
        else:
            merged[extension_id.lower()] = Entry(
                extension_id=extension_id,
                publisher_id=publisher_id,
                extension_name=extension_name,
                metadata_comment=row["metadata_comment"],
                metadata_severity=row["metadata_severity"],
                metadata_category=row["metadata_category"],
                metadata_source="static_list",
                metadata_reference=ref,
                metadata_status="listed_static",
                removal_date="",
                source_reason="",
                last_updated_utc=current_ts,
                merged_sources="static_list",
            )

    return sorted(
        merged.values(),
        key=lambda item: (
            -SEVERITY_RANK.get(item.metadata_severity, -1),
            item.metadata_category,
            item.extension_id.lower(),
        ),
    )


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

FIELDNAMES = [
    "extension_id",
    "publisher_id",
    "extension_name",
    "metadata_comment",
    "metadata_severity",
    "metadata_category",
    "metadata_source",
    "metadata_reference",
    "metadata_status",
    "removal_date",
    "source_reason",
    "last_updated_utc",
    "merged_sources",
]


def write_csv(path: Path, rows: List[Entry]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def write_json(path: Path, rows: List[Entry], *, feed_type: str = "all") -> None:
    payload = {
        "generated_utc": now_utc(),
        "project": "VSXSentry",
        "feed_type": feed_type,
        "total_records": len(rows),
        "records": [asdict(row) for row in rows],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_txt(path: Path, lines: Iterable[str]) -> None:
    content = "\n".join(sorted({line.strip() for line in lines if line.strip()}))
    path.write_text(content + ("\n" if content else ""), encoding="utf-8")


def write_stats(path: Path, all_rows: List[Entry], malicious: List[Entry], risky: List[Entry]) -> None:
    severity_counts = Counter(row.metadata_severity for row in all_rows)
    category_counts = Counter(row.metadata_category for row in all_rows)
    publisher_counts = Counter(row.publisher_id for row in all_rows)

    malicious_cats = Counter(row.metadata_category for row in malicious)
    risky_cats = Counter(row.metadata_category for row in risky)

    payload = {
        "generated_utc": now_utc(),
        "total_records": len(all_rows),
        "total_malicious": len(malicious),
        "total_risky": len(risky),
        "severity_counts": dict(sorted(severity_counts.items())),
        "category_counts": dict(sorted(category_counts.items())),
        "malicious_category_counts": dict(sorted(malicious_cats.items())),
        "risky_category_counts": dict(sorted(risky_cats.items())),
        "total_publishers": len(publisher_counts),
        "top_publishers": publisher_counts.most_common(25),
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # --- Parse sources ---
    removed_text = http_get_text(args.removed_url)
    removed_rows = parse_removed_packages(removed_text)
    static_rows = load_static_csv(Path(args.static_csv))
    all_rows = merge_entries(removed_rows, static_rows, args.reference_url)

    # --- Split by risky- prefix ---
    malicious_rows = [r for r in all_rows if not r.is_risky()]
    risky_rows = [r for r in all_rows if r.is_risky()]

    # --- Combined feed (malicious + risky) ---
    write_csv(output_dir / "vsxsentry_feed.csv", all_rows)
    write_json(output_dir / "vsxsentry_feed.json", all_rows, feed_type="all")

    # --- Malicious-only feed ---
    write_csv(output_dir / "vsxsentry_malicious_feed.csv", malicious_rows)
    write_json(output_dir / "vsxsentry_malicious_feed.json", malicious_rows, feed_type="malicious")

    # --- Risky-only feed ---
    write_csv(output_dir / "vsxsentry_risky_feed.csv", risky_rows)
    write_json(output_dir / "vsxsentry_risky_feed.json", risky_rows, feed_type="risky")

    # --- IOC text files (malicious only — risky are legitimate extensions) ---
    write_txt(
        output_dir / "ioc_all_extension_ids.txt",
        [row.extension_id for row in malicious_rows],
    )
    write_txt(
        output_dir / "ioc_high_risk_extension_ids.txt",
        [row.extension_id for row in malicious_rows if SEVERITY_RANK.get(row.metadata_severity, 0) >= 3],
    )
    write_txt(
        output_dir / "ioc_block_publishers.txt",
        [row.publisher_id for row in malicious_rows if SEVERITY_RANK.get(row.metadata_severity, 0) >= 3],
    )

    # --- Risky extension IDs (separate, not IOCs) ---
    write_txt(
        output_dir / "risky_extension_ids.txt",
        [row.extension_id for row in risky_rows],
    )

    # --- Stats ---
    write_stats(output_dir / "stats.json", all_rows, malicious_rows, risky_rows)

    # --- Summary ---
    print(f"[+] Parsed {len(removed_rows)} Microsoft removed-package rows")
    print(f"[+] Parsed {len(static_rows)} static rows")
    print(f"[+] Merged: {len(all_rows)} total = {len(malicious_rows)} malicious + {len(risky_rows)} risky")
    print(f"[+] Outputs written to {output_dir}/")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the VSXSentry feed.")
    parser.add_argument("--removed-url", default=DEFAULT_REMOVED_URL, help="URL for RemovedPackages.md")
    parser.add_argument("--reference-url", default=DEFAULT_REFERENCE_URL, help="Reference URL stored in the feed")
    parser.add_argument("--static-csv", default="vscode_extensions_static.csv", help="Path to analyst-curated static CSV")
    parser.add_argument("--output-dir", default="feeds", help="Output directory")
    args = parser.parse_args()
    try:
        return build(args)
    except Exception as exc:
        print(f"[!] Build failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
