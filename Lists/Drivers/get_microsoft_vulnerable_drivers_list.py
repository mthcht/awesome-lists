#!/usr/bin/env python3
import csv
import io
import os
import shutil
import tempfile
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone

DOWNLOAD_URL = "https://aka.ms/VulnerableDriverBlockList"

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "microsoft_block_list"
CSV_FILE = SCRIPT_DIR / "microsoft_block_list.csv"

MAX_ZIP_SIZE = 100 * 1024 * 1024   # 100 MB
MAX_FILE_SIZE = 50 * 1024 * 1024   # 50 MB per extracted file
HTTP_TIMEOUT = 120


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    print(f"[{utc_now()}] {msg}", flush=True)


def download_zip(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "loldriver-microsoft-blocklist-fetcher",
            "Accept": "application/zip,application/octet-stream,*/*",
        },
    )

    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:
        content_length = response.headers.get("Content-Length")

        if content_length and int(content_length) > MAX_ZIP_SIZE:
            raise RuntimeError(f"ZIP too large: {content_length} bytes")

        data = response.read(MAX_ZIP_SIZE + 1)

    if len(data) > MAX_ZIP_SIZE:
        raise RuntimeError(f"ZIP exceeded max size: {MAX_ZIP_SIZE} bytes")

    return data


def safe_extract_zip(zip_data: bytes, destination: Path) -> None:
    destination = destination.resolve()

    if destination.exists():
        shutil.rmtree(destination)

    destination.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        for member in zf.infolist():
            member_name = member.filename.replace("\\", "/")

            if member.is_dir():
                continue

            if member.file_size > MAX_FILE_SIZE:
                log(f"Skipping oversized file: {member_name}")
                continue

            target_path = (destination / member_name).resolve()

            try:
                target_path.relative_to(destination)
            except ValueError:
                raise RuntimeError(f"Unsafe ZIP path blocked: {member_name}")

            target_path.parent.mkdir(parents=True, exist_ok=True)

            with zf.open(member) as src, open(target_path, "wb") as dst:
                shutil.copyfileobj(src, dst)

    flatten_single_root_folder(destination)


def flatten_single_root_folder(destination: Path) -> None:
    """
    If the ZIP extracts as:
      microsoft_block_list/SomeRootFolder/files...

    Convert it to:
      microsoft_block_list/files...
    """
    entries = list(destination.iterdir())

    if len(entries) != 1 or not entries[0].is_dir():
        return

    root = entries[0]
    temp_dir = destination.parent / f".{destination.name}_flatten_tmp"

    if temp_dir.exists():
        shutil.rmtree(temp_dir)

    root.rename(temp_dir)
    shutil.rmtree(destination)
    temp_dir.rename(destination)


def strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def extract_deny_rows(xml_file: Path) -> list[dict[str, str]]:
    rows = []

    tree = ET.parse(xml_file)
    root = tree.getroot()

    for element in root.iter():
        if strip_namespace(element.tag) != "Deny":
            continue

        deny_id = element.attrib.get("ID", "").strip()
        friendly_name = element.attrib.get("FriendlyName", "").strip()
        file_hash = element.attrib.get("Hash", "").strip()

        if not deny_id and not friendly_name and not file_hash:
            continue

        rows.append(
            {
                "Deny ID": deny_id,
                "FriendlyName": friendly_name,
                "Hash": file_hash,
            }
        )

    return rows


def write_csv(rows: list[dict[str, str]], csv_file: Path) -> None:
    csv_file.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        delete=False,
        dir=str(csv_file.parent),
        prefix=f".{csv_file.name}.",
        suffix=".tmp",
    ) as tmp:
        writer = csv.DictWriter(
            tmp,
            fieldnames=["Deny ID", "FriendlyName", "Hash"],
        )
        writer.writeheader()
        writer.writerows(rows)
        tmp_path = Path(tmp.name)

    tmp_path.replace(csv_file)


def build_csv_from_xmls() -> int:
    xml_files = sorted(OUTPUT_DIR.rglob("*.xml"))

    if not xml_files:
        raise RuntimeError(f"No XML files found under {OUTPUT_DIR}")

    all_rows = []
    seen = set()

    for xml_file in xml_files:
        log(f"Parsing XML: {xml_file.relative_to(OUTPUT_DIR)}")

        for row in extract_deny_rows(xml_file):
            key = (row["Deny ID"], row["FriendlyName"], row["Hash"])

            if key in seen:
                continue

            seen.add(key)
            all_rows.append(row)

    write_csv(all_rows, CSV_FILE)
    return len(all_rows)


def main() -> int:
    log(f"Downloading Microsoft Vulnerable Driver Block List ZIP: {DOWNLOAD_URL}")
    zip_data = download_zip(DOWNLOAD_URL)

    log(f"Downloaded ZIP size: {len(zip_data)} bytes")
    log(f"Extracting to: {OUTPUT_DIR}")
    safe_extract_zip(zip_data, OUTPUT_DIR)

    row_count = build_csv_from_xmls()

    log(f"CSV created: {CSV_FILE}")
    log(f"Rows written: {row_count}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        log(f"ERROR: {e}")
        raise SystemExit(1)
