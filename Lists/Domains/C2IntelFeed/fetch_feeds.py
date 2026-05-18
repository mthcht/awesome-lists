#!/usr/bin/env python3
import csv
import hashlib
import io
import json
import time
import zipfile
import tempfile
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

REPO_OWNER = "drb-ra"
REPO_NAME = "C2IntelFeeds"
BRANCH = "master"
SOURCE_DIR = "feeds"

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR

ZIP_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/archive/refs/heads/{BRANCH}.zip"

MAX_ZIP_SIZE = 50 * 1024 * 1024          # 50 MB
MAX_CSV_SIZE = 10 * 1024 * 1024          # 10 MB per CSV
MAX_CSV_FILES = 500
HTTP_TIMEOUT = 60

MANIFEST_FILE = OUTPUT_DIR / "c2intelfeeds_manifest.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    print(f"[{utc_now()}] {msg}", flush=True)


def sanitize_path_part(part: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in part)
    cleaned = cleaned.strip("._")
    return cleaned or "unnamed"


def safe_output_path(relative_path: str) -> Path:
    """
    Saves CSV files under the script folder.

    Examples:
      feeds/example.csv
        -> ./example.csv

      feeds/unverified/example.csv
        -> ./unverified/unverified__example.csv

      feeds/a/b/example.csv
        -> ./a/b/a__b__example.csv
    """
    parts = Path(relative_path).parts

    if not parts:
        raise ValueError("Empty relative path")

    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"Unsafe relative path blocked: {relative_path}")

    safe_parts = [sanitize_path_part(part) for part in parts]

    filename = safe_parts[-1]
    parent_parts = safe_parts[:-1]

    if not filename.lower().endswith(".csv"):
        raise ValueError(f"Not a CSV filename: {filename}")

    if parent_parts:
        prefixed_filename = "__".join(parent_parts + [filename])
        destination = OUTPUT_DIR.joinpath(*parent_parts, prefixed_filename)
    else:
        destination = OUTPUT_DIR / filename

    destination = destination.resolve()
    output_root = OUTPUT_DIR.resolve()

    try:
        destination.relative_to(output_root)
    except ValueError:
        raise ValueError(f"Unsafe output path blocked: {destination}")

    return destination


def http_download(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "c2intelfeeds-secure-downloader",
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


def is_valid_csv(data: bytes, source_name: str) -> bool:
    try:
        text = data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        log(f"Skipping non UTF-8 CSV: {source_name}")
        return False

    try:
        reader = csv.reader(io.StringIO(text))
        first_row = next(reader, None)
    except csv.Error:
        log(f"Skipping invalid CSV: {source_name}")
        return False

    if first_row is None:
        log(f"Skipping empty CSV: {source_name}")
        return False

    return True


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes) -> bool:
    """
    Atomic write.
    Returns True if file changed, False if identical.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists() and path.read_bytes() == data:
        return False

    with tempfile.NamedTemporaryFile(
        mode="wb",
        delete=False,
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    ) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)

    tmp_path.replace(path)
    return True


def extract_csvs(zip_data: bytes) -> dict:
    manifest = {
        "source": f"{REPO_OWNER}/{REPO_NAME}",
        "branch": BRANCH,
        "source_dir": SOURCE_DIR,
        "updated_at_utc": utc_now(),
        "files": [],
    }

    changed = 0
    downloaded = 0

    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        csv_members = []

        for member in zf.infolist():
            if member.is_dir():
                continue

            member_path = member.filename.replace("\\", "/")

            # Expected ZIP path:
            # C2IntelFeeds-master/feeds/example.csv
            split_path = member_path.split("/", 1)
            if len(split_path) != 2:
                continue

            inner_path = split_path[1]

            if not inner_path.startswith(f"{SOURCE_DIR}/"):
                continue

            if not inner_path.lower().endswith(".csv"):
                continue

            if ".." in Path(inner_path).parts:
                raise RuntimeError(f"Unsafe archive path blocked: {inner_path}")

            if member.file_size > MAX_CSV_SIZE:
                log(f"Skipping oversized CSV: {inner_path} ({member.file_size} bytes)")
                continue

            csv_members.append((member, inner_path))

        if len(csv_members) > MAX_CSV_FILES:
            raise RuntimeError(f"Too many CSV files: {len(csv_members)}")

        for member, inner_path in csv_members:
            relative_path = inner_path.removeprefix(f"{SOURCE_DIR}/")
            output_path = safe_output_path(relative_path)

            data = zf.read(member)

            if len(data) > MAX_CSV_SIZE:
                log(f"Skipping oversized CSV after read: {inner_path}")
                continue

            if not is_valid_csv(data, inner_path):
                continue

            file_changed = atomic_write(output_path, data)
            downloaded += 1

            status = "updated" if file_changed else "unchanged"
            saved_as = str(output_path.relative_to(OUTPUT_DIR))

            manifest["files"].append(
                {
                    "source_path": inner_path,
                    "saved_as": saved_as,
                    "size_bytes": len(data),
                    "sha256": sha256_hex(data),
                    "status": status,
                }
            )

            log(f"{status}: {saved_as}")

    manifest["downloaded_files"] = downloaded
    manifest["changed_files"] = changed

    for entry in manifest["files"]:
        if entry["status"] == "updated":
            changed += 1

    manifest["changed_files"] = changed

    atomic_write(
        MANIFEST_FILE,
        json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"),
    )

    return manifest


def main() -> int:
    start = time.time()

    log(f"Downloading ZIP archive from {REPO_OWNER}/{REPO_NAME}:{BRANCH}")
    zip_data = http_download(ZIP_URL)

    log(f"Downloaded ZIP size: {len(zip_data)} bytes")
    manifest = extract_csvs(zip_data)

    elapsed = round(time.time() - start, 2)

    log(
        f"Done. Downloaded={manifest['downloaded_files']} "
        f"Changed={manifest['changed_files']} "
        f"Elapsed={elapsed}s"
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        log(f"ERROR: {e}")
        raise SystemExit(1)
