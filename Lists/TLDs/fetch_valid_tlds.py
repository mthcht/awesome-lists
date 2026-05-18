#!/usr/bin/env python3
import csv
import tempfile
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

SOURCE_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

SCRIPT_DIR = Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()

TXT_OUTPUT = SCRIPT_DIR / "iana_tlds.txt"
CSV_OUTPUT = SCRIPT_DIR / "iana_tlds.csv"

HTTP_TIMEOUT = 60
MAX_DOWNLOAD_SIZE = 5 * 1024 * 1024  # 5 MB


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    print(f"[{utc_now()}] {msg}", flush=True)


def download_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "iana-tld-fetcher",
            "Accept": "text/plain,*/*",
        },
    )

    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:
        data = response.read(MAX_DOWNLOAD_SIZE + 1)

    if len(data) > MAX_DOWNLOAD_SIZE:
        raise RuntimeError(f"Downloaded file exceeded {MAX_DOWNLOAD_SIZE} bytes")

    return data.decode("utf-8", errors="strict")


def parse_tlds(text: str) -> list[str]:
    tlds = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        tld = line.lower().strip(".")

        if not tld:
            continue

        tlds.append(tld)

    return sorted(set(tlds))


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        delete=False,
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    ) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    tmp_path.replace(path)


def write_txt(tlds: list[str]) -> None:
    content = "\n".join(tlds) + "\n"
    atomic_write_text(TXT_OUTPUT, content)


def write_csv(tlds: list[str]) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        delete=False,
        dir=str(CSV_OUTPUT.parent),
        prefix=f".{CSV_OUTPUT.name}.",
        suffix=".tmp",
    ) as tmp:
        writer = csv.DictWriter(
            tmp,
            fieldnames=["tld", "dest_nt_domain", "metadata_link"],
        )

        writer.writeheader()

        for tld in tlds:
            writer.writerow(
                {
                    "tld": tld,
                    "dest_nt_domain": f"*.{tld}",
                    "metadata_link": SOURCE_URL,
                }
            )

        tmp_path = Path(tmp.name)

    tmp_path.replace(CSV_OUTPUT)


def main() -> int:
    log(f"Downloading IANA TLD list: {SOURCE_URL}")

    text = download_text(SOURCE_URL)
    tlds = parse_tlds(text)

    if not tlds:
        raise RuntimeError("No TLDs parsed from source file")

    write_txt(tlds)
    write_csv(tlds)

    log(f"TXT created: {TXT_OUTPUT}")
    log(f"CSV created: {CSV_OUTPUT}")
    log(f"TLD count: {len(tlds)}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        log(f"ERROR: {e}")
        raise SystemExit(1)
