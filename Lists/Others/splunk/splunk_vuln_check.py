#!/usr/bin/env python3
"""
splunk_vuln_check.py

Builds Splunk vulnerability lookup CSVs from the official Splunk advisory site.

Outputs:
  1. Range lookup CSV:
     - Best for accurate alerting.
     - Contains affected_min/affected_max version boundaries and comparable numeric fields.

  2. Expanded lookup CSV:
     - Best for simple lookup joins in SPL.
     - Expands finite ranges such as 9.4.0 to 9.4.10 into one row per vulnerable version.

No external Python libraries required.

Examples:
  python3 splunk_vuln_check.py \
    --ranges-output splunk_vuln_ranges.csv \
    --expanded-output splunk_vuln_lookup_expanded.csv

  python3 splunk_vuln_check.py \
    --inventory inventory.csv \
    --findings-output splunk_vuln_findings.csv \
    --summary-output splunk_vuln_summary.csv
"""

import argparse
import csv
import datetime as dt
import html
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from xml.etree import ElementTree


BASE_URL = "https://advisory.splunk.com/"
FEED_URL = "https://advisory.splunk.com/feed.xml"

USER_AGENT = "splunk-vuln-check/2.0"

PRODUCT_PREFIXES = sorted([
    "Splunk/UniversalForwarder for Windows",
    "Splunk Universal Forwarder for Windows",
    "Splunk Universal Forwarder",
    "Universal Forwarder",
    "Splunk Enterprise on Linux",
    "Splunk Enterprise for Windows",
    "Splunk Enterprise Cloud",
    "Splunk Enterprise",
], key=len, reverse=True)

SEVERITY_ORDER = {
    "Informational": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


class AdvisoryHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.links = set()
        self.skip = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in ("script", "style", "noscript"):
            self.skip = True

        attrs = dict(attrs)
        href = attrs.get("href")
        if href and re.search(r"/advisories/SVD-\d{4}-\d{4}", href):
            self.links.add(urllib.parse.urljoin(BASE_URL, href.split("#")[0]))

        if tag in ("br", "p", "tr", "li", "h1", "h2", "h3", "table", "td", "th"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ("script", "style", "noscript"):
            self.skip = False
        if tag in ("p", "tr", "li", "h1", "h2", "h3", "table", "td", "th"):
            self.parts.append("\n")

    def handle_data(self, data):
        if self.skip:
            return
        data = data.strip()
        if data:
            self.parts.append(data + " ")

    def clean_text(self):
        raw = html.unescape("".join(self.parts))
        raw = raw.replace("\xa0", " ")
        lines = []
        for line in raw.splitlines():
            line = re.sub(r"\s+", " ", line).strip()
            if line:
                lines.append(line)
        return "\n".join(lines)


def log(msg):
    print(msg, file=sys.stderr)


def fetch_url(url, timeout=30, retries=3):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )

    last_error = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last_error = e
            if attempt < retries:
                time.sleep(2 * attempt)

    raise RuntimeError(f"Failed to fetch {url}: {last_error}")


def html_to_text_and_links(raw_html):
    parser = AdvisoryHTMLParser()
    parser.feed(raw_html)
    return parser.clean_text(), parser.links


def extract_advisory_urls_from_homepage(timeout):
    raw = fetch_url(BASE_URL, timeout=timeout)
    _, links = html_to_text_and_links(raw)

    for m in re.finditer(r'href=["\']([^"\']*/advisories/SVD-\d{4}-\d{4}[^"\']*)["\']', raw):
        links.add(urllib.parse.urljoin(BASE_URL, m.group(1).split("#")[0]))

    return sorted(links, reverse=True)


def extract_advisory_urls_from_rss(timeout):
    urls = set()
    try:
        raw = fetch_url(FEED_URL, timeout=timeout)
        root = ElementTree.fromstring(raw)
        for elem in root.iter():
            if elem.tag.lower().endswith("link") and elem.text:
                if "/advisories/SVD-" in elem.text:
                    urls.add(elem.text.strip())
    except Exception:
        pass
    return sorted(urls, reverse=True)


def normalize_product_kind(product):
    p = product.lower().replace("/", " ")
    if "forwarder" in p or "universalforwarder" in p or "splunkforwarder" in p:
        return "forwarder"
    if "enterprise" in p:
        return "enterprise"
    return ""


def split_version(version):
    nums = [int(x) for x in re.findall(r"\d+", str(version))]
    nums = (nums + [0, 0, 0, 0])[:4]
    return nums


def version_to_vnum(version):
    """
    4-part safe numeric version:
      9.4.10   -> 9004010000
      9.4.10.1 -> 9004010001
      10.2.3   -> 10002003000

    SPL equivalent:
      major*1000000000 + minor*1000000 + patch*1000 + build
    """
    major, minor, patch, build = split_version(version)
    return major * 1000000000 + minor * 1000000 + patch * 1000 + build


def compare_versions(a, b):
    av = split_version(a)
    bv = split_version(b)
    return (av > bv) - (av < bv)


def normalize_version(version, parts=3):
    nums = split_version(version)
    if parts == 4 and nums[3]:
        return f"{nums[0]}.{nums[1]}.{nums[2]}.{nums[3]}"
    return f"{nums[0]}.{nums[1]}.{nums[2]}"


def version_starts_with_base(version, base):
    vv = [int(x) for x in re.findall(r"\d+", str(version))]
    bb = [int(x) for x in re.findall(r"\d+", str(base))]
    if not bb:
        return True
    return vv[:len(bb)] == bb


def extract_first(pattern, text, default=""):
    m = re.search(pattern, text, flags=re.I | re.S)
    return m.group(1).strip() if m else default


def highest_severity(text):
    candidates = []

    for m in re.finditer(r"CVSSv3\.1\s*Score:\s*[\d.]+,\s*(Critical|High|Medium|Low|Informational)", text, re.I):
        candidates.append(m.group(1).capitalize())

    solution_split = re.split(r"\nSolution\n|## Solution", text, flags=re.I)
    pre_solution = solution_split[0] if solution_split else text

    for sev in SEVERITY_ORDER:
        if re.search(rf"\b{sev}\b", pre_solution, re.I):
            candidates.append(sev)

    if not candidates:
        return ""

    return max(candidates, key=lambda s: SEVERITY_ORDER.get(s, -1))


def extract_title(lines):
    skip = {
        "Home",
        "Report a Vulnerability",
        "FAQs",
        "Mailing List",
        "Toggle menu",
        "Email",
        "RSS Feed",
        "Support",
    }

    for line in lines:
        clean = line.strip("# ").strip()
        if not clean or clean in skip:
            continue
        if clean.startswith("Advisory ID:"):
            break
        if clean.startswith("Image:"):
            continue
        if clean.startswith("©"):
            continue
        return clean

    return ""


def get_product_status_section(lines):
    start = None
    for i, line in enumerate(lines):
        clean = line.strip("# ").strip()
        if clean.lower() == "product status":
            start = i + 1
            break

    if start is None:
        return []

    stop_markers = (
        "severity",
        "changelog",
        "email",
        "rss feed",
        "support",
        "mitigations",
        "workarounds",
        "references",
        "detections",
    )

    section = []
    for line in lines[start:]:
        clean = line.strip("# ").strip()
        if clean.lower() in stop_markers:
            break
        if clean.startswith("©"):
            break
        section.append(clean)

    return section


def parse_affected_range(base_version, affected_raw):
    """
    Returns normalized range metadata.

    affected_type:
      range_exact         9.4.0 to 9.4.10
      below              Below 10.2.3
      lower_or_earlier   9.1.0.1 and lower
      exact_list          9.4.1, 9.4.2
      unknown             not parsed safely
    """
    raw = affected_raw.strip()
    low = raw.lower()

    if not raw or "not affected" in low:
        return None

    # 9.4.0 to 9.4.10
    m = re.search(r"(\d+(?:\.\d+){1,3})\s+to\s+(\d+(?:\.\d+){1,3})", low)
    if m:
        min_v, max_v = m.group(1), m.group(2)
        return {
            "affected_type": "range_exact",
            "affected_min_version": normalize_version(min_v, 4),
            "affected_min_vnum": str(version_to_vnum(min_v)),
            "affected_min_inclusive": "1",
            "affected_max_version": normalize_version(max_v, 4),
            "affected_max_vnum": str(version_to_vnum(max_v)),
            "affected_max_inclusive": "1",
        }

    # Below 10.2.3 / prior to 10.2.3
    m = re.search(r"(?:below|prior to|before|less than)\s+(\d+(?:\.\d+){1,3})", low)
    if m:
        max_v = m.group(1)
        min_v = ""
        if base_version:
            base_nums = [int(x) for x in re.findall(r"\d+", str(base_version))]
            if len(base_nums) == 1:
                min_v = f"{base_nums[0]}.0.0"
            elif len(base_nums) == 2:
                min_v = f"{base_nums[0]}.{base_nums[1]}.0"
            elif len(base_nums) >= 3:
                min_v = f"{base_nums[0]}.{base_nums[1]}.{base_nums[2]}"

        return {
            "affected_type": "below",
            "affected_min_version": normalize_version(min_v, 4) if min_v else "",
            "affected_min_vnum": str(version_to_vnum(min_v)) if min_v else "",
            "affected_min_inclusive": "1" if min_v else "0",
            "affected_max_version": normalize_version(max_v, 4),
            "affected_max_vnum": str(version_to_vnum(max_v)),
            "affected_max_inclusive": "0",
        }

    # 9.1.0.1 and lower / 8.2.11 or earlier
    m = re.search(r"(\d+(?:\.\d+){1,3}).{0,20}(?:and lower|or lower|and earlier|or earlier)", low)
    if m:
        max_v = m.group(1)
        min_v = ""
        if base_version:
            base_nums = [int(x) for x in re.findall(r"\d+", str(base_version))]
            if len(base_nums) == 1:
                min_v = f"{base_nums[0]}.0.0"
            elif len(base_nums) == 2:
                min_v = f"{base_nums[0]}.{base_nums[1]}.0"
            elif len(base_nums) >= 3:
                min_v = f"{base_nums[0]}.{base_nums[1]}.{base_nums[2]}"

        return {
            "affected_type": "lower_or_earlier",
            "affected_min_version": normalize_version(min_v, 4) if min_v else "",
            "affected_min_vnum": str(version_to_vnum(min_v)) if min_v else "",
            "affected_min_inclusive": "1" if min_v else "0",
            "affected_max_version": normalize_version(max_v, 4),
            "affected_max_vnum": str(version_to_vnum(max_v)),
            "affected_max_inclusive": "1",
        }

    versions = re.findall(r"\d+(?:\.\d+){1,3}", raw)
    if versions:
        v = versions[0]
        return {
            "affected_type": "exact_list",
            "affected_min_version": normalize_version(v, 4),
            "affected_min_vnum": str(version_to_vnum(v)),
            "affected_min_inclusive": "1",
            "affected_max_version": normalize_version(v, 4),
            "affected_max_vnum": str(version_to_vnum(v)),
            "affected_max_inclusive": "1",
        }

    return {
        "affected_type": "unknown",
        "affected_min_version": "",
        "affected_min_vnum": "",
        "affected_min_inclusive": "0",
        "affected_max_version": "",
        "affected_max_vnum": "",
        "affected_max_inclusive": "0",
    }


def parse_product_status_line(line):
    line = line.strip()
    if not line:
        return None

    if "Product Base Version Affected Version Fix Version" in line:
        return None

    for product in PRODUCT_PREFIXES:
        if line.lower().startswith(product.lower() + " "):
            rest = line[len(product):].strip()

            m = re.match(
                r"^(?P<base>\d+(?:\.\d+){0,3}(?:\.x)?)\s+"
                r"(?P<affected>.+?)\s+"
                r"(?P<fix>Not affected|N/A|\d+(?:\.\d+){1,3})$",
                rest,
                flags=re.I,
            )
            if not m:
                return None

            base_version = m.group("base").replace(".x", "")
            affected_raw = m.group("affected").strip()
            fix_version = m.group("fix").strip()

            range_meta = parse_affected_range(base_version, affected_raw)
            if not range_meta:
                return None

            row = {
                "product": product,
                "product_kind": normalize_product_kind(product),
                "base_version": base_version,
                "affected_raw": affected_raw,
                "fix_version": normalize_version(fix_version, 4) if re.match(r"^\d", fix_version) else fix_version,
                "fix_vnum": str(version_to_vnum(fix_version)) if re.match(r"^\d", fix_version) else "",
            }
            row.update(range_meta)
            return row

    return None


def parse_product_status_rows(lines):
    rows = []

    # One rendered table row per line.
    for line in lines:
        row = parse_product_status_line(line)
        if row:
            rows.append(row)

    if rows:
        return rows

    # Fallback: table cells rendered one per line.
    i = 0
    while i < len(lines):
        product = None
        for prefix in PRODUCT_PREFIXES:
            if lines[i].lower() == prefix.lower():
                product = prefix
                break

        if product and i + 3 < len(lines):
            base = lines[i + 1].strip().replace(".x", "")
            affected = lines[i + 2].strip()
            fix = lines[i + 3].strip()

            if re.match(r"^\d+(?:\.\d+){0,3}", base):
                range_meta = parse_affected_range(base, affected)
                if range_meta and fix.lower() not in ("not affected", "n/a"):
                    row = {
                        "product": product,
                        "product_kind": normalize_product_kind(product),
                        "base_version": base,
                        "affected_raw": affected,
                        "fix_version": normalize_version(fix, 4) if re.match(r"^\d", fix) else fix,
                        "fix_vnum": str(version_to_vnum(fix)) if re.match(r"^\d", fix) else "",
                    }
                    row.update(range_meta)
                    rows.append(row)
                    i += 4
                    continue

        i += 1

    return rows


def parse_advisory(url, timeout):
    raw = fetch_url(url, timeout=timeout)
    text, _ = html_to_text_and_links(raw)
    lines = text.splitlines()

    advisory_id = extract_first(r"Advisory\s*ID:\s*(SVD-\d{4}-\d{4})", text)
    cve_id = extract_first(r"CVE\s*ID:\s*([^\n]+)", text)
    published = extract_first(r"Published:\s*(\d{4}-\d{2}-\d{2})", text)
    last_update = extract_first(r"Last\s*Update:\s*(\d{4}-\d{2}-\d{2})", text)
    title = extract_title(lines)
    severity = highest_severity(text)

    solution = ""
    m = re.search(r"\nSolution\n(.+?)(?:\nProduct Status\n|\nSeverity\n|\nChangelog\n)", text, flags=re.I | re.S)
    if m:
        solution = re.sub(r"\s+", " ", m.group(1)).strip()

    status_lines = get_product_status_section(lines)
    rows = parse_product_status_rows(status_lines)

    product_rows = []
    for row in rows:
        if row["product_kind"] not in ("enterprise", "forwarder"):
            continue
        if row["fix_version"].lower() in ("not affected", "n/a"):
            continue
        if "not affected" in row["affected_raw"].lower():
            continue

        enriched = dict(row)
        enriched.update({
            "advisory_id": advisory_id,
            "cve_id": cve_id,
            "severity": severity,
            "title": title,
            "published": published,
            "last_update": last_update,
            "solution": solution,
            "source": "splunk_advisory",
            "url": url,
        })
        product_rows.append(enriched)

    return {
        "advisory_id": advisory_id,
        "title": title,
        "published": published,
        "last_update": last_update,
        "severity": severity,
        "url": url,
        "rows": product_rows,
    }


def load_cache(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_cache(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def collect_advisories(args):
    if args.offline:
        return load_cache(args.cache)

    try:
        urls = extract_advisory_urls_from_homepage(args.timeout)
        if not urls:
            urls = extract_advisory_urls_from_rss(args.timeout)

        if args.max_advisories > 0:
            urls = urls[:args.max_advisories]

        advisories = []
        for idx, url in enumerate(urls, 1):
            try:
                adv = parse_advisory(url, args.timeout)
                if adv["rows"]:
                    advisories.append(adv)
                if idx % 25 == 0:
                    log(f"[+] Parsed {idx}/{len(urls)} advisories")
            except Exception as e:
                log(f"[!] Failed to parse {url}: {e}")

        data = {
            "generated_at_utc": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "source": BASE_URL,
            "advisories": advisories,
        }

        save_cache(args.cache, data)
        return data

    except Exception as e:
        if os.path.exists(args.cache):
            log(f"[!] Online refresh failed, using existing cache: {e}")
            return load_cache(args.cache)
        raise


def flatten_ranges(data, product_filter):
    wanted = set(product_filter)
    rows = []

    for adv in data.get("advisories", []):
        for row in adv.get("rows", []):
            if row["product_kind"] in wanted:
                rows.append(row)

    return rows


def range_contains_version(vnum, row):
    min_vnum = row.get("affected_min_vnum")
    max_vnum = row.get("affected_max_vnum")
    min_inc = row.get("affected_min_inclusive") == "1"
    max_inc = row.get("affected_max_inclusive") == "1"

    if min_vnum:
        min_vnum = int(min_vnum)
        if min_inc and vnum < min_vnum:
            return False
        if not min_inc and vnum <= min_vnum:
            return False

    if max_vnum:
        max_vnum = int(max_vnum)
        if max_inc and vnum > max_vnum:
            return False
        if not max_inc and vnum >= max_vnum:
            return False

    return True


def expand_range_row(row, max_patch_expansion=300):
    """
    Expands simple finite patch ranges into exact vulnerable versions.

    Keeps range CSV as the authoritative source. Expanded CSV is for simple SPL lookups.
    """
    min_v = row.get("affected_min_version")
    max_v = row.get("affected_max_version")

    if not min_v or not max_v:
        return []

    min_nums = split_version(min_v)
    max_nums = split_version(max_v)

    # Only expand same major.minor ranges, because that is how Splunk Product Status rows are scoped.
    if min_nums[:2] != max_nums[:2]:
        return []

    min_patch = min_nums[2]
    max_patch = max_nums[2]

    if row.get("affected_max_inclusive") != "1":
        max_patch -= 1

    if row.get("affected_min_inclusive") != "1":
        min_patch += 1

    if max_patch < min_patch:
        return []

    if max_patch - min_patch > max_patch_expansion:
        return []

    expanded = []
    for patch in range(min_patch, max_patch + 1):
        vulnerable_version = f"{min_nums[0]}.{min_nums[1]}.{patch}"
        expanded_row = {
            "lookup_key": f"{row['product_kind']}:{vulnerable_version}",
            "product_kind": row["product_kind"],
            "product": row["product"],
            "vulnerable_version": vulnerable_version,
            "vulnerable_vnum": str(version_to_vnum(vulnerable_version)),
            "fix_version": row["fix_version"],
            "fix_vnum": row["fix_vnum"],
            "advisory_id": row["advisory_id"],
            "cve_id": row.get("cve_id", ""),
            "severity": row.get("severity", ""),
            "title": row.get("title", ""),
            "affected_raw": row.get("affected_raw", ""),
            "published": row.get("published", ""),
            "last_update": row.get("last_update", ""),
            "url": row.get("url", ""),
        }
        expanded.append(expanded_row)

    return expanded


def build_expanded_lookup(range_rows):
    rows = []
    seen = set()

    for row in range_rows:
        for expanded in expand_range_row(row):
            key = (
                expanded["lookup_key"],
                expanded["fix_version"],
                expanded["advisory_id"],
            )
            if key in seen:
                continue
            seen.add(key)
            rows.append(expanded)

    return rows


def read_inventory(path):
    assets = []

    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            asset = {k.strip().lower(): (v or "").strip() for k, v in row.items()}
            version = asset.get("version") or asset.get("installed_version") or asset.get("splunk_version")
            if not version:
                continue

            product = asset.get("product") or asset.get("component") or "Splunk Universal Forwarder"
            host = asset.get("host") or asset.get("hostname") or asset.get("name") or asset.get("server") or ""

            assets.append({
                "host": host,
                "product": product,
                "product_kind": normalize_product_kind(product) or "forwarder",
                "version": normalize_version(version, 4),
                "version_vnum": str(version_to_vnum(version)),
                "os": asset.get("os") or asset.get("platform") or "",
            })

    return assets


def discover_local_inventory():
    checks = [
        ("/opt/splunkforwarder/bin/splunk", "Splunk Universal Forwarder"),
        ("/opt/splunk/bin/splunk", "Splunk Enterprise"),
    ]

    assets = []
    host = socket.gethostname()

    for binary, product in checks:
        if not os.path.exists(binary):
            continue

        try:
            output = subprocess.check_output(
                [binary, "version"],
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
            )
        except Exception as e:
            log(f"[!] Could not run {binary} version: {e}")
            continue

        m = re.search(r"(\d+\.\d+(?:\.\d+){1,2})", output)
        if not m:
            continue

        version = normalize_version(m.group(1), 4)

        assets.append({
            "host": host,
            "product": product,
            "product_kind": normalize_product_kind(product),
            "version": version,
            "version_vnum": str(version_to_vnum(version)),
            "os": sys.platform,
        })

    return assets


def os_matches(asset_os, advisory_product):
    product_l = advisory_product.lower()
    os_l = (asset_os or "").lower()

    if "windows" in product_l:
        return "win" in os_l

    if "linux" in product_l:
        return any(x in os_l for x in ("linux", "debian", "ubuntu", "rhel", "centos", "rocky", "alma"))

    return True


def check_assets(assets, range_rows):
    findings = []

    for asset in assets:
        asset_vnum = int(asset["version_vnum"])

        for vuln in range_rows:
            if asset["product_kind"] != vuln["product_kind"]:
                continue

            if not os_matches(asset.get("os", ""), vuln["product"]):
                continue

            if not range_contains_version(asset_vnum, vuln):
                continue

            findings.append({
                "host": asset["host"],
                "asset_product": asset["product"],
                "asset_product_kind": asset["product_kind"],
                "asset_version": asset["version"],
                "asset_vnum": asset["version_vnum"],
                "asset_os": asset.get("os", ""),
                "status": "vulnerable",
                "required_fix_version": vuln["fix_version"],
                "required_fix_vnum": vuln["fix_vnum"],
                "advisory_id": vuln["advisory_id"],
                "severity": vuln.get("severity", ""),
                "cve_id": vuln.get("cve_id", ""),
                "title": vuln.get("title", ""),
                "affected_product": vuln["product"],
                "affected_raw": vuln["affected_raw"],
                "affected_min_version": vuln["affected_min_version"],
                "affected_max_version": vuln["affected_max_version"],
                "published": vuln.get("published", ""),
                "last_update": vuln.get("last_update", ""),
                "url": vuln.get("url", ""),
            })

    return findings


def highest_fix_version(findings):
    fixes = [f["required_fix_version"] for f in findings if re.match(r"^\d", f["required_fix_version"])]
    if not fixes:
        return ""
    return max(fixes, key=version_to_vnum)


def highest_finding_severity(findings):
    severities = [f["severity"] for f in findings if f.get("severity") in SEVERITY_ORDER]
    if not severities:
        return ""
    return max(severities, key=lambda s: SEVERITY_ORDER[s])


def build_summary(assets, findings):
    by_asset = {}

    for f in findings:
        key = (f["host"], f["asset_product_kind"], f["asset_version"], f["asset_os"])
        by_asset.setdefault(key, []).append(f)

    summary = []
    for asset in assets:
        key = (asset["host"], asset["product_kind"], asset["version"], asset.get("os", ""))
        fs = by_asset.get(key, [])

        summary.append({
            "host": asset["host"],
            "product": asset["product"],
            "product_kind": asset["product_kind"],
            "version": asset["version"],
            "version_vnum": asset["version_vnum"],
            "os": asset.get("os", ""),
            "status": "vulnerable" if fs else "ok",
            "advisory_count": str(len(fs)),
            "highest_severity": highest_finding_severity(fs),
            "recommended_minimum_upgrade": highest_fix_version(fs),
            "advisories": ",".join(sorted({x["advisory_id"] for x in fs})),
        })

    return summary


def write_csv(path, rows, fields):
    if not path:
        return

    out = sys.stdout if path == "-" else open(path, "w", encoding="utf-8", newline="")
    try:
        writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    finally:
        if out is not sys.stdout:
            out.close()


def write_json(path, obj):
    if not path:
        return

    out = sys.stdout if path == "-" else open(path, "w", encoding="utf-8")
    try:
        json.dump(obj, out, indent=2, sort_keys=True)
        out.write("\n")
    finally:
        if out is not sys.stdout:
            out.close()


RANGE_FIELDS = [
    "source",
    "advisory_id",
    "cve_id",
    "severity",
    "title",
    "product",
    "product_kind",
    "base_version",
    "affected_raw",
    "affected_type",
    "affected_min_version",
    "affected_min_vnum",
    "affected_min_inclusive",
    "affected_max_version",
    "affected_max_vnum",
    "affected_max_inclusive",
    "fix_version",
    "fix_vnum",
    "published",
    "last_update",
    "url",
]

EXPANDED_FIELDS = [
    "lookup_key",
    "product_kind",
    "product",
    "vulnerable_version",
    "vulnerable_vnum",
    "fix_version",
    "fix_vnum",
    "advisory_id",
    "cve_id",
    "severity",
    "title",
    "affected_raw",
    "published",
    "last_update",
    "url",
]

FINDING_FIELDS = [
    "host",
    "asset_product",
    "asset_product_kind",
    "asset_version",
    "asset_vnum",
    "asset_os",
    "status",
    "required_fix_version",
    "required_fix_vnum",
    "advisory_id",
    "severity",
    "cve_id",
    "title",
    "affected_product",
    "affected_raw",
    "affected_min_version",
    "affected_max_version",
    "published",
    "last_update",
    "url",
]

SUMMARY_FIELDS = [
    "host",
    "product",
    "product_kind",
    "version",
    "version_vnum",
    "os",
    "status",
    "advisory_count",
    "highest_severity",
    "recommended_minimum_upgrade",
    "advisories",
]


def parse_args():
    p = argparse.ArgumentParser(description="Build Splunk vulnerability CSV lookups from official Splunk advisories.")

    p.add_argument("--products", default="enterprise,forwarder", help="Comma list: enterprise,forwarder")
    p.add_argument("--ranges-output", default="splunk_vuln_ranges.csv", help="Accurate range lookup CSV")
    p.add_argument("--expanded-output", default="splunk_vuln_lookup_expanded.csv", help="Exact-version expanded lookup CSV")
    p.add_argument("--json-output", help="Optional full JSON output")

    p.add_argument("--inventory", help="Optional CSV inventory with host,product,version,os")
    p.add_argument("--local", action="store_true", help="Detect local /opt/splunk or /opt/splunkforwarder version")
    p.add_argument("--findings-output", help="Optional vulnerable asset findings CSV")
    p.add_argument("--summary-output", help="Optional all-asset summary CSV")

    p.add_argument("--cache", default="splunk_advisories_cache.json", help="Advisory cache JSON path")
    p.add_argument("--offline", action="store_true", help="Use cache only")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--max-advisories", type=int, default=0, help="Limit advisories parsed, 0 = no limit")

    return p.parse_args()


def main():
    args = parse_args()
    product_filter = [x.strip().lower() for x in args.products.split(",") if x.strip()]

    data = collect_advisories(args)
    range_rows = flatten_ranges(data, product_filter)
    expanded_rows = build_expanded_lookup(range_rows)

    write_csv(args.ranges_output, range_rows, RANGE_FIELDS)
    write_csv(args.expanded_output, expanded_rows, EXPANDED_FIELDS)

    if args.json_output:
        write_json(args.json_output, {
            "generated_at_utc": data.get("generated_at_utc"),
            "source": data.get("source"),
            "ranges": range_rows,
            "expanded": expanded_rows,
        })

    assets = []
    if args.inventory:
        assets.extend(read_inventory(args.inventory))
    if args.local:
        assets.extend(discover_local_inventory())

    if assets:
        findings = check_assets(assets, range_rows)

        if args.findings_output:
            write_csv(args.findings_output, findings, FINDING_FIELDS)

        if args.summary_output:
            write_csv(args.summary_output, build_summary(assets, findings), SUMMARY_FIELDS)

        log(f"[+] Assets checked: {len(assets)}")
        log(f"[+] Vulnerable asset findings: {len(findings)}")

    log(f"[+] Range lookup rows: {len(range_rows)}")
    log(f"[+] Expanded lookup rows: {len(expanded_rows)}")
    log(f"[+] Range output: {args.ranges_output}")
    log(f"[+] Expanded output: {args.expanded_output}")


if __name__ == "__main__":
    main()
