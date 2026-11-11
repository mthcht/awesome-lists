#!/usr/bin/env python3
# fetch_threatfox_ip_port.py
#
# abuse.ch now requires a (free) Auth-Key for all ThreatFox exports.
# Get one at https://auth.abuse.ch/ and store it as the repository secret
# THREATFOX_AUTH_KEY; the workflow passes it in as an environment variable.

import requests, zipfile, io, csv, re, sys, os

AUTH_KEY = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
if not AUTH_KEY:
    sys.exit("[!] Error: THREATFOX_AUTH_KEY environment variable is not set")

URL      = f"https://threatfox-api.abuse.ch/v2/files/exports/{AUTH_KEY}/full.csv.zip"
OUTFILE  = "threatfox_ip_ports_list.csv"
IP_PORT  = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$')

def redact(text):
    # never leak the key into public Action logs
    return str(text).replace(AUTH_KEY, "***")

try:
    # 1. download ZIP
    resp = requests.get(URL, timeout=120)
    if resp.status_code != 200:
        sys.exit(f"[!] Error: HTTP {resp.status_code} from ThreatFox export: {redact(resp.text[:300])}")
    zbytes = resp.content
    if not zbytes.startswith(b"PK"):
        sys.exit(f"[!] Error: response is not a ZIP file: {redact(zbytes[:300])}")

    # 2. extract CSV text
    with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
        csv_name = next(n for n in z.namelist() if n.endswith(".csv"))
        raw_txt  = z.read(csv_name).decode("utf-8-sig")

    # 3. keep header (strip leading '#') / drop other comments
    cleaned = []
    for line in raw_txt.splitlines():
        if line.startswith('#') and '"ioc_value"' in line:   # real header prefixed by #
            cleaned.append(line.lstrip('# ').rstrip())
        elif line.startswith('#'):                         # other comments -> skip
            continue
        else:
            cleaned.append(line.rstrip())

    # 4. csv parse + keep only ip:port IOCs (the full export also has domains, URLs, hashes)
    reader   = csv.DictReader(cleaned, skipinitialspace=True)
    if not reader.fieldnames or "ioc_value" not in reader.fieldnames:
        sys.exit(f"[!] Error: unexpected CSV header: {reader.fieldnames}")
    fieldout = reader.fieldnames + ["dest_ip", "dest_port"]
    rows_out = []

    for row in reader:
        val = (row.get("ioc_value") or "").strip().replace('"', "")
        m   = IP_PORT.fullmatch(val)
        if m:
            rows_out.append([row[h] for h in reader.fieldnames] + [m.group(1), m.group(2)])

    if not rows_out:
        sys.exit("[!] Error: no ip:port IOCs parsed, refusing to overwrite the CSV with an empty list")

    # 5. write clean csv
    with open(OUTFILE, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(fieldout)
        writer.writerows(rows_out)

    print(f"[+] Saved {len(rows_out)} rows to {OUTFILE}")
except Exception as e:
    sys.exit(f"[!] Error: {redact(e)}")
