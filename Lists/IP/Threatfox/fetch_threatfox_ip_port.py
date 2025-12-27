#!/usr/bin/env python3
# fetch_threatfox_ip_port.py

import requests, zipfile, io, csv, re, sys

URL      = "https://threatfox.abuse.ch/export/csv/ip-port/full/"
OUTFILE  = "threatfox_ip_ports_list.csv"
IP_PORT  = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$')

try:
    # 1. download ZIP
    zbytes = requests.get(URL, timeout=30).content

    # 2. extract CSV text
    with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
        csv_name = next(n for n in z.namelist() if n.endswith(".csv"))
        raw_txt  = z.read(csv_name).decode("utf-8-sig")

    # 3. keep header (strip leading '#') / drop other comments
    cleaned = []
    for line in raw_txt.splitlines():
        if line.startswith('# "first_seen_utc"'):        # real header prefixed by #
            cleaned.append(line.lstrip('# ').rstrip())
        elif line.startswith('#'):                       # other comments -> skip
            continue
        else:
            cleaned.append(line.rstrip())

    # 4. csv parse + split ioc_value
    reader   = csv.DictReader(cleaned, skipinitialspace=True)
    ioc_idx  = reader.fieldnames.index("ioc_value")
    fieldout = reader.fieldnames + ["dest_ip", "dest_port"]
    rows_out = []

    for row in reader:
        val = row["ioc_value"].strip().replace('"', "")
        m   = IP_PORT.fullmatch(val)
        if m:
            rows_out.append([row[h] for h in reader.fieldnames] + [m.group(1), m.group(2)])

    # 5. write clean csv
    with open(OUTFILE, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(fieldout)
        writer.writerows(rows_out)

    print(f"[+] Saved {len(rows_out)} rows to {OUTFILE}")
except Exception as e:
    sys.exit(f"[!] Error: {e}")
