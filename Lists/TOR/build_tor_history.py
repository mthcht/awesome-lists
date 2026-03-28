#!/usr/bin/env python3
"""
build_tor_history.py — runs inside the repo, uses git log/show only.

First run: all commits sampled 1/day. Next runs: incremental.

Now stores guard/exit/middle probability and infers role from
probabilities when metadata_dest_role is unknown/empty.
"""

import argparse
import csv
import io
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

FILE_PATH = "Lists/TOR/TOR_nodes_list.csv"

COL_IP         = "dest_ip"
COL_FIRST_SEEN = "metadata_first_seen"
COL_LAST_SEEN  = "metadata_last_seen"
COL_NICKNAME   = "metadata_nickname"
COL_FP         = "metadata_fingerprint"
COL_COUNTRY    = "metadata_country"
COL_COUNTRY_N  = "metadata_country_name"
COL_AS         = "metadata_as"
COL_AS_NAME    = "metadata_as_name"
COL_ROLE       = "metadata_dest_role"
COL_PORT       = "dest_port"
COL_RUNNING    = "metadata_running"
COL_HOST       = "dest_nt_host"
COL_CONTACT    = "metadata_contact"
COL_GUARD_P    = "metadata_guard_probability"
COL_EXIT_P     = "metadata_exit_probability"
COL_MID_P      = "metadata_middle_probability"


def git(args):
    r = subprocess.run(["git"] + args, capture_output=True, text=True, check=True)
    return r.stdout.strip()


def get_commits(since_sha=None):
    raw = git(["log", "--format=%H %aI", "--reverse", "--", FILE_PATH])
    if not raw:
        return []
    commits = []
    found = since_sha is None
    for line in raw.splitlines():
        parts = line.strip().split(" ", 1)
        if len(parts) != 2:
            continue
        sha, date = parts
        if not found:
            if sha == since_sha:
                found = True
            continue
        commits.append({"sha": sha, "date": date})
    return commits


def get_file_at(sha):
    return git(["show", f"{sha}:{FILE_PATH}"])


def parse_csv(text):
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []
    rows = []
    for row in reader:
        ip = (row.get(COL_IP) or "").strip()
        if not ip:
            continue
        rows.append(row)
    return rows


def norm_date(d):
    if not d or not d.strip():
        return ""
    d = d.strip()
    if d.startswith("1970-01-01"):
        return ""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            return datetime.strptime(d, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return d[:10]


def merge_periods(periods):
    if not periods:
        return []
    parsed = sorted(periods)
    merged = [list(parsed[0])]
    for s, e in parsed[1:]:
        prev = merged[-1]
        try:
            if datetime.strptime(s, "%Y-%m-%d") <= datetime.strptime(prev[1], "%Y-%m-%d") + timedelta(days=2):
                prev[1] = max(prev[1], e)
                continue
        except ValueError:
            if s <= prev[1]:
                prev[1] = max(prev[1], e)
                continue
        merged.append([s, e])
    return merged


def sample(commits, hours):
    if not commits:
        return []
    out, last_ts = [], None
    for c in commits:
        try:
            ts = datetime.fromisoformat(c["date"])
        except Exception:
            ts = datetime.now(timezone.utc)
        if last_ts is None or (ts - last_ts).total_seconds() >= hours * 3600:
            out.append(c)
            last_ts = ts
    if out[-1]["sha"] != commits[-1]["sha"]:
        out.append(commits[-1])
    return out


def safe_float(v):
    """Parse a float, return 0 on failure."""
    try:
        f = float(v)
        return f if f == f else 0  # NaN check
    except (ValueError, TypeError):
        return 0


def infer_role(row):
    """
    Return (role, gp, ep, mp).
    If metadata_dest_role is known (exit/guard/middle), use it.
    Otherwise infer from probabilities.
    """
    role_raw = (row.get(COL_ROLE) or "").strip().lower()
    gp = safe_float(row.get(COL_GUARD_P, ""))
    ep = safe_float(row.get(COL_EXIT_P, ""))
    mp = safe_float(row.get(COL_MID_P, ""))

    if role_raw in ("exit", "guard", "middle"):
        return role_raw, gp, ep, mp

    # Infer from probabilities
    if gp == 0 and ep == 0 and mp == 0:
        return "unknown", gp, ep, mp

    # Pick the highest probability
    best = max(("guard", gp), ("exit", ep), ("middle", mp), key=lambda x: x[1])
    return best[0], gp, ep, mp


def build_meta(row):
    m = {}
    for csv_col, key in [
        (COL_NICKNAME, "nick"),
        (COL_FP,       "fp"),
        (COL_COUNTRY,  "cc"),
        (COL_COUNTRY_N, "cn"),
        (COL_AS,       "as"),
        (COL_AS_NAME,  "asn"),
        (COL_PORT,     "port"),
        (COL_HOST,     "host"),
    ]:
        v = (row.get(csv_col) or "").strip()
        if v:
            m[key] = v

    role, gp, ep, mp = infer_role(row)
    m["role"] = role

    # Store probabilities if any are > 0
    if gp > 0:
        m["gp"] = round(gp, 8)
    if ep > 0:
        m["ep"] = round(ep, 8)
    if mp > 0:
        m["mp"] = round(mp, 8)

    # Store original role if we inferred a different one
    role_raw = (row.get(COL_ROLE) or "").strip().lower()
    if role_raw and role_raw != role:
        m["orig_role"] = role_raw

    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="Lists/TOR/tor_nodes_history.json")
    ap.add_argument("--full", action="store_true", help="Force full rebuild")
    args = ap.parse_args()
    output = Path(args.output)

    existing = {}
    if output.exists() and not args.full:
        print("Loading existing history...")
        with open(output) as f:
            existing = json.load(f)
        print(f"   {existing.get('total_ips', 0):,} IPs | last: {existing.get('last_commit_sha', '?')[:7]}")

    ip_db = existing.get("ips", {})
    last_sha = existing.get("last_commit_sha") if not args.full else None
    prev_count = existing.get("commits_processed", 0) if not args.full else 0

    if last_sha:
        print(f"New commits after {last_sha[:7]}...")
        commits = get_commits(since_sha=last_sha)
        print(f"   {len(commits)} new")
        if not commits:
            print("Up to date")
            return
        sampled = sample(commits, hours=3)
    else:
        print("First run - all commits...")
        commits = get_commits()
        print(f"   {len(commits)} total")
        if not commits:
            print("No commits found")
            sys.exit(1)
        sampled = sample(commits, hours=24)

    print(f"Processing {len(sampled)} commits...\n")

    errors = 0
    for i, c in enumerate(sampled):
        sha, cdate = c["sha"], c["date"]
        pct = int((i + 1) / len(sampled) * 100)
        print(f"  [{pct:3d}%] {sha[:7]} ({cdate[:10]})", end=" ", flush=True)
        try:
            text = get_file_at(sha)
            rows = parse_csv(text)
            new = 0
            for row in rows:
                ip = row[COL_IP].strip()
                fs = norm_date(row.get(COL_FIRST_SEEN, ""))
                ls = norm_date(row.get(COL_LAST_SEEN, ""))
                cd = cdate[:10]
                if not fs and not ls:
                    fs = ls = cd
                elif not fs:
                    fs = ls
                elif not ls:
                    ls = fs

                if ip not in ip_db:
                    ip_db[ip] = {"p": [], "m": {}}
                    new += 1

                ip_db[ip]["p"].append([fs, ls])
                meta = build_meta(row)
                if meta:
                    ip_db[ip]["m"] = meta

            print(f"-> {len(rows)} rows ({new} new)")
        except Exception as e:
            errors += 1
            print(f"ERROR: {e}")

    print("\nMerging periods...")
    for ip in ip_db:
        ip_db[ip]["p"] = merge_periods(ip_db[ip]["p"])

    firsts, lasts = [], []
    for d in ip_db.values():
        for p in d["p"]:
            if p[0]:
                firsts.append(p[0])
            if p[1]:
                lasts.append(p[1])

    # Role counts (using inferred roles)
    role_counts = {}
    for d in ip_db.values():
        role = d.get("m", {}).get("role", "unknown")
        role_counts[role] = role_counts.get(role, 0) + 1

    country_counts = {}
    for d in ip_db.values():
        cc = d.get("m", {}).get("cc", "")
        if cc:
            country_counts[cc] = country_counts.get(cc, 0) + 1

    top_countries = dict(sorted(country_counts.items(), key=lambda x: -x[1])[:30])

    result = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "source": f"https://github.com/mthcht/awesome-lists/blob/main/{FILE_PATH}",
        "total_ips": len(ip_db),
        "commits_processed": prev_count + len(sampled),
        "range": [min(firsts) if firsts else "", max(lasts) if lasts else ""],
        "last_commit_sha": sampled[-1]["sha"],
        "last_commit_date": sampled[-1]["date"],
        "roles": role_counts,
        "top_countries": top_countries,
        "errors": errors,
        "ips": ip_db,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(result, f, separators=(",", ":"))

    mb = output.stat().st_size / 1048576
    print(f"\n Done: {output} ({mb:.1f} MB)")
    print(f"   {len(ip_db):,} IPs | {result['range'][0]} -> {result['range'][1]}")
    print(f"   Roles: {role_counts}")
    print(f"   {len(sampled)} commits this run ({prev_count + len(sampled)} total)")


if __name__ == "__main__":
    main()
