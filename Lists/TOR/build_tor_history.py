#!/usr/bin/env python3
"""
build_tor_history.py — runs inside the repo, uses git log/show only.

State is stored in a separate .tor_history_state.json file (committed alongside).
The output tor_nodes_history.json is a clean data feed with no script metadata.
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
COL_HOST       = "dest_nt_host"
COL_GUARD_P    = "metadata_guard_probability"
COL_EXIT_P     = "metadata_exit_probability"
COL_MID_P      = "metadata_middle_probability"


def git(args):
    r = subprocess.run(["git"] + args, capture_output=True, text=True, check=True)
    return r.stdout.strip()


def get_all_commits():
    raw = git(["log", "--format=%H %aI", "--reverse", "--", FILE_PATH])
    if not raw:
        return []
    return [{"sha": p[0], "date": p[1]} for line in raw.splitlines()
            if len(p := line.strip().split(" ", 1)) == 2]


def get_new_commits(since_date, exclude_sha=None):
    raw = git(["log", "--format=%H %aI", "--reverse",
               "--after=" + since_date, "--", FILE_PATH])
    if not raw:
        return []
    return [{"sha": p[0], "date": p[1]} for line in raw.splitlines()
            if len(p := line.strip().split(" ", 1)) == 2 and p[0] != exclude_sha]


def get_file_at(sha):
    return git(["show", f"{sha}:{FILE_PATH}"])


def parse_csv(text):
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []
    return [row for row in reader if (row.get(COL_IP) or "").strip()]


def norm_date(d):
    if not d or not d.strip() or d.strip().startswith("1970-01-01"):
        return ""
    d = d.strip()
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
    try:
        f = float(v)
        return f if f == f else 0
    except (ValueError, TypeError):
        return 0


def infer_role(row):
    role_raw = (row.get(COL_ROLE) or "").strip().lower()
    gp = safe_float(row.get(COL_GUARD_P, ""))
    ep = safe_float(row.get(COL_EXIT_P, ""))
    mp = safe_float(row.get(COL_MID_P, ""))
    if role_raw in ("exit", "guard", "middle"):
        return role_raw, gp, ep, mp
    if gp == 0 and ep == 0 and mp == 0:
        return "unknown", 0, 0, 0
    best = max(("guard", gp), ("exit", ep), ("middle", mp), key=lambda x: x[1])
    return best[0], gp, ep, mp


def build_meta(row):
    m = {}
    for csv_col, key in [
        (COL_NICKNAME, "nick"), (COL_FP, "fp"), (COL_COUNTRY, "cc"),
        (COL_COUNTRY_N, "cn"), (COL_AS, "as"), (COL_AS_NAME, "asn"),
        (COL_PORT, "port"), (COL_HOST, "host"),
    ]:
        v = (row.get(csv_col) or "").strip()
        if v:
            m[key] = v
    role, gp, ep, mp = infer_role(row)
    m["role"] = role
    if gp > 0:
        m["gp"] = round(gp, 8)
    if ep > 0:
        m["ep"] = round(ep, 8)
    if mp > 0:
        m["mp"] = round(mp, 8)
    role_raw = (row.get(COL_ROLE) or "").strip().lower()
    if role_raw and role_raw != role:
        m["orig_role"] = role_raw
    return m


def load_state(state_path):
    """Load script state from separate file."""
    if state_path.exists():
        with open(state_path) as f:
            return json.load(f)
    return {}


def save_state(state_path, last_sha, last_date, commits_processed):
    """Save script state to separate file."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, "w") as f:
        json.dump({
            "last_commit_sha": last_sha,
            "last_commit_date": last_date,
            "commits_processed": commits_processed,
            "state_updated": datetime.now(timezone.utc).isoformat(),
        }, f, indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="Lists/TOR/tor_nodes_history.json")
    ap.add_argument("--state", default="Lists/TOR/.tor_history_state.json")
    ap.add_argument("--full", action="store_true", help="Force full rebuild")
    args = ap.parse_args()
    output = Path(args.output)
    state_path = Path(args.state)

    # ── Load state ───────────────────────────────────────────────────
    state = {} if args.full else load_state(state_path)
    last_sha = state.get("last_commit_sha")
    last_date = state.get("last_commit_date")
    prev_count = state.get("commits_processed", 0)

    if last_sha:
        print(f"State: last SHA {last_sha[:7]} | date {last_date} | {prev_count} commits processed")
    elif args.full:
        print("Full rebuild requested.")
    else:
        print("No state file — first run.")

    # ── Load existing data (if any) ──────────────────────────────────
    ip_db = {}
    if output.exists() and not args.full:
        print(f"Loading existing data from {output}...")
        with open(output) as f:
            existing = json.load(f)
        ip_db = existing.get("ips", {})
        print(f"   {len(ip_db):,} existing IPs")

    # ── Get commits ──────────────────────────────────────────────────
    if last_date and not args.full:
        print(f"Fetching commits after {last_date[:19]}...")
        commits = get_new_commits(last_date, exclude_sha=last_sha)
        print(f"   {len(commits)} new commits")
        if not commits:
            print("Already up to date.")
            return
        sampled = sample(commits, hours=3)
    else:
        print("Fetching ALL commits...")
        commits = get_all_commits()
        print(f"   {len(commits)} total commits")
        if not commits:
            print("No commits found — is fetch-depth: 0 set?")
            sys.exit(1)
        sampled = sample(commits, hours=24)

    print(f"Processing {len(sampled)} commits...\n")

    # ── Process ──────────────────────────────────────────────────────
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
                ip_db[ip]["m"] = build_meta(row)
            print(f"-> {len(rows)} rows ({new} new)")
        except Exception as e:
            errors += 1
            print(f"ERROR: {e}")

    # ── Merge periods ────────────────────────────────────────────────
    print("\nMerging periods...")
    for ip in ip_db:
        ip_db[ip]["p"] = merge_periods(ip_db[ip]["p"])

    # ── Compute stats for the data feed ──────────────────────────────
    firsts, lasts = [], []
    for d in ip_db.values():
        for p in d["p"]:
            if p[0]:
                firsts.append(p[0])
            if p[1]:
                lasts.append(p[1])

    role_counts = {}
    for d in ip_db.values():
        r = d.get("m", {}).get("role", "unknown")
        role_counts[r] = role_counts.get(r, 0) + 1

    country_counts = {}
    for d in ip_db.values():
        cc = d.get("m", {}).get("cc", "")
        if cc:
            country_counts[cc] = country_counts.get(cc, 0) + 1

    # ── Write clean data feed (no script state) ──────────────────────
    feed = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "source": f"https://github.com/mthcht/awesome-lists/blob/main/{FILE_PATH}",
        "total_ips": len(ip_db),
        "range": [min(firsts) if firsts else "", max(lasts) if lasts else ""],
        "roles": role_counts,
        "top_countries": dict(sorted(country_counts.items(), key=lambda x: -x[1])[:30]),
        "ips": ip_db,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(feed, f, separators=(",", ":"))

    # ── Write state separately ───────────────────────────────────────
    total_processed = prev_count + len(sampled)
    save_state(state_path, sampled[-1]["sha"], sampled[-1]["date"], total_processed)

    mb = output.stat().st_size / 1048576
    print(f"\nDone: {output} ({mb:.1f} MB)")
    print(f"   {len(ip_db):,} IPs | {feed['range'][0]} -> {feed['range'][1]}")
    print(f"   Roles: {role_counts}")
    print(f"   State: {state_path}")
    print(f"   {len(sampled)} commits this run ({total_processed} total)")


if __name__ == "__main__":
    main()
