#!/usr/bin/env python3
"""
build_tor_history.py

Runs INSIDE the repo via GitHub Actions.
Uses `git log` + `git show` directly — no API, no token needed.

First run  → processes all commits (sampled 1/day)
Next runs  → only processes commits after the last known SHA

Output: tor_nodes_history.json
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


# ---------------------------------------------------------------------------
# Git helpers (local CLI, zero API)
# ---------------------------------------------------------------------------

def git(args: list[str]) -> str:
    result = subprocess.run(
        ["git"] + args,
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def get_commits(since_sha: str | None = None) -> list[dict]:
    """
    All commits that touched FILE_PATH, oldest first.
    If since_sha is given, only return commits AFTER that one.
    """
    raw = git(["log", "--format=%H %aI", "--reverse", "--", FILE_PATH])
    if not raw:
        return []

    commits = []
    found_marker = since_sha is None
    for line in raw.splitlines():
        parts = line.strip().split(" ", 1)
        if len(parts) != 2:
            continue
        sha, date = parts
        if not found_marker:
            if sha == since_sha:
                found_marker = True
            continue
        commits.append({"sha": sha, "date": date})
    return commits


def get_file_at(sha: str) -> str:
    return git(["show", f"{sha}:{FILE_PATH}"])


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

def detect_columns(headers):
    m = {"ip": None, "first_seen": None, "last_seen": None}
    for h in headers:
        hl = h.lower().strip()
        if hl in ("ip", "ip_address", "address", "src_ip", "node_ip", "tor_ip"):
            m["ip"] = h; break
    if not m["ip"]:
        m["ip"] = headers[0]
    for h in headers:
        hl = h.lower().strip()
        if "first" in hl and "seen" in hl: m["first_seen"] = h
        if "last"  in hl and "seen" in hl: m["last_seen"]  = h
    return m


def parse_csv(text, col_map=None):
    reader = csv.reader(io.StringIO(text))
    try:
        hdrs = [h.strip().strip('"').strip("\ufeff") for h in next(reader)]
    except StopIteration:
        return col_map, [], []

    if col_map is None:
        col_map = detect_columns(hdrs)

    idx = {h: i for i, h in enumerate(hdrs)}
    ip_i = idx.get(col_map["ip"])
    fs_i = idx.get(col_map["first_seen"]) if col_map["first_seen"] else None
    ls_i = idx.get(col_map["last_seen"])  if col_map["last_seen"]  else None
    if ip_i is None:
        return col_map, hdrs, []

    skip = {ip_i, fs_i, ls_i} - {None}
    meta_cols = [(i, hdrs[i]) for i in range(len(hdrs)) if i not in skip]

    rows = []
    for row in reader:
        if len(row) <= ip_i:
            continue
        ip = row[ip_i].strip().strip('"')
        if not ip or ip.lower() == col_map["ip"].lower():
            continue
        fs = row[fs_i].strip().strip('"') if fs_i is not None and len(row) > fs_i else ""
        ls = row[ls_i].strip().strip('"') if ls_i is not None and len(row) > ls_i else ""
        meta = {}
        for mi, mn in meta_cols:
            if mi < len(row) and row[mi].strip():
                meta[mn] = row[mi].strip().strip('"')
        rows.append({"ip": ip, "fs": fs, "ls": ls, "m": meta})
    return col_map, hdrs, rows


def norm_date(d):
    if not d: return ""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M", "%Y-%m-%d", "%d/%m/%Y"):
        try: return datetime.strptime(d.strip(), fmt).strftime("%Y-%m-%d")
        except ValueError: pass
    return d.strip()[:10]


def merge_periods(periods):
    if not periods: return []
    parsed = sorted((p[0] or "1970-01-01", p[1] or "2099-12-31") for p in periods)
    merged = [list(parsed[0])]
    for s, e in parsed[1:]:
        prev = merged[-1]
        try:
            if datetime.strptime(s, "%Y-%m-%d") <= datetime.strptime(prev[1], "%Y-%m-%d") + timedelta(days=2):
                prev[1] = max(prev[1], e); continue
        except ValueError:
            if s <= prev[1]: prev[1] = max(prev[1], e); continue
        merged.append([s, e])
    return merged


def sample(commits, hours):
    if not commits: return []
    out, last_ts = [], None
    for c in commits:
        try:    ts = datetime.fromisoformat(c["date"])
        except: ts = datetime.now(timezone.utc)
        if last_ts is None or (ts - last_ts).total_seconds() >= hours * 3600:
            out.append(c); last_ts = ts
    if out[-1]["sha"] != commits[-1]["sha"]:
        out.append(commits[-1])
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="Lists/TOR/tor_nodes_history.json")
    ap.add_argument("--full", action="store_true", help="Force full rebuild")
    args = ap.parse_args()
    output = Path(args.output)

    # ── Load existing ────────────────────────────────────────────────────
    existing = {}
    if output.exists() and not args.full:
        print("📂 Loading existing history…")
        with open(output) as f:
            existing = json.load(f)
        print(f"   {existing.get('total_ips',0):,} IPs | last: {existing.get('last_commit_sha','?')[:7]}")

    ip_db      = existing.get("ips", {})
    col_map    = existing.get("_col_map")
    columns    = existing.get("columns", [])
    last_sha   = existing.get("last_commit_sha") if not args.full else None
    prev_count = existing.get("commits_processed", 0) if not args.full else 0

    # ── Get commits ──────────────────────────────────────────────────────
    if last_sha:
        print(f"🔍 New commits after {last_sha[:7]}…")
        commits = get_commits(since_sha=last_sha)
        print(f"   {len(commits)} new")
        if not commits:
            print("✅ Up to date — nothing to do"); return
        sampled = sample(commits, hours=3)
    else:
        print("🔍 First run — all commits…")
        commits = get_commits()
        print(f"   {len(commits)} total")
        if not commits:
            print("❌ No commits. Clone with fetch-depth: 0 ?"); sys.exit(1)
        sampled = sample(commits, hours=24)

    print(f"📊 Processing {len(sampled)} commits…\n")

    # ── Process ──────────────────────────────────────────────────────────
    errors = 0
    for i, c in enumerate(sampled):
        sha, cdate = c["sha"], c["date"]
        pct = int((i+1) / len(sampled) * 100)
        print(f"  [{pct:3d}%] {sha[:7]} ({cdate[:10]})", end=" ", flush=True)
        try:
            text = get_file_at(sha)
            col_map, hdrs, rows = parse_csv(text, col_map)
            if not columns and hdrs: columns = hdrs
            new = 0
            for r in rows:
                ip = r["ip"]
                fs = norm_date(r["fs"]) or cdate[:10]
                ls = norm_date(r["ls"]) or cdate[:10]
                if not fs: fs = ls
                if not ls: ls = fs
                if ip not in ip_db:
                    ip_db[ip] = {"p": [], "m": {}}; new += 1
                ip_db[ip]["p"].append([fs, ls])
                if r["m"]: ip_db[ip]["m"] = r["m"]
            print(f"→ {len(rows)} IPs ({new} new)")
        except Exception as e:
            errors += 1; print(f"ERROR: {e}")

    # ── Merge ────────────────────────────────────────────────────────────
    print("\n🔗 Merging periods…")
    for ip in ip_db:
        ip_db[ip]["p"] = merge_periods(ip_db[ip]["p"])

    # ── Stats ────────────────────────────────────────────────────────────
    firsts, lasts = [], []
    for d in ip_db.values():
        for p in d["p"]:
            if p[0] != "1970-01-01": firsts.append(p[0])
            if p[1] != "2099-12-31": lasts.append(p[1])

    # ── Write ────────────────────────────────────────────────────────────
    result = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "source": f"https://github.com/mthcht/awesome-lists/blob/main/{FILE_PATH}",
        "total_ips": len(ip_db),
        "commits_processed": prev_count + len(sampled),
        "range": [min(firsts) if firsts else "", max(lasts) if lasts else ""],
        "columns": columns,
        "last_commit_sha": sampled[-1]["sha"],
        "last_commit_date": sampled[-1]["date"],
        "errors": errors,
        "_col_map": col_map,
        "ips": ip_db,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(result, f, separators=(",", ":"))

    mb = output.stat().st_size / 1048576
    print(f"\n✅ {output} ({mb:.1f} MB)")
    print(f"   {len(ip_db):,} unique IPs | {result['range'][0]} → {result['range'][1]}")
    print(f"   {len(sampled)} commits this run ({prev_count + len(sampled)} total)")


if __name__ == "__main__":
    main()
