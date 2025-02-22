# from https://github.dev/mthcht/awesome-lists
# resolving the top1M domains (NS only)

import asyncio
import aiosqlite
import sqlite3
import csv
import json
import requests
import argparse
import tempfile
import os
from datetime import datetime
from rich.console import Console, Group
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, BarColumn, TextColumn
from rich.panel import Panel
from rich.live import Live

console = Console()

DB_FILE = "dns_records.db"
MAX_DOMAINS = 1000000  # Number of domains to process per run
RECORD_TYPE = "NS"
RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]



async def initialize_database():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS domain_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP,
                processed INTEGER DEFAULT 0
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS dns_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                dns_records TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()

def fetch_top_domains():
    url = "https://github.com/mthcht/awesome-lists/raw/refs/heads/main/Lists/Domains/TOP1M/TOP1M_domains.csv"
    console.print(f"[INFO] Downloading top 1M domains from {url}", style="bold yellow")
    response = requests.get(url)
    domains = []
    if response.status_code == 200:
        csv_reader = csv.reader(response.text.splitlines())
        next(csv_reader)  # Skip header
        for row in csv_reader:
            domain = row[2].strip()
            if domain:
                domains.append(domain)
        # Insert domains using synchronous sqlite3 (one-off operation)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        for domain in domains:
            cursor.execute("INSERT OR IGNORE INTO domain_list (domain) VALUES (?)", (domain,))
        conn.commit()
        conn.close()
        console.print(f"[INFO] {len(domains)} domains saved to the database.", style="bold green")
    else:
        console.print(f"[ERROR] Failed to download domain list: {response.status_code}", style="bold red")
    return domains

async def get_domains_to_process():
    domains = []
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute("SELECT domain FROM domain_list WHERE processed = 0 LIMIT ?", (MAX_DOMAINS,)) as cursor:
            rows = await cursor.fetchall()
            domains = [row[0] for row in rows]
    return domains

def create_input_file(domains):
    """
    Create a temporary input file for massdns.
    Each line contains a single domain.
    """
    temp_input = tempfile.NamedTemporaryFile(mode="w+", delete=False)
    for domain in domains:
        temp_input.write(f"{domain}\n")
    temp_input.flush()
    return temp_input.name

def create_resolvers_file():
    """
    Create a temporary file containing the resolvers.
    """
    temp_resolvers = tempfile.NamedTemporaryFile(mode="w+", delete=False)
    for resolver in RESOLVERS:
        temp_resolvers.write(f"{resolver}\n")
    temp_resolvers.flush()
    return temp_resolvers.name

async def run_massdns_with_live_output(input_file, resolvers_file, total_queries):
    """
    Run massdns asynchronously while displaying a live progress bar and output log.
    We use stdbuf to force line buffering and query only A records.
    """
    # Create temporary file to store full output for later parsing.
    temp_output = tempfile.NamedTemporaryFile(mode="w+", delete=False)
    output_file = temp_output.name
    temp_output.close()

    # Build the massdns command.
    cmd = [
        "stdbuf", "-oL", "-eL", "massdns",
        "-r", resolvers_file,
        "-q",           # Quiet mode
        "-o", "S",      # Simple output format
        "-t", RECORD_TYPE,  # Query type: NS
        input_file
    ]
    console.print(f"[INFO] Running massdns with command: {' '.join(cmd)}", style="bold yellow")

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    output_log = []
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} queries")
    )
    task_id = progress.add_task("[cyan]MassDNS scanning...", total=total_queries)

    def renderable():
        log_text = "\n".join(output_log[-10:]) if output_log else ""
        return Group(progress, Panel(log_text, title="MassDNS Output", border_style="green"))

    with Live(renderable(), refresh_per_second=4, console=console) as live:
        with open(output_file, "w") as outfile:
            while True:
                try:
                    # Wait up to 0.5 seconds for a line.
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=0.5)
                except asyncio.TimeoutError:
                    live.update(renderable())
                    if process.returncode is not None:
                        break
                    continue
                if not line:
                    break
                decoded_line = line.decode().strip()
                outfile.write(decoded_line + "\n")
                output_log.append(decoded_line)
                progress.advance(task_id)
                live.update(renderable())
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        console.print(f"[ERROR] massdns failed: {stderr.decode()}", style="bold red")
        raise Exception("massdns execution failed")
    return output_file


def parse_massdns_output(output_file):
    """
    Parse massdns output, extracting only NS records.
    Expected format: domain. NS nsX.example.com.
    """
    results = {}

    with open(output_file, "r") as f:
        for line in f:
            line = line.strip()

            # Ignore status lines, only process NS record lines
            if not line or "NS" not in line or "pps" in line or "|" in line or "Processed" in line:
                continue

            parts = line.split()
            if len(parts) < 3:
                console.print(f"[WARNING] Skipping unexpected format: {line}", style="bold red")
                continue

            domain_raw = parts[0]  # Example: google.com.
            rtype = parts[1]        # Example: NS
            data = parts[2]         # Example: ns1.google.com.

            # Ensure we're only processing NS records
            if rtype != "NS":
                continue

            # Normalize domain name
            domain = domain_raw.rstrip('.').lower()

            # Store in dictionary
            if domain not in results:
                results[domain] = {"NS": []}

            results[domain]["NS"].append(data)

    console.print(f"[DEBUG] Parsed NS records: {json.dumps(results, indent=2)}", style="bold green")
    return results


async def update_database(results, input_domains):
    """
    Update the dns_history table with results for each domain.
    """
    async with aiosqlite.connect(DB_FILE) as db:
        for domain in input_domains:
            # Normalize domain to match keys from massdns output
            norm_domain = domain.lower()
            record = results.get(norm_domain, {})
            await db.execute(
                "INSERT INTO dns_history (domain, dns_records) VALUES (?, ?)",
                (domain, json.dumps(record))
            )
            await db.execute(
                "UPDATE domain_list SET processed = 1, last_checked = ? WHERE domain = ?",
                (datetime.now().isoformat(), domain)
            )
        await db.commit()

def cleanup_files(*files):
    for file in files:
        try:
            os.remove(file)
        except Exception:
            pass

async def browse_database():
    async with aiosqlite.connect(DB_FILE) as db:
        while True:
            domain = Prompt.ask("Enter a domain to search (or 'exit' to quit)")
            if domain.lower() == "exit":
                break
            async with db.execute("SELECT domain, dns_records FROM dns_history WHERE domain = ?", (domain,)) as cursor:
                rows = await cursor.fetchall()
            if rows:
                table = Table(title=f"Results for {domain}")
                table.add_column("Domain", style="bold cyan")
                table.add_column("DNS Records", style="bold magenta")
                for row in rows:
                    table.add_row(row[0], row[1])
                console.print(table)
            else:
                console.print(f"[WARNING] No records found for {domain}", style="bold red")

async def main_async():
    parser = argparse.ArgumentParser(description="MassDNS-based DNS scanner with live output")
    parser.add_argument("--rescan", action="store_true", help="Rescan previously processed domains")
    parser.add_argument("--browse", action="store_true", help="Browse DNS results")
    args = parser.parse_args()

    await initialize_database()

    if args.browse:
        await browse_database()
        return

    if not args.rescan:
        fetch_top_domains()

    domains = await get_domains_to_process()
    if not domains:
        console.print("[INFO] No unprocessed domains found.", style="bold yellow")
        return

    console.print(f"[INFO] Processing {len(domains)} domains using massdns", style="bold yellow")
    input_file = create_input_file(domains)
    resolvers_file = create_resolvers_file()

    total_queries = len(domains)

    output_file = None
    try:
        output_file = await run_massdns_with_live_output(input_file, resolvers_file, total_queries)
        results = parse_massdns_output(output_file)
        await update_database(results, domains)
        console.print("[INFO] DNS resolution completed successfully.", style="bold green")
    finally:
        if output_file:
            cleanup_files(input_file, resolvers_file, output_file)
        else:
            cleanup_files(input_file, resolvers_file)

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
