
import requests
from bs4 import BeautifulSoup
import pandas as pd
import json
import argparse
import sys
import logging
import re
from pathlib import Path
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

# Reset logs at startup and limit total log storage to ~2 MB
log_file = Path('get_ip_range_debug.log')

for old_log in (
    log_file,
    log_file.with_name(f'{log_file.name}.1')
):
    old_log.unlink(missing_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            log_file,
            maxBytes=1024 * 1024,
            backupCount=1,
            encoding='utf-8'
        )
    ]
)


def get_asns_and_ip_ranges(query):
    logging.info(f'Starting search for query: {query}')

    search_url = (
        f'https://bgp.he.net/search?search%5Bsearch%5D={query}&commit=Search'
    )

    response = requests.get(search_url, timeout=60)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, 'html.parser')

    asns = []
    ip_ranges = []

    for row in soup.find_all('tr'):
        cols = row.find_all('td')
        if not cols:
            continue

        result = cols[0].find('a', href=True)
        if not result:
            continue

        result_text = result.get_text().strip()
        result_href = result['href']

        if result_href.startswith('/net/'):
            ip_ranges.append((
                result_text,
                get_asn_from_ip_range(result_text)
            ))
        elif result_href.startswith('/AS'):
            asns.append(result_href[3:])

    logging.info(
        f'Found {len(asns)} ASNs and {len(ip_ranges)} IP ranges '
        f'for query: {query}'
    )

    return asns, ip_ranges


def get_asn_from_ip_range(ip_range):
    logging.info(f'Retrieving ASN for IP range: {ip_range}')

    url = f'https://bgp.he.net/net/{ip_range}'
    response = requests.get(url, timeout=60)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')
    div_netinfo = soup.find('div', id='netinfo')

    if not div_netinfo:
        logging.warning(f'Network information not found: {ip_range}')
        return 'ASN not found'

    table = div_netinfo.find('table')
    if not table:
        logging.warning(f'ASN table missing: {ip_range}')
        return 'ASN not found'

    tbody = table.find('tbody')
    if not tbody:
        return 'ASN not found'

    asn_link = tbody.find('a', href=True, string=True)

    if asn_link and 'AS' in asn_link.get_text():
        asn_number = asn_link.get_text().replace('AS', '').strip()
        return f'AS{asn_number}'

    logging.warning(f'ASN not found for {ip_range}')
    return 'ASN not found'


def get_asn_ip_ranges(asn_number):
    logging.info(f'Retrieving IP ranges for ASN: {asn_number}')

    url = f'https://bgp.he.net/AS{asn_number}#_prefixes'
    response = requests.get(url, timeout=60)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')
    ip_ranges = []

    prefixes4_table = soup.find('table', id='table_prefixes4')
    if prefixes4_table:
        tbody = prefixes4_table.find('tbody')
        if tbody:
            for row in tbody.find_all('tr'):
                cols = row.find_all('td')
                if cols:
                    ip_range = cols[0].text.strip()
                    ip_ranges.append((ip_range, f'AS{asn_number} IPv4'))

    prefixes6_table = soup.find('table', id='table_prefixes6')
    if prefixes6_table:
        tbody = prefixes6_table.find('tbody')
        if tbody:
            for row in tbody.find_all('tr'):
                cols = row.find_all('td')
                if cols:
                    ip_range = cols[0].text.strip()
                    ip_ranges.append((ip_range, f'AS{asn_number} IPv6'))

    logging.info(
        f'Retrieved {len(ip_ranges)} IP ranges for AS{asn_number}'
    )

    return ip_ranges


def save_output(query, all_ip_ranges, output_format):
    logging.info(f'Saving output for {query} as {output_format}')

    if output_format.lower() == 'csv':
        df = pd.DataFrame(
            all_ip_ranges,
            columns=['dest_ip', 'metadata_comment']
        )
        df.to_csv(f'{query}_IP_Ranges.csv', index=False)

    elif output_format.lower() == 'json':
        with open(f'{query}_IP_Ranges.json', 'w') as file:
            json.dump(all_ip_ranges, file, indent=4)

    else:
        raise ValueError('Unsupported output format')


def main(queries, output_format):
    asn_regex = re.compile(r'^AS\d+$')

    # Remove any stale completion marker
    sentinel_file = Path('ASN_FETCH_DONE.log')
    sentinel_file.unlink(missing_ok=True)

    for query in queries:
        logging.info(f'Processing query: {query}')

        if asn_regex.match(query):
            asns = [query[2:]]
            initial_ip_ranges = []
        else:
            asns, initial_ip_ranges = get_asns_and_ip_ranges(query)

        all_ip_ranges = initial_ip_ranges.copy()

        for asn in asns:
            all_ip_ranges.extend(get_asn_ip_ranges(asn))

        all_ip_ranges = sorted(set(all_ip_ranges))
        save_output(query, all_ip_ranges, output_format)

    # Write completion marker only after successful processing
    with open(sentinel_file, 'w', encoding='utf-8') as file:
        file.write(
            f'Done at {datetime.now(timezone.utc).isoformat()}\n'
        )

    logging.info(f'Completed processing {len(queries)} queries')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Retrieve ASN and IP ranges from bgp.he.net'
    )

    parser.add_argument(
        '-name', type=str,
        help='Company name or ASN to retrieve'
    )
    parser.add_argument(
        '-list', type=str,
        help='Comma-separated list of company names or ASNs'
    )
    parser.add_argument(
        '-format', type=str,
        choices=['csv', 'json'],
        default='csv'
    )

    args = parser.parse_args()

    if args.name:
        queries = [args.name]
    elif args.list:
        queries = [q.strip() for q in args.list.split(',') if q.strip()]
    else:
        parser.error('Specify -name or -list')

    try:
        main(queries, args.format)
    except Exception:
        logging.exception('ASN retrieval failed')
        sys.exit(1)
