import requests
from bs4 import BeautifulSoup
import pandas as pd
import json
import argparse
import sys
import logging
import re
from datetime import datetime

# Set up logging
logging.basicConfig(filename='get_ip_range_debug.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def get_asns_and_ip_ranges(query):
    logging.info(f'Starting search for query: {query}')
    search_url = f'https://bgp.he.net/search?search%5Bsearch%5D={query}&commit=Search'
    response = requests.get(search_url)
    soup = BeautifulSoup(response.text, 'html.parser')

    asns = []
    ip_ranges = []

    rows = soup.find_all('tr')
    for row in rows:
        cols = row.find_all('td')
        if cols:
            result = cols[0].find('a')
            if result:
                result_text = result.get_text().strip()
                result_href = result['href']

                if result_href.startswith('/net/'):
                    ip_ranges.append((result_text, get_asn_from_ip_range(result_text)))
                elif result_href.startswith('/AS'):
                    asn_number = result_href[3:]
                    asns.append(asn_number)

    logging.info(f'Found ASNs: {asns} and IP ranges: {ip_ranges} for query: {query}')
    return asns, ip_ranges

def get_asn_from_ip_range(ip_range):
    logging.info(f'Retrieving ASN for IP range: {ip_range}')
    url = f'https://bgp.he.net/net/{ip_range}'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    div_netinfo = soup.find('div', id='netinfo')
    if not div_netinfo:
        logging.error(f"'div' with id 'netinfo' not found for IP range: {ip_range}")
        return "ASN not found"

    table = div_netinfo.find('table')
    if not table:
        logging.error(f"'table' not found under 'div#netinfo' for IP range: {ip_range}")
        return "ASN not found"

    asn_link = table.find('tbody').find('a', href=True, string=True)
    if asn_link and 'AS' in asn_link.get_text():
        asn_number = asn_link.get_text().replace('AS', '').strip()
        logging.info(f'Found ASN {asn_number} for IP range: {ip_range}')
        return f"AS{asn_number}"
    else:
        logging.warning(f'ASN not found for IP range: {ip_range}')
        return "ASN not found"

def get_asn_ip_ranges(asn_number):
    logging.info(f'Retrieving IP ranges for ASN: {asn_number}')
    url = f'https://bgp.he.net/AS{asn_number}#_prefixes'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    ip_ranges = []

    prefixes4_table = soup.find('table', id='table_prefixes4')
    if prefixes4_table:
        for row in prefixes4_table.find('tbody').find_all('tr'):
            ip_range = row.find_all('td')[0].text.strip()
            ip_ranges.append((ip_range, f"AS{asn_number} IPv4"))

    prefixes6_table = soup.find('table', id='table_prefixes6')
    if prefixes6_table:
        for row in prefixes6_table.find('tbody').find_all('tr'):
            ip_range = row.find_all('td')[0].text.strip()
            ip_ranges.append((ip_range, f"AS{asn_number} IPv6"))

    logging.info(f'IP ranges retrieved for ASN: {asn_number}')
    return ip_ranges

def save_output(query, all_ip_ranges, output_format):
    logging.info(f'Saving output for query: {query} in format: {output_format}')
    if output_format.lower() == 'csv':
        df = pd.DataFrame(all_ip_ranges, columns=['dest_ip', 'metadata_comment'])
        df.to_csv(f'{query}_IP_Ranges.csv', index=False)
    elif output_format.lower() == 'json':
        with open(f'{query}_IP_Ranges.json', 'w') as f:
            json.dump(all_ip_ranges, f, indent=4)
    else:
        logging.error("Unsupported output format. Please use 'csv' or 'json'.")
        print("Unsupported output format. Please use 'csv' or 'json'.")

def main(queries, output_format):
    asn_regex = re.compile(r'^AS\d+$')
    for query in queries:
        logging.info(f'Processing query: {query}')
        if asn_regex.match(query):
            asns = [query[2:]]
            initial_ip_ranges = []
        else:
            asns, initial_ip_ranges = get_asns_and_ip_ranges(query)

        all_ip_ranges = initial_ip_ranges.copy()

        for asn in asns:
            asn_ip_ranges = get_asn_ip_ranges(asn)
            all_ip_ranges.extend(asn_ip_ranges)

        all_ip_ranges = list(set(all_ip_ranges))
        save_output(query, all_ip_ranges, output_format)

    # Write sentinel log file at end
    with open('ASN_FETCH_DONE.log', 'w') as f:
        f.write(f'Done at {datetime.utcnow().isoformat()}Z\n')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Retrieve ASN and IP ranges of a company from bgp.he.net')
    parser.add_argument('-name', type=str, help='Specify the company name to retrieve its IP range')
    parser.add_argument('-list', type=str, help='Comma-separated list of company names to retrieve IP ranges')
    parser.add_argument('-format', type=str, choices=['csv', 'json'], default='csv', help='Output format')

    args = parser.parse_args()

    if args.name:
        queries = [args.name]
    elif args.list:
        queries = args.list.split(',')
    else:
        logging.error("No company name or list provided.")
        print("Please provide a company name with -name or a list of company names with -list. Examples: `python3 get_ip_range.py -name microsoft -format csv` OR `python3 get_ip_range.py -list microsoft,webex,DigitalOcean -format csv` ")
        sys.exit(1)

    main(queries, args.format)
