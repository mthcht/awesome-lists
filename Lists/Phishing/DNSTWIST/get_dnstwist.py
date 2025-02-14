import csv
import logging
import subprocess
import sys
from pathlib import Path

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])

def run_dnstwist(domain):
    """
    Run the dnstwist command and return the output.
    """
    try:
        logging.debug(f"Running dnstwist for domain: {domain}")
        result = subprocess.run(['dnstwist', domain, '--format', 'csv'], capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"dnstwist failed with error: {result.stderr}")
            return None
        logging.debug(f"dnstwist output: {result.stdout}")
        return result.stdout
    except Exception as e:
        logging.error(f"Exception occurred while running dnstwist: {e}")
        return None

def parse_dnstwist_output(output):
    """
    Parse the CSV output from dnstwist.
    """
    try:
        logging.debug("Parsing dnstwist output")
        rows = output.splitlines()
        reader = csv.reader(rows)
        parsed_data = [row for row in reader]
        logging.debug(f"Parsed data: {parsed_data}")
        return parsed_data
    except Exception as e:
        logging.error(f"Exception occurred while parsing dnstwist output: {e}")
        return None

def write_to_csv(data, output_file):
    """
    Write parsed data to a CSV file.
    """
    try:
        logging.debug(f"Writing data to CSV file: {output_file}")
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(data)
        logging.debug("Data written to CSV file successfully")
    except Exception as e:
        logging.error(f"Exception occurred while writing to CSV file: {e}")

def process_domain(domain):
    """
    Process a single domain to generate dnstwist information and write to a CSV file.
    """
    logging.info(f"Starting dnstwist analysis for domain: {domain}")
    output = run_dnstwist(domain)
    if output:
        data = parse_dnstwist_output(output)
        if data:
            output_file = f"{domain}_dnstwist_list.csv"
            write_to_csv(data, output_file)
    else:
        logging.warning(f"No output received for domain: {domain}")
    logging.info(f"Completed dnstwist analysis for domain: {domain}")

def main(domain_list):
    """
    Main function to process a list of domains.
    """
    for domain in domain_list:
        process_domain(domain)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python get_dnstwist.py domain1 [domain2 ... domainN] or python get_dnstwist.py domains.txt")
        sys.exit(1)

    input_arg = sys.argv[1]
    domains = []

    # Check if the argument is a file or a list of domains
    if Path(input_arg).is_file():
        try:
            with open(input_arg, 'r') as file:
                domains = [line.strip() for line in file.readlines()]
            logging.debug(f"Loaded domains from file: {domains}")
        except Exception as e:
            logging.error(f"Exception occurred while reading domains file: {e}")
            sys.exit(1)
    else:
        domains = sys.argv[1:]
        logging.debug(f"Loaded domains from arguments: {domains}")

    main(domains)
