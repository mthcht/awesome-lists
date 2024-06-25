import requests
import csv
from datetime import datetime
import logging
import time

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# URL to download the blacklist CSV
url = 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv'

# Fetch the CSV data
logging.debug("Starting download...")
response = requests.get(url)
response.raise_for_status()  # Ensure we notice bad responses
logging.debug("Download completed.")

# Read the CSV data
lines = response.text.splitlines()
reader = csv.reader(lines)
logging.debug("CSV data read into memory.")

# Prepare the output data
output_data = []

# Skip header lines
logging.debug("Processing data...")
for row in reader:
    if not row or row[0].startswith('#'):
        continue
    
    # Extract relevant data
    listing_date, sha1, description = row
    metadata_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    metadata_date_epoch = int(time.time())
    metadata_reference = url

    # Append to output list
    output_data.append([sha1, metadata_date, metadata_date_epoch, description, metadata_reference])
    logging.debug(f"Processed: {sha1}, {metadata_date}, {metadata_date_epoch}, {description}, {metadata_reference}")

# Output in the specified format
output_filename = 'ssl_certificates_malicious_list.csv'
with open(output_filename, mode='w', newline='') as file:
    writer = csv.writer(file)
    # Write header
    writer.writerow(['ssl_hash', 'metadata_date', 'metadata_date_epoch', 'metadata_description', 'metadata_reference'])
    # Write data rows
    writer.writerows(output_data)

logging.info(f'Reformatted data saved to {output_filename}')
