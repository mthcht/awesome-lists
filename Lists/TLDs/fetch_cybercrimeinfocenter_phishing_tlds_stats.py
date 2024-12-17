import requests
from bs4 import BeautifulSoup
import csv
import re

# Base URL
BASE_URL = "https://www.cybercrimeinfocenter.org"

# Main page URL
main_url = f"{BASE_URL}/phishing-activity"

# Fetch the main page
main_response = requests.get(main_url)
main_response.raise_for_status()
main_soup = BeautifulSoup(main_response.content, 'html.parser')

# Find all report links
report_links = main_soup.find_all('a', href=re.compile(r'phishing-activity-in-tlds-'))

# Function to sanitize and fix URLs
def sanitize_url(href):
    if href.startswith("http"):
        return href  # Already valid
    elif href.startswith("/"):
        return f"{BASE_URL}{href}"  # Relative URL, prepend domain
    else:
        # Remove any leading invalid domains and prepend BASE_URL
        cleaned_href = re.sub(r'^https?://', '', href)
        return f"{BASE_URL}/{cleaned_href.lstrip('/')}"

# Fix the latest report URL
latest_report_href = report_links[0]['href']
latest_report_url = sanitize_url(latest_report_href)

# Attempt to fetch the corrected report
try:
    response = requests.get(latest_report_url)
    response.raise_for_status()
except requests.exceptions.RequestException as e:
    print(f"Failed to fetch URL: {latest_report_url}. Error: {e}")
    exit()

# Parse the latest report
soup = BeautifulSoup(response.content, 'html.parser')
heading = soup.find('h2', string=re.compile(r'Ranking of TLDs by Phishing Domain Score'))
table = heading.find_next('table', {'border': '1', 'cellpadding': '6pt'})

# Extract table rows
rows = table.find_all('tr')[1:]

# Write data to CSV
output_file = "latest_bad_tlds_phishing_cybercrimeinfocenter_list.csv"
with open(output_file, mode='w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    # Write headers
    writer.writerow(['dest_nt_domain', 'metadata_rank', 'metadata_domains_count',
                     'metadata_phishing_domains_count', 'metadata_phishing_domain_score'])
    # Write table data
    for row in rows:
        columns = row.find_all('td')
        rank = columns[0].text.strip()
        tld = f"*.{columns[1].text.strip()}"
        domains_count = columns[2].text.strip().replace(",", "")
        phishing_domains_count = columns[3].text.strip().replace(",", "")
        phishing_domain_score = columns[4].text.strip()

        writer.writerow([tld, rank, domains_count, phishing_domains_count, phishing_domain_score])

print(f"Data extraction complete. CSV file saved as '{output_file}'. Latest report fetched from {latest_report_url}.")
