import requests
from bs4 import BeautifulSoup
import csv
import re

# URL of the main page containing the links to quarterly reports
main_url = "https://www.cybercrimeinfocenter.org/phishing-activity"
main_response = requests.get(main_url)
main_response.raise_for_status()

main_soup = BeautifulSoup(main_response.content, 'html.parser')

# Find all the links to the quarterly reports for "bad ASN"
asn_report_links = main_soup.find_all('a', href=re.compile(r'/phishing-activity-in-hosting-networks-'))

# Get the latest report link (the first link shold be the latest one)
latest_asn_report_url = "https://www.cybercrimeinfocenter.org" + asn_report_links[0]['href']
asn_response = requests.get(latest_asn_report_url)
asn_response.raise_for_status()

asn_soup = BeautifulSoup(asn_response.content, 'html.parser')

# Find the specific table by heading, using a regex to account for date changes
asn_heading = asn_soup.find('h2', string=re.compile(r'Ranking of Hosting Networks \(ASNs\) by Phishing Attack Score'))
asn_table = asn_heading.find_next('table', {'border': '1', 'cellpadding': '6pt'})

# Extract table rows
asn_rows = asn_table.find_all('tr')[1:]

# Open a CSV file to write the extracted data
with open('latest_bad_asn_phishing_list.csv', mode='w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    writer.writerow(['rank', 'hosting_provider', 'as_number', 'routed_ipv4_addresses', 'phishing_attacks', 'phishing_attack_score'])

    # Write data rows to CSV
    for row in asn_rows:
        columns = row.find_all('td')
        rank = columns[0].text.strip()
        hosting_provider = columns[1].text.strip()
        as_number = columns[2].text.strip()
        routed_ipv4_addresses = columns[3].text.strip().replace(",", "")
        phishing_attacks = columns[4].text.strip().replace(",", "")
        phishing_attack_score = columns[5].text.strip()

        data = [rank, hosting_provider, as_number, routed_ipv4_addresses, phishing_attacks, phishing_attack_score]
        writer.writerow(data)

print(f"Data extraction complete. CSV file created as 'latest_bad_asn_phishing_list.csv'. Latest report fetched from {latest_asn_report_url}")
