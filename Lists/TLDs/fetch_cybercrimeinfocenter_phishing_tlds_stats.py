import requests
from bs4 import BeautifulSoup
import csv
import re

# URL of the main page containing the links to quarterly reports
main_url = "https://www.cybercrimeinfocenter.org/phishing-activity"

main_response = requests.get(main_url)
main_response.raise_for_status()
main_soup = BeautifulSoup(main_response.content, 'html.parser')

# Find all the links to the quarterly reports
report_links = main_soup.find_all('a', href=re.compile(r'/phishing-activity-in-tlds-'))

# Get the latest report link (the first link shold be the latest one)
latest_report_url = "https://www.cybercrimeinfocenter.org" + report_links[0]['href']
response = requests.get(latest_report_url)
response.raise_for_status()
soup = BeautifulSoup(response.content, 'html.parser')

heading = soup.find('h2', string=re.compile(r'Ranking of TLDs by Phishing Domain Score'))
table = heading.find_next('table', {'border': '1', 'cellpadding': '6pt'})

# Extract table rows
rows = table.find_all('tr')[1:]

# Open a CSV file to write the extracted data
with open('latest_bad_tlds_phishing_cybercrimeinfocenter_list.csv', mode='w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    # Write new headers to CSV
    writer.writerow(['dest_nt_domain', 'metadata_rank', 'metadata_domains_count', 'metadata_phishing_domains_count', 'metadata_phishing_domain_score'])

    # Write data rows to CSV
    for row in rows:
        columns = row.find_all('td')
        rank = columns[0].text.strip()
        tld = f"*.{columns[1].text.strip()}"
        domains_count = columns[2].text.strip().replace(",", "")
        phishing_domains_count = columns[3].text.strip().replace(",", "")
        phishing_domain_score = columns[4].text.strip()

        data = [tld, rank, domains_count, phishing_domains_count, phishing_domain_score]
        writer.writerow(data)

print(f"Data extraction complete. CSV file created as 'latest_bad_tlds_phishing_cybercrimeinfocenter_list.csv'. Latest report fetched from {latest_report_url}")
