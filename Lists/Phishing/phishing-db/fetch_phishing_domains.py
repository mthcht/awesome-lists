import requests
import csv
from datetime import datetime

# Define the source URL and output filename
url = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt"
output_file = "phish_co_za_domains_list.csv"

# Get the current date in YYYY/MM/DD format
metadata_date = datetime.now().strftime("%Y/%m/%d")

# Fetch the file content
response = requests.get(url)
if response.status_code == 200:
    lines = response.text.splitlines()

    # Write to CSV file
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["dest_nt_domain", "metadata_reference", "metadata_list_last_updated"])  # Header
        
        # Write domain data
        for line in lines:
            if line.strip():  # Ignore empty lines
                writer.writerow([line.strip(), url, metadata_date])

    print(f"CSV file saved as {output_file}")
else:
    print("Failed to download the file.")

