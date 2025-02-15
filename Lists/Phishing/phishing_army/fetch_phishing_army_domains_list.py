import requests
import csv
from datetime import datetime

# Define the source URL and output filename
url = "https://phishing.army/download/phishing_army_blocklist_extended.txt"
output_file = "phishing_army_domains_list.csv"

# Get the current date in YYYY/MM/DD format
metadata_list_last_updated = datetime.now().strftime("%Y/%m/%d")

# Fetch the file content
response = requests.get(url)
if response.status_code == 200:
    lines = response.text.splitlines()

    # Remove empty lines and commented lines (starting with "#")
    filtered_lines = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

    # Write to CSV file
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["dest_nt_domain", "metadata_reference", "metadata_list_last_updated"])  # Header
        
        # Write domain data
        for line in filtered_lines:
            writer.writerow([line, url, metadata_list_last_updated])

    print(f"CSV file saved as {output_file}")
else:
    print("Failed to download the file.")
