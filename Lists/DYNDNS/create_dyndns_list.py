import requests
import csv
from io import StringIO

# URL of the CSV file
url = "https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/DYNDNS/dyn-dns-list-mthcht_corrected/links.csv"

# Fetch the CSV file
output_filename = "dyndns_list.csv"

try:
    print(f"Downloading CSV file from {url}...")
    response = requests.get(url)
    response.raise_for_status()  # Raise an error for failed requests

    # Parse the CSV content
    csv_content = StringIO(response.text)
    reader = csv.DictReader(csv_content)

    # New header names
    new_headers = ["dest_nt_domain", "metadata_RetrievedAt", "metadata_Provider"]

    # Open a new file to save the updated CSV
    with open(output_filename, "w", newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        # Write the new headers
        writer.writerow(new_headers)

        # Write the updated rows
        for row in reader:
            writer.writerow([row["Domain"], row["RetrievedAt"], row["Provider"]])

    print(f"CSV file has been downloaded and updated successfully as '{output_filename}'.")

except requests.exceptions.RequestException as e:
    print(f"Failed to download the CSV file. Error: {e}")
