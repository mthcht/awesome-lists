import requests
import csv

# Define the source URL and output filename
url = "https://dl.red.flag.domains/red.flag.domains.txt"
output_file = "red_flag_domains.csv"

# Fetch the file content
response = requests.get(url)
if response.status_code == 200:
    lines = response.text.splitlines()
    
    # Remove the first line if it starts with "#"
    if lines and lines[0].startswith("#"):
        lines = lines[1:]

    # Write to CSV file
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["dest_nt_domain", "metadata_reference"])  # Header
        
        # Write domain data
        for line in lines:
            if line.strip():  # Ignore empty lines
                writer.writerow([line.strip(), url])

    print(f"CSV file saved as {output_file}")
else:
    print("Failed to download the file.")
