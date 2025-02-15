import requests
import csv

# Define URL
feed_url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
output_file = "openphish_url_list.csv"

# Download the feed
response = requests.get(feed_url)
if response.status_code == 200:
    urls = response.text.strip().split("\n")
else:
    print("Failed to download feed.")
    exit()

# Write to CSV
with open(output_file, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["url", "metadata_reference"])
    for url in urls:
        writer.writerow([url, feed_url])

print(f"CSV file saved as {output_file}")
