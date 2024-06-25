import requests
import csv

def fetch_csv(url, output_file):
    try:
        response = requests.get(url)
        response.raise_for_status() 
        with open(output_file, 'wb') as file:
            file.write(response.content)
        print(f"CSV file has been fetched and saved as {output_file}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch the CSV file: {e}")

def filter_and_split_columns(input_file, output_file):
    try:
        with open(input_file, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            fieldnames = ['file_hash', 'metadata_driver_name']
            with open(output_file, 'w', newline='', encoding='utf-8') as newfile:
                writer = csv.DictWriter(newfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in reader:
                    hashes = row['KnownVulnerableSamples_SHA256'].split(', ') if row['KnownVulnerableSamples_SHA256'] else row['KnownVulnerableSamples_SHA1'].split(', ')
                    driver_name = row['Tags']
                    for hash_value in hashes:
                        writer.writerow({'file_hash': hash_value, 'metadata_driver_name': driver_name})
        print(f"Filtered and split CSV file has been saved as {output_file}")
    except Exception as e:
        print(f"Failed to filter and save the CSV file: {e}")

if __name__ == "__main__":
    url = "https://www.loldrivers.io/api/drivers.csv"
    url2 = "https://www.bootloaders.io/api/bootloaders.csv"
    fetched_file = "loldrivers_list.csv"
    fetched_file2 = "malicious_bootloaders_list.csv"
    filtered_file = "loldrivers_only_hashes_list.csv"
    filtered_file2 = "malicious_bootloaders_only_hashes_list.csv"

    fetch_csv(url, fetched_file)
    fetch_csv(url2, fetched_file2)
    filter_and_split_columns(fetched_file, filtered_file)
    filter_and_split_columns(fetched_file2, filtered_file2)
