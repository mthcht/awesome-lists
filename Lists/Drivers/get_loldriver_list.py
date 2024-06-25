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

def filter_columns(input_file, output_file):
    try:
        with open(input_file, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            fieldnames = ['KnownVulnerableSamples_SHA256', 'Tags']
            new_fieldnames = ['file_hash', 'metadata_driver_name']
            with open(output_file, 'w', newline='', encoding='utf-8') as newfile:
                writer = csv.DictWriter(newfile, fieldnames=new_fieldnames)
                writer.writeheader()
                for row in reader:
                    filtered_row = {
                        'file_hash': row['KnownVulnerableSamples_SHA256'],
                        'metadata_driver_name': row['Tags']
                    }
                    writer.writerow(filtered_row)
        print(f"Filtered CSV file has been saved as {output_file}")
    except Exception as e:
        print(f"Failed to filter and save the CSV file: {e}")

if __name__ == "__main__":
    url = "https://www.loldrivers.io/api/drivers.csv"
    fetched_file = "loldrivers_list.csv"
    filtered_file = "loldrivers_only_hashes_list.csv"
    
    fetch_csv(url, fetched_file)
    filter_columns(fetched_file, filtered_file)
