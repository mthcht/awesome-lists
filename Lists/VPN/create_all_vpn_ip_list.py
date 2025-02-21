import os
import csv

def merge_csv_files(output_file='VPN_ALL_IP_List.csv'):
    all_data = []
    all_columns = set()

    # Recursively find and read all CSV files
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.lower().endswith('.csv'):
                csv_path = os.path.join(root, file)
                with open(csv_path, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        all_data.append(row)
                        all_columns.update(row.keys())

    # Write merged CSV with all columns
    all_columns = list(all_columns)
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=all_columns)
        writer.writeheader()
        for row in all_data:
            writer.writerow(row)

if __name__ == "__main__":
    merge_csv_files("VPN_ALL_IP_List.csv")
