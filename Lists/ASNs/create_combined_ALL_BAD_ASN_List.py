import os
import csv
import glob

# Directory where the AS*_IP_Ranges.csv files are stored
input_folder = 'ASN_IP_Ranges'
output_file = '_ALL_BAD_ASN_IP_Ranges_List.csv'

# Collect all AS*_IP_Ranges.csv files in the folder
asn_files = glob.glob(os.path.join(input_folder, 'AS*_IP_Ranges.csv'))

# Initialize a set to store unique rows (to avoid duplicates)
all_rows = set()

# Read each file and collect its rows
for file in asn_files:
    with open(file, mode='r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)  # Read and ignore the header in each file
        for row in reader:
            all_rows.add(tuple(row))  # Add rows as tuples to ensure uniqueness

# Write the collected rows into a single output file
with open(output_file, mode='w', encoding='utf-8', newline='') as f:
    writer = csv.writer(f)
    # Write the correct header
    writer.writerow(["dest_ip", "metadata_comment"])
    writer.writerows(sorted(all_rows))  # Sort rows to make it more readable

print(f"All ASNs concatenated into {output_file}")
