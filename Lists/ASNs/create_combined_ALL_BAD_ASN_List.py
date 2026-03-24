import os
import csv
import glob

# Directory where the AS*_IP_Ranges.csv files are stored
input_folder = 'ASN_IP_Ranges'
output_file = '_ALL_BAD_ASN_IP_Ranges_List.csv'
metadata_file = 'asn_metadata_infos.csv'

# --- Step 1: Load ASNs with high false_positive_rate from metadata ---
high_fp_asns = set()

if os.path.exists(metadata_file):
    with open(metadata_file, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('false_positive_rate', '').strip().lower() == 'high':
                asn = row.get('as_number', '').strip().upper()
                if asn:
                    high_fp_asns.add(asn)
    print(f"Loaded {len(high_fp_asns)} ASNs with high false_positive_rate to exclude:")
    for asn in sorted(high_fp_asns):
        print(f"  - {asn}")
else:
    print(f"Warning: {metadata_file} not found. No ASNs will be excluded.")

# --- Step 2: Collect all AS*_IP_Ranges.csv files ---
asn_files = glob.glob(os.path.join(input_folder, 'AS*_IP_Ranges.csv'))

# --- Step 3: Read each file, skip those whose ASN is in the exclusion set ---
all_rows = set()
skipped_files = []

for file in asn_files:
    # Extract ASN from filename (e.g. "AS13335_IP_Ranges.csv" -> "AS13335")
    basename = os.path.basename(file)
    file_asn = basename.split('_')[0].upper()

    if file_asn in high_fp_asns:
        skipped_files.append(basename)
        continue

    with open(file, mode='r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)  # Read and ignore the header in each file
        for row in reader:
            # Extra safety: also check ASN in the metadata_comment column
            # metadata_comment format is "AS13335 IPv4" or "AS13335 IPv6"
            if len(row) >= 2:
                row_asn = row[1].strip().split()[0].upper()
                if row_asn in high_fp_asns:
                    continue
            all_rows.add(tuple(row))

# --- Step 4: Write the collected rows into the output file ---
with open(output_file, mode='w', encoding='utf-8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["dest_ip", "metadata_comment"])
    writer.writerows(sorted(all_rows))

print(f"\nSkipped {len(skipped_files)} files with high false_positive_rate:")
for name in sorted(skipped_files):
    print(f"  - {name}")
print(f"\nTotal unique IP ranges written: {len(all_rows)}")
print(f"Output: {output_file}")
