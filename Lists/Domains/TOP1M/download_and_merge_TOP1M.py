import requests
import pandas as pd
import io
import zipfile
import os

# URLs for the lists
majestic_url = 'https://downloads.majestic.com/majestic_million.csv'
tranco_zip_url = 'https://tranco-list.eu/top-1m.csv.zip'

# File paths
majestic_file = 'majestic_million_original.csv'
tranco_zip_file = 'tranco_list_original.zip'
tranco_csv_file = 'tranco_list_original.csv'
merged_file = 'TOP1M_domains.csv'

def download_file(url, file_path):
    """Downloads a file from a URL and saves it locally."""
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        return True
    else:
        print(f"Failed to download: {url}")
        return False

# Download Majestic Million
if download_file(majestic_url, majestic_file):
    with open(majestic_file, 'r', encoding='utf-8') as f:
        majestic_data = f.read()
else:
    majestic_data = None

# Download Tranco ZIP file
if download_file(tranco_zip_url, tranco_zip_file):
    # Extract the CSV from the ZIP
    with zipfile.ZipFile(tranco_zip_file, 'r') as zip_ref:
        extracted_file_name = zip_ref.namelist()[0]  # Get first file in ZIP
        zip_ref.extract(extracted_file_name, '.')  # Extract to current directory
        os.rename(extracted_file_name, tranco_csv_file)  # Rename it for consistency
else:
    tranco_csv_file = None

# Process Majestic Million (Extract 3rd column: 'Domain')
if majestic_data:
    majestic_df = pd.read_csv(majestic_file, usecols=[2], names=['dest_nt_domain'], header=0)
    majestic_df['metadata_comment'] = majestic_url
else:
    majestic_df = pd.DataFrame(columns=['dest_nt_domain', 'metadata_comment'])

# Process Tranco List (Extract 2nd column: 'Domain', no header)
if tranco_csv_file and os.path.exists(tranco_csv_file):
    tranco_df = pd.read_csv(tranco_csv_file, usecols=[1], names=['dest_nt_domain'], header=None, dtype=str)
    tranco_df['metadata_comment'] = tranco_zip_url
else:
    tranco_df = pd.DataFrame(columns=['dest_nt_domain', 'metadata_comment'])

# Merge lists
merged_df = pd.concat([majestic_df, tranco_df])

# Handle duplicates: If a domain appears in both lists, merge the metadata_comment
merged_df = merged_df.groupby('dest_nt_domain', as_index=False).agg({'metadata_comment': ' & '.join})

# Save the final merged list
merged_df.to_csv(merged_file, index=False)

print(f"Original Majestic Million saved as: {majestic_file}")
print(f"Original Tranco List ZIP saved as: {tranco_zip_file}")
print(f"Extracted Tranco List saved as: {tranco_csv_file}")
print(f"Merged list saved as: {merged_file}, total unique domains: {len(merged_df)}")
