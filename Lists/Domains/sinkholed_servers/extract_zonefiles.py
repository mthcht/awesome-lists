import os
import gzip
import shutil

# Define source and destination directories
source_dir = "/zones/zonefiles/"
destination_dir = "/zones/extracted_zonefiles/"

# Ensure destination directory exists
os.makedirs(destination_dir, exist_ok=True)

# Iterate over all files in the source directory
for filename in os.listdir(source_dir):
    if filename.endswith(".gz"):
        source_file = os.path.join(source_dir, filename)
        destination_file = os.path.join(destination_dir, filename[:-3])  # Remove .gz extension

        # Extract the .gz file
        with gzip.open(source_file, 'rb') as f_in, open(destination_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

        print(f"Extracted: {filename} -> {destination_file}")

print("Extraction complete.")
