import os
import csv

directory = "."
output_csv = "Microsoft_Defender_All_signatures_list.csv"

files = [f for f in os.listdir(directory) if f.endswith('.txt')]

csv_data = []

for file in files:
    category = file.replace('.txt', '')
    file_path = os.path.join(directory, file)
    
    with open(file_path, 'r', encoding='utf-16') as f:
        signatures = f.readlines()
    
    for signature in signatures:
        signature = signature.strip()
        if signature:
            csv_data.append([signature, category, ""])

# Write data to CSV
with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(["signature", "metadata_category", "metadata_comment"])
    csv_writer.writerows(csv_data)

print(f"CSV file '{output_csv}' has been created successfully.")