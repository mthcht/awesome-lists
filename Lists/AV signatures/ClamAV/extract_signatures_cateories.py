import os
from collections import defaultdict

signatures_file = 'ClamAV_All_signatures_list.csv' 
signatures_by_category = defaultdict(list)

output_dir = 'signatures'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

with open(signatures_file, 'r') as f:
    for line in f:
        # Extract the category from the signature name
        signature_name = line.strip()
        if '.' in signature_name:
            category = '.'.join(signature_name.split('.')[:2])
            signatures_by_category[category].append(signature_name)

# Write each category's signatures to a separate file in the 'signatures' directory
for category, signatures in signatures_by_category.items():
    category_filename = os.path.join(output_dir, f'{category}.txt')
    with open(category_filename, 'w') as f:
        for signature in signatures:
            f.write(signature + '\n')

print(f"Signatures have been organized into the '{output_dir}' directory.")
