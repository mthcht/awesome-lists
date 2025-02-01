import os
import pandas as pd
from collections import defaultdict

def process_txt_files(output_csv='PROXY_ALL_hideip_me_List.csv'):
    data = defaultdict(set)
    files = [f for f in os.listdir() if f.endswith('.txt')]
    
    for file in files:
        with open(file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) == 3:
                    dest_ip, dest_port, dest_country = parts
                    data[(dest_ip, dest_port, dest_country)].add(file)  # Collecting filenames in a set
    
    # Convert collected data to a DataFrame
    df = pd.DataFrame(
        [(ip, port, country, ', '.join(sorted(files))) for (ip, port, country), files in data.items()],
        columns=['dest_ip', 'dest_port', 'dest_country', 'metadata_file']
    )
    
    # Save to CSV
    df.to_csv(output_csv, index=False, encoding='utf-8')
    print(f"Merged CSV saved as {output_csv}")

if __name__ == "__main__":
    process_txt_files()
