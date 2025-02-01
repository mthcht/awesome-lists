import os
import pandas as pd

def process_txt_files(output_csv='PROXY_ALL_hideip_me_List.csv'):
    data = []
    files = [f for f in os.listdir() if f.endswith('.txt')]
    
    for file in files:
        with open(file, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) == 3:
                    dest_ip, dest_port, dest_country = parts
                    data.append((dest_ip, dest_port, dest_country, file))
    
    # Create DataFrame and remove duplicates
    df = pd.DataFrame(data, columns=['dest_ip', 'dest_port', 'dest_country', 'metadata_file'])
    df.drop_duplicates(inplace=True)
    
    # Save to CSV
    df.to_csv(output_csv, index=False)
    print(f"Merged CSV saved as {output_csv}")

if __name__ == "__main__":
    process_txt_files()
