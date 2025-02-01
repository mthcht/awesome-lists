import os
import pandas as pd
from collections import defaultdict

def process_txt_files(output_csv='PROXY_ALL_TheSpeedX_List.csv'):
    data = set()
    files = [f for f in os.listdir() if f.endswith('.txt')]
    
    for file in files:
        with open(file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    dest_ip, dest_port = parts[:2]
                    data.add((dest_ip, dest_port))  # Store only dest_ip and dest_port
    
    # Convert collected data to a DataFrame
    df = pd.DataFrame(list(data), columns=['dest_ip', 'dest_port'])
    
    # Save to CSV
    df.to_csv(output_csv, index=False, encoding='utf-8')
    print(f"Merged CSV saved as {output_csv}")

if __name__ == "__main__":
    process_txt_files()
