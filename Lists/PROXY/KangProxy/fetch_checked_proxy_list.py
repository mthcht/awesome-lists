import requests
import csv
import re

def download_proxy_list(url):
    try:
        print(f"Starting download: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        proxies = response.text.strip().split('\n')
        print(f"Successfully downloaded {len(proxies)} proxies from {url}.")
        return proxies
    except requests.RequestException as e:
        print(f"Failed to download {url}: {e}")
        return []

def create_csv(output_filename, proxies):
    print(f"Creating CSV file: {output_filename}")
    
    unique_proxies = set()
    
    for proxy in proxies:
        match = re.match(r'http[s]?://([\d\.]+):(\d+)', proxy)
        if match:
            ip, port = match.groups()
            unique_proxies.add((ip.strip(), port.strip()))
    
    with open(output_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["dest_ip", "dest_port"])
        
        for ip, port in unique_proxies:
            writer.writerow([ip, port])
    
    print(f"CSV file '{output_filename}' created successfully with {len(unique_proxies)} unique proxies.")

if __name__ == "__main__":
    proxy_url = "https://raw.githubusercontent.com/officialputuid/KangProxy/refs/heads/KangProxy/xResults/RAW.txt"
    output_csv = "PROXY_ALL_kangproxy_List.csv"
    
    proxies = download_proxy_list(proxy_url)
    create_csv(output_csv, proxies)
