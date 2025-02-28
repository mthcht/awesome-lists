import os
import requests
import csv
import json

def download_file(url, filename):
    try:
        print(f"Starting download: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        with open(filename, 'wb') as file:
            file.write(response.content)
        
        print(f"Successfully downloaded: {filename} ({len(response.content)} bytes)")
    except requests.RequestException as e:
        print(f"Failed to download {url}: {e}")

def create_csv(output_filename, proxy_files):
    print(f"Creating CSV file: {output_filename}")
    csv_header = ["dest_ip", "dest_port", "metadata_type", "metadata_country"]
    
    with open(output_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(csv_header)
        
        for proxy_file in proxy_files:
            print(f"Processing file: {proxy_file}")
            try:
                with open(proxy_file, 'r') as file:
                    proxies = json.load(file)
                    print(f"Loaded {len(proxies)} entries from {proxy_file}")
                    
                    for proxy in proxies:
                        writer.writerow([
                            proxy.get("ip", ""),
                            proxy.get("port", ""),
                            proxy.get("type", ""),
                            proxy.get("country", "")
                        ])
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"Error processing {proxy_file}: {e}")
    print(f"CSV file '{output_filename}' created successfully with combined proxy data.")

if __name__ == "__main__":
    proxy_urls = {
        "http_proxies.json": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/http_proxies.json",
        "socks4_proxies.json": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks4_proxies.json",
        "socks5_proxies.json": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks5_proxies.json"
    }
    
    for filename, url in proxy_urls.items():
        download_file(url, filename)
    
    create_csv("PROXY_ALL_sunny9577_list.csv", list(proxy_urls.keys()))
