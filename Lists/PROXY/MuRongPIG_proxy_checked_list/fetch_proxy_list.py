import requests
import csv

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

def create_combined_csv(output_filename, proxy_urls):
    print(f"Creating combined CSV file: {output_filename}")
    
    unique_proxies = set()
    
    for url in proxy_urls:
        proxies = download_proxy_list(url)
        for proxy in proxies:
            if ':' in proxy:
                unique_proxies.add(proxy.strip())
    
    with open(output_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["dest_ip", "dest_port"])
        
        for proxy in unique_proxies:
            ip, port = proxy.split(':', 1)
            writer.writerow([ip.strip(), port.strip()])
    
    print(f"CSV file '{output_filename}' created successfully with {len(unique_proxies)} unique proxies.")

if __name__ == "__main__":
    proxy_urls = [
        "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/refs/heads/main/http_checked.txt",
        "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/refs/heads/main/socks4_checked.txt",
        "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/refs/heads/main/socks5_checked.txt"
    ]
    
    create_combined_csv("PROXY_ALL_MuRongPIG_checked_List.csv", proxy_urls)
