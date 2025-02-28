import requests
import csv

def download_proxy_list(url, output_filename):
    try:
        print(f"Starting download: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        proxies = response.text.strip().split('\n')
        
        print(f"Successfully downloaded {len(proxies)} proxies.")
        
        with open(output_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["dest_ip", "dest_port"])
            
            for proxy in proxies:
                if ':' in proxy:
                    ip, port = proxy.split(':', 1)
                    writer.writerow([ip.strip(), port.strip()])
        
        print(f"CSV file '{output_filename}' created successfully.")
    except requests.RequestException as e:
        print(f"Failed to download {url}: {e}")

if __name__ == "__main__":
    proxy_url = "https://api.openproxylist.xyz/http.txt"
    output_csv = "PROXY_ALL_openproxy_list.csv"
    download_proxy_list(proxy_url, output_csv)