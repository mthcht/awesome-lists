import requests
import csv
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_vpn_data(url):
    try:
        logging.debug(f"Fetching data from {url}")
        response = requests.get(url)
        response.raise_for_status() 
        logging.debug("Data fetched successfully")
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None

def extract_ip_data(response_json):
    ip_list = []
    try:
        for server in response_json['LogicalServers']:
            entry_country = server['EntryCountry']
            exit_country = server['ExitCountry']
            for server_info in server['Servers']:
                entry_ip = server_info['EntryIP']
                exit_ip = server_info['ExitIP']
                ip_list.append([entry_ip, exit_ip, entry_country, exit_country])
        logging.debug("IP data extracted successfully")
    except KeyError as e:
        logging.error(f"Key error: {e}")
    return ip_list

def save_to_csv(ip_list, filename):
    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["src_ip_entry", "src_ip_exit", "src_country_entry", "src_country_exit"])
            writer.writerows(ip_list)
        logging.debug(f"Data written to {filename} successfully")
    except IOError as e:
        logging.error(f"File writing failed: {e}")

def main():
    url = 'https://api.protonmail.ch/vpn/logicals'
    response_json = fetch_vpn_data(url)
    
    if response_json:
        ip_list = extract_ip_data(response_json)
        save_to_csv(ip_list, 'protonvpn_ip_list.csv')
        num_ips = len(ip_list)
        print(f"{num_ips} records exported to protonvpn_ips.csv")

if __name__ == "__main__":
    main()
