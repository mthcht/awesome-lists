import requests
import csv
import re
# from bs4 import BeautifulSoup  # No longer needed since we're skipping HTML parsing

# Fetch HTML content of the given URL
# def fetch_html(url):
#     response = requests.get(url)
#     response.raise_for_status()
#     return response.text

# Extract .ovpn file URLs from the HTML content
# def extract_ovpn_links(html_content):
#     soup = BeautifulSoup(html_content, 'html.parser')
#     links = soup.find_all('a', href=re.compile(r'.*\.ovpn$'))
#     return [link['href'] for link in links]

# Download .ovpn files and extract IP addresses and server names
# def download_and_extract_ips(ovpn_urls):
#     ip_server_list = []
#     for ovpn_url in ovpn_urls:
#         try:
#             response = requests.get(ovpn_url)
#             response.raise_for_status()
#             ips = re.findall(r'remote\s+([0-9.]+)\s+\d+', response.text)
#             server_name = re.search(r'servers/([^/]+)\.ovpn$', ovpn_url).group(1)
#             ip_server_list.extend([(ip, server_name) for ip in ips])
#         except requests.RequestException as e:
#             print(f"Failed to fetch {ovpn_url}: {e}")
#     return ip_server_list

# Fetch IPs and server names from NordVPN JSON API
def fetch_ips_from_api(api_url):
    ip_server_list = []
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()
        for server in data.get('servers', []):
            ip = server.get('station')
            server_name = server.get('hostname')
            if ip and server_name:
                # Add an empty string for metadata_comment
                ip_server_list.append((ip, server_name, "https://github.com/mthcht/awesome-lists"))
    except requests.RequestException as e:
        print(f"Failed to fetch API data: {e}")
    return ip_server_list

# Fetch IP addresses from a GitHub CSV
def fetch_ips_from_github_csv(github_url):
    ip_server_list = []
    try:
        response = requests.get(github_url)
        response.raise_for_status()
        content = response.text.splitlines()
        reader = csv.reader(content)
        for row in reader:
            # Skip header if it starts with '#ip'
            if len(row) < 2 or row[0].startswith('#ip'):
                continue
            ip = row[0]
            # For these IPs, store "N/A" as server name, and the github_url as comment
            ip_server_list.append((ip, "N/A", github_url))
    except requests.RequestException as e:
        print(f"Failed to fetch GitHub CSV data: {e}")
    return ip_server_list

# Save the extracted IPs and server names to a CSV file, removing duplicates
def save_to_csv(ip_server_list, filename):
    # Deduplicate by turning list into a set of tuples
    unique_ip_server_list = list(set(ip_server_list))
    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            # Now we have three columns
            writer.writerow(["src_ip", "metadata_servername", "metadata_comment"])
            writer.writerows(unique_ip_server_list)
        print(f"{len(unique_ip_server_list)} unique IP addresses exported to {filename}")
    except IOError as e:
        print(f"File writing failed: {e}")

def main():
    # base_url = 'https://nordvpn.com/fr/ovpn/'  # Skipping HTML fetching since it's redirecting to a login page since 2025/01
    api_url = 'https://api.nordvpn.com/v2/servers'
    github_url = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/refs/heads/master/vpn/NordVPNIPs.csv"

    # Fetch and process .ovpn links (DISABLED)
    # html_content = fetch_html(base_url)
    # ovpn_links = extract_ovpn_links(html_content)
    # full_ovpn_urls = [link if link.startswith('http') else f"https://nordvpn.com{link}" for link in ovpn_links]
    # ovpn_ip_server_list = download_and_extract_ips(full_ovpn_urls)
    
    # Fetch data from JSON API
    api_ip_server_list = fetch_ips_from_api(api_url)

    # Fetch IPs from GitHub CSV
    github_ip_list = fetch_ips_from_github_csv(github_url)
    
    # Combine both sources (only API data is used now)
    # combined_ip_server_list = ovpn_ip_server_list + api_ip_server_list
    
    # Combine both sources
    combined_ip_server_list = api_ip_server_list + github_ip_list
    save_to_csv(combined_ip_server_list, 'nordvpn_ips_list.csv')

if __name__ == "__main__":
    main()
