import json
import csv
import requests

# Input and output file paths
json_url = "https://api.mullvad.net/app/v1/relays"
input_file = "relays.json"
output_file = "mullvad_relay_servers_ips_list.csv"

def download_json(url, filename):
    """
    Download the JSON file from the given URL and save it locally.
    """
    response = requests.get(url)
    response.raise_for_status()
    with open(filename, "w") as f:
        f.write(response.text)

def process_relay_data(json_data):
    """
    Process the JSON data to extract required fields.
    """
    rows = []

    # Extract OpenVPN relays
    for relay in json_data.get("openvpn", {}).get("relays", []):
        hostname = relay.get("hostname")
        if hostname:
            hostname += ".relays.mullvad.net"
        ipv4 = relay.get("ipv4_addr_in")
        ipv6 = relay.get("ipv6_addr_in")
        ports = json_data.get("openvpn", {}).get("ports", [])

        # Add IPv4 and IPv6 entries with ports
        for port_entry in ports:
            port = port_entry.get("port")
            protocol = port_entry.get("protocol")
            if protocol == "udp":
                continue  # Only handle TCP for OpenVPN

            if ipv4:
                rows.append({"dest_ip": ipv4, "dest_nt_domain": hostname, "dest_port": port})
            if ipv6:
                rows.append({"dest_ip": ipv6, "dest_nt_domain": hostname, "dest_port": port})

    # Extract WireGuard relays
    for relay in json_data.get("wireguard", {}).get("relays", []):
        hostname = relay.get("hostname")
        if hostname:
            hostname += ".relays.mullvad.net"
        ipv4 = relay.get("ipv4_addr_in")
        ipv6 = relay.get("ipv6_addr_in")
        port = 51820  # Default WireGuard port

        if ipv4:
            rows.append({"dest_ip": ipv4, "dest_nt_domain": hostname, "dest_port": port})
        if ipv6:
            rows.append({"dest_ip": ipv6, "dest_nt_domain": hostname, "dest_port": port})

    return rows

def save_to_csv(data, filename):
    """
    Save the processed data to a CSV file.
    """
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["dest_ip", "dest_nt_domain", "dest_port"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

# Main logic
if __name__ == "__main__":
    # Download the JSON file
    download_json(json_url, input_file)

    with open(input_file, "r") as f:
        json_data = json.load(f)

    processed_data = process_relay_data(json_data)
    save_to_csv(processed_data, output_file)
    print(f"Data saved to {output_file}")
