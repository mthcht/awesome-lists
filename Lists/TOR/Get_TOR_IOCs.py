import requests
import json
import csv

ascii_art='''
  _______           _   _           _             _      _     _   
 |__   __|         | \ | |         | |           | |    (_)   | |  
    | | ___  _ __  |  \| | ___   __| | ___  ___  | |     _ ___| |_ 
    | |/ _ \| '__| | . ` |/ _ \ / _` |/ _ \/ __| | |    | / __| __|
    | | (_) | |    | |\  | (_) | (_| |  __/\__ \ | |____| \__ \ |_ 
    |_|\___/|_|    |_| \_|\___/ \__,_|\___||___/ |______|_|___/\__|
                                        
                              ..               
                            ... ...            
                         ....::..              
                        .--.:...               
                       .--::..                 
                      .=-...                   
                   @@ .-...                    
                    .  ::@                     
                    @   #@#                    
                    @.  @%@                    
                 @@@.   %%*@%@                 
               @@@   = . -@=-#@%               
            @@@      # =  :@+=--%@@            
           @@      @-   @  @@++=-:%%           
         @@     @@    .. *  @***+=-=@#         
        @@    @+     @ *  @ %%+*+++--@@        
        @@  :@     @+  .@  :.@+*++++-%#        
        @:  @    @.      @ @ @=*++++-*%        
        @:  @  @#     @+   % @=*++++-*%        
        @@  @  %  . #* ::  @.@=*++++-%#        
         @  :# %    %   @ -*@%+*+--=@%         
         @@-  @%*   @   @ @ @++*+--=@#         
           @@  .+@  %   + .@@=+=-:@@           
            @@@.   . + . @@*---#@%%            
                @@@@@@@@@@-*%@@                
    from: https://github.com/mthcht/awesome-lists/ 
'''

print(ascii_art)

# Function to process each address and extract IP and port, handling IPv6 correctly
def process_address(address):
    if address.startswith('['):
        # Splitting IPv6 address with a port
        ip, _, port = address[1:].partition(']:')
    else:
        # Splitting IPv4 or IPv6 without a port
        ip, _, port = address.partition(':')
    return ip, port

# Fetch the data from the Onionoo API and save the original JSON
url = 'https://onionoo.torproject.org/details'
response = requests.get(url)
data = response.json()
json_file_path = 'TOR_nodes_list.json'
with open(json_file_path, 'w', encoding='utf-8') as json_file:
    json.dump(data, json_file, ensure_ascii=False, indent=4)

# Specify original fields for CSV including new ones, excluding 'verified_host_names' since it's being handled separately
original_fields = [
    'nickname', 'fingerprint', 'last_seen',
    'first_seen', 'running', 'country', 'country_name', 'as', 'as_name',
    'contact', 'guard_probability', 'exit_probability', 'middle_probability'
]

# Rename some fields by adding "metadata_" prefix
fields = ['metadata_' + field for field in original_fields] + ['dest_ip', 'dest_port', 'metadata_dest_role', 'dest_nt_host']

# Prepare a dictionary to hold the best entries for each IP
entries_by_ip = {}

# Lists to hold exit node and guard node IPs
exit_node_ips = []
guard_node_ips = []

# Determine the "dest_role" based on probabilities
def determine_dest_role(entry):
    probabilities = {
        "guard": float(entry.get("guard_probability", 0)),
        "exit": float(entry.get("exit_probability", 0)),
        "middle": float(entry.get("middle_probability", 0))
    }
    highest_role = max(probabilities, key=probabilities.get)
    return highest_role if probabilities[highest_role] > 0 else "unknown"

# Iterate over each entry in the data to fill entries_by_ip
for entry in data.get('relays', []) + data.get('bridges', []):
    for address_type in ['or_addresses', 'exit_addresses']:
        addresses = entry.get(address_type, [])
        for address in addresses:
            ip, port = process_address(address)
            # Prepare entry data with additional fields
            entry_data = {'metadata_' + key: entry.get(key, '') for key in original_fields}
            entry_data['dest_nt_host'] = ', '.join(entry.get('verified_host_names', [])) if entry.get('verified_host_names', []) else ''
            entry_data['dest_ip'] = ip
            entry_data['dest_port'] = port
            entry_data['metadata_dest_role'] = determine_dest_role(entry)
            
            # Define a unique key based on IP and port, or just IP if there's no port
            unique_key = f"{ip}:{port}" if port else ip

            # Check for an existing entry without a port when the current entry has a port
            if port:
                # Replace or add the entry with a port, ensuring it takes precedence over any without a port
                entries_by_ip[unique_key] = entry_data
                # Additionally, remove the entry without a port if it exists
                if ip in entries_by_ip and not entries_by_ip[ip]['dest_port']:
                    del entries_by_ip[ip]
            else:
                # For entries without a port, add only if there's no entry with the same IP and any port
                if not any(key.startswith(f"{ip}:") for key in entries_by_ip):
                    entries_by_ip[ip] = entry_data

            # Collect exit node IPs
            if entry_data['metadata_dest_role'] == 'exit':
                exit_node_ips.append(ip)

            # Collect guard node IPs
            if entry_data['metadata_dest_role'] == 'guard':
                guard_node_ips.append(ip)

csv_file_path = 'TOR_nodes_list.csv'

# Write the processed entries to the CSV file
with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=fields)
    writer.writeheader()
    for entry in entries_by_ip.values():
        writer.writerow(entry)

print(f"All TOR nodes written to {csv_file_path}")

# Write the exit node IPs to a separate CSV file
exit_ips_file_path = 'only_tor_exit_nodes_IP_list.csv'
with open(exit_ips_file_path, mode='w', newline='', encoding='utf-8') as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(['dest_ip'])
    for ip in exit_node_ips:
        writer.writerow([ip])

print(f"Exit node IPs written to {exit_ips_file_path}")

# Write the guard node IPs to a separate CSV file
guard_ips_file_path = 'only_tor_guard_nodes_IP_list.csv'
with open(guard_ips_file_path, mode='w', newline='', encoding='utf-8') as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(['dest_ip'])
    for ip in guard_node_ips:
        writer.writerow([ip])

print(f"Guard node IPs written to {guard_ips_file_path}")
