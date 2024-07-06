import csv
import subprocess
import os

# Path to the CSV file
csv_file_path = 'latest_bad_asn_phishing_list.csv'

# Path to the script to be executed using relative path
script_path = os.path.join('..', 'Ranges_IP_Address_Company_List', 'bgp.he.net', 'get_ip_range.py')

# Read the AS numbers from the CSV file
as_numbers = []
with open(csv_file_path, mode='r', encoding='utf-8') as file:
    reader = csv.DictReader(file)
    for row in reader:
        as_numbers.append('AS' + row['as_number'])

# Join the AS numbers into a single string separated by commas
as_numbers_str = ','.join(as_numbers)

# Construct the command
command = f'python {script_path} -list {as_numbers_str} -format csv'

# Execute the command
subprocess.run(command, shell=True)

print(f"Command executed: {command}")
