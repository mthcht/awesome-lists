import csv
import subprocess
import os

# Paths to the CSV files
latest_csv_file_path = 'latest_bad_asn_phishing_list.csv'
static_csv_file_path = 'bad_asn_static_list.csv'

# Path to the script to be executed using relative path
script_path = os.path.join('..', 'Ranges_IP_Address_Company_List', 'bgp.he.net', 'get_ip_range.py')

# Function to read AS numbers from a CSV file
def read_as_numbers(csv_file_path):
    as_numbers = []
    with open(csv_file_path, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            as_numbers.append('AS' + row['as_number'])
    return as_numbers

# Read AS numbers from both files
latest_as_numbers = read_as_numbers(latest_csv_file_path)
static_as_numbers = read_as_numbers(static_csv_file_path)

# Combine AS numbers from both lists
combined_as_numbers = list(set(latest_as_numbers + static_as_numbers))

# Join the AS numbers into a single string separated by commas
as_numbers_str = ','.join(combined_as_numbers)

# Construct the command
command = f'python {script_path} -list {as_numbers_str} -format csv'

# Execute the command
subprocess.run(command, shell=True)

print(f"Command executed: {command}")
