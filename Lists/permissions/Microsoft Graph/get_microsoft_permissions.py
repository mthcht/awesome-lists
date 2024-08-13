import requests
from bs4 import BeautifulSoup
import csv

# Microsoft Graph permissions reference page
url = "https://learn.microsoft.com/en-us/graph/permissions-reference#all-permissions"

response = requests.get(url)
soup = BeautifulSoup(response.content, 'html.parser')

if soup is None:
    print("Failed to retrieve content. Please check the URL or your internet connection.")
    exit()

# Find all sections with permissions (each h3 and the following table)
permissions = soup.find_all('h3')
if not permissions:
    print("No permissions found. The structure of the page might have changed.")
    exit()

# List of critical permissions i selected
critical_permissions = [
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Mail.ReadWrite",
    "Files.ReadWrite.All",
    "Calendars.ReadWrite",
    "AuditLog.Read.All",
    "Reports.Read.All",
    "SecurityEvents.ReadWrite.All",
    "Device.ReadWrite.All"
]

csv_data = []

# Extract data for each permission
for perm in permissions:
    permission_name = perm.get_text(strip=True)
    table = perm.find_next('table')
    
    if table is None:
        print(f"No table found for permission: {permission_name}")
        continue
    
    data_row = [permission_name]
    permission_data = {
        'Application Identifier': '',
        'Delegated Identifier': '',
        'Application DisplayText': '',
        'Delegated DisplayText': '',
        'Application Description': '',
        'Delegated Description': '',
        'Application AdminConsentRequired': '',
        'Delegated AdminConsentRequired': ''
    }
    
    rows = table.find_all('tr')
    for row in rows:
        columns = row.find_all('td')
        if len(columns) == 3:
            label = columns[0].get_text(strip=True)
            permission_data[f'Application {label}'] = columns[1].get_text(strip=True)
            permission_data[f'Delegated {label}'] = columns[2].get_text(strip=True)
        elif len(columns) == 2:
            label = columns[0].get_text(strip=True)
            permission_data[f'Application {label}'] = columns[1].get_text(strip=True)
    
    # Determine if the permission is critical (could be enhanced, let me know)
    is_critical = "yes" if permission_name in critical_permissions else "no"
    
    data_row.extend([
        permission_data['Application Identifier'],
        permission_data['Delegated Identifier'],
        permission_data['Application DisplayText'],
        permission_data['Delegated DisplayText'],
        permission_data['Application Description'],
        permission_data['Delegated Description'],
        permission_data['Application AdminConsentRequired'],
        permission_data['Delegated AdminConsentRequired'],
        is_critical
    ])
    
    csv_data.append(data_row)

# CSV headers
headers = [
    'permission_name',
    'application_id',
    'delegated_id',
    'application_text',
    'delegated_text',
    'application_description',
    'delegated_description',
    'application_AdminConsentRequired',
    'delegated_AdminConsentRequired',
    'metadata_is_critical'
]

csv_file_path = 'microsoft_graph_permissions.csv'
with open(csv_file_path, 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(headers)
    writer.writerows(csv_data)

print(f"Graph Permissions references saved to {csv_file_path}")