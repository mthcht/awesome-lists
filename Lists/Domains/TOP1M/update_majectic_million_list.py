import requests

url = 'https://downloads.majestic.com/majestic_million.csv'
file_path = 'TOP1M_domains.csv'

response = requests.get(url)

with open(file_path, 'wb') as file:
    file.write(response.content)

print(f'File downloaded successfully and saved as {file_path}')
