import requests

def fetch_csv(url, output_file):
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(output_file, 'wb') as file:
            file.write(response.content)
        print(f"CSV file has been fetched and saved as {output_file}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch the CSV file: {e}")

if __name__ == "__main__":
    url = "https://www.loldrivers.io/api/drivers.csv"
    output_file = "loldrivers_list.csv"
    fetch_csv(url, output_file)
