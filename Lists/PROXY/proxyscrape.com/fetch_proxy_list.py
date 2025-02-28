import os
import logging
import requests
import pandas as pd
from io import StringIO

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Proxy list URL
URL = "http://api.proxyscrape.com/v4/free-proxy-list/get?request=get_proxies&proxy_format=ipport&format=csv"
FILE_NAME = "proxyscrape_proxies_raw.csv"
OUTPUT_FILE = "PROXY_ALL_proxyscrape_list.csv"

def download_proxy_list():
    try:
        logging.info("Starting proxy list download...")
        response = requests.get(URL, timeout=10)
        response.raise_for_status()  # Raise an error for bad responses (4xx, 5xx)
        
        with open(FILE_NAME, "wb") as file:
            file.write(response.content)
        
        logging.info(f"Proxy list downloaded successfully and saved as {FILE_NAME}")
        
        process_proxy_list(response.content.decode('utf-8'))
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading proxy list: {e}")
        exit(1)

def process_proxy_list(csv_data):
    try:
        df = pd.read_csv(StringIO(csv_data))
        
        df.rename(columns={
            'ip': 'dest_ip',
            'port': 'dest_port',
            'alive': 'metadata_alive',
            'alive_since': 'metadata_alive_since',
            'anonymity': 'metadata_anonymity',
            'average_timeout': 'metadata_average_timeout',
            'first_seen': 'metadata_first_seen',
            'ip_data_as': 'metadata_asn',
            'ip_data_asname': 'metadata_asname',
            'ip_data_city': 'metadata_city',
            'ip_data_continent': 'metadata_continent',
            'ip_data_continentCode': 'metadata_continent_code',
            'ip_data_country': 'metadata_country',
            'ip_data_countryCode': 'metadata_country_code',
            'ip_data_district': 'metadata_district',
            'ip_data_hosting': 'metadata_hosting',
            'ip_data_isp': 'metadata_isp',
            'ip_data_lat': 'metadata_latitude',
            'ip_data_lon': 'metadata_longitude',
            'ip_data_mobile': 'metadata_mobile',
            'ip_data_org': 'metadata_org',
            'ip_data_proxy': 'metadata_proxy',
            'ip_data_regionName': 'metadata_region',
            'ip_data_status': 'metadata_status',
            'ip_data_timezone': 'metadata_timezone',
            'ip_data_zip': 'metadata_zip',
            'ip_data_last_update': 'metadata_last_update',
            'last_seen': 'metadata_last_seen',
            'protocol': 'metadata_protocol',
            'proxy': 'metadata_proxy_address',
            'ssl': 'metadata_ssl',
            'timeout': 'metadata_timeout',
            'times_alive': 'metadata_times_alive',
            'times_dead': 'metadata_times_dead',
            'uptime': 'metadata_uptime'
        }, inplace=True)
        
        df.to_csv(OUTPUT_FILE, index=False)
        logging.info(f"Processed proxy list saved as {OUTPUT_FILE}")
    except Exception as e:
        logging.error(f"Error processing proxy list: {e}")

if __name__ == "__main__":
    download_proxy_list()
