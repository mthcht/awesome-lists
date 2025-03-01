import os
import requests
import zipfile
import shutil

# Define download URLs
BASE_URL = "https://download.maxmind.com/geoip/databases"
DATABASES = {
    "GeoLite2-ASN-CSV": f"{BASE_URL}/GeoLite2-ASN-CSV/download?suffix=zip",
    "GeoLite2-City-CSV": f"{BASE_URL}/GeoLite2-City-CSV/download?suffix=zip",
    "GeoLite2-Country-CSV": f"{BASE_URL}/GeoLite2-Country-CSV/download?suffix=zip",
}

# Get license key from environment variable (set in GitHub Actions secrets)
LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY")
ACCOUNT_ID = os.getenv("MAXMIND_ACCOUNT_ID")

if not LICENSE_KEY or not ACCOUNT_ID:
    raise ValueError("Missing MaxMind Account ID or License Key. Set them as environment variables.")

# Output directory
DOWNLOAD_DIR = "maxmind_databases"
EXTRACT_DIR = os.path.join(DOWNLOAD_DIR, "extracted")

# Ensure directories exist
os.makedirs(DOWNLOAD_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)


def download_file(url, output_path):
    """Download a file with basic authentication and follow redirects."""
    print(f"Downloading {url} ...")
    response = requests.get(url, auth=(ACCOUNT_ID, LICENSE_KEY), stream=True)
    if response.status_code == 200:
        with open(output_path, "wb") as file:
            for chunk in response.iter_content(1024):
                file.write(chunk)
        print(f"Saved to {output_path}")
    else:
        print(f"Failed to download {url}. HTTP Status: {response.status_code}")


def extract_zip(file_path, extract_to):
    """Extract ZIP files to a specified directory."""
    with zipfile.ZipFile(file_path, "r") as zip_ref:
        zip_ref.extractall(extract_to)
        print(f"Extracted {file_path} to {extract_to}")


# Download and extract each database
for db_name, db_url in DATABASES.items():
    zip_path = os.path.join(DOWNLOAD_DIR, f"{db_name}.zip")
    
    # Download
    download_file(db_url, zip_path)
    
    # Extract
    extract_zip(zip_path, EXTRACT_DIR)
    
    # Remove the zip file after extraction
    os.remove(zip_path)

print(f"All databases downloaded and extracted to {EXTRACT_DIR}.")
