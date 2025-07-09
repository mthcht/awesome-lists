#!/usr/bin/env python3
import os
import logging
import requests

# === CONFIG ===
URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SAVE_PATH = os.path.join(SCRIPT_DIR, "aws_ip_ranges.json")

# === LOGGING ===
logging.basicConfig(
    filename=os.path.join(SCRIPT_DIR, 'aws_ip_ranges_update.log'),
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def update_ranges():
    try:
        response = requests.get(URL, timeout=15)
        response.raise_for_status()
        with open(SAVE_PATH, 'w') as f:
            f.write(response.text)
        logging.info("✅ AWS IP ranges updated successfully.")
    except Exception as e:
        logging.error(f"❌ Failed to update AWS IP ranges: {e}")

if __name__ == "__main__":
    update_ranges()
