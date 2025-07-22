name: Update Cloudflare IP ranges

on:
  schedule:
    - cron: '12 */2 * * *'  
  workflow_dispatch:

jobs:
  fetch-Cloudflare-IP-From-Cloudflare-list:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install requests

      - name: Run Cloudflare IP range extraction script
        run: |
          cd Lists/Ranges_IP_Address_Company_List/CloudFlare
          python fetch_cloudflare_ip_ranges.py

      - name: Show resulting files
        run: ls -R Lists/Ranges_IP_Address_Company_List/CloudFlare

      - name: Commit and Push results
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          git pull --rebase
          git add Lists/Ranges_IP_Address_Company_List/CloudFlare/*
          git commit -m "Update Cloudflare IP ranges List Daily" --allow-empty
          git push
