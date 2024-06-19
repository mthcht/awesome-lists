#!/usr/bin/env python

# Generate csv lookup files in the same directory containing updated IP ranges of the company declared in domain_list variable

import requests
import csv
import time

# get your token on ipinfo.io
ipinfo_token = "FIXME"
domain_list = ["hpe.com","webex.com"]

for domain in domain_list:
    print(domain)
    # Get the IP range of the company
    url = "https://ipinfo.io/ranges/{}?token={}".format(domain,ipinfo_token)
    response = requests.get(url)
    data = response.json()
    epoch_time = int(time.time())
    filepath = "./{}_IP_Range_WL.csv".format(domain)
    # open a file for writing
    csvfile = open(filepath, 'w', newline='\n')
    # create the csv writer object
    writer = csv.writer(csvfile)
    # write headers
    writer.writerow(["dest_ip","metadata.company","metadata.date"])
    # write data
    for range in data['ranges']:
        writer.writerow([range, data['domain'],epoch_time])
    # close the file
    csvfile.close()
    
