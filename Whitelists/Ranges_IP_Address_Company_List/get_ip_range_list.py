#work in progress 

import requests

ipinfo_token = "fixme"
#company_list = ["AS10782","AS8075","AS13445"]
domain_list = ["hpe.com"]

for domain in domain_list:
    # Get the IP range of the company
    url = "https://ipinfo.io/ranges/{}?token={}".format(domain,ipinfo_token)
    response = requests.get(url)
    data = response.json()
