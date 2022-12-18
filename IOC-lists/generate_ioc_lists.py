#!/usr/bin/env python

#work in progress

import requests
import pathlib
import re

urls = ['https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv',
        'http://data.phishtank.com/data/online-valid.csv',
        'https://dl.red.flag.domains/red.flag.domains.txt',
        'https://dl.red.flag.domains/red.flag.domains_fr.txt',
        'https://dl.red.flag.domains/red.flag.domains_ovh.txt',
        'https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt',
        'https://malware-filter.gitlab.io/malware-filter/pup-filter-domains.txt',
        'https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt',
        'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt',
        'https://malware-filter.gitlab.io/malware-filter/pup-filter-domains.txt',
        'https://raw.githubusercontent.com/bigdargon/hostsVN/master/extensions/threat/hosts'
        'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt',
        'https://raw.githubusercontent.com/cbuijs/ut1/master/malware/domains',
        'https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt',
        'https://raw.githubusercontent.com/KitsapCreator/pihole-blocklists/master/malware-malicious.txt',
        'https://raw.githubusercontent.com/KitsapCreator/pihole-blocklists/master/scam-spam.txt',
        'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/fake.txt',
        'http://data.phishtank.com/data/online-valid.csv',
        'https://www.openphish.com/feed.txt',
        'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains/output/domains/ACTIVE/list',
        'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains/output/domains/INACTIVE/list',
        'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv'
]
excluded_domains=['twitter.com','github.com','google.com','gtly.to','pastebin.com']
excluded_lines = ["r',url,http'"]

for url in urls:
    folder_name = url.replace('https://', '').replace('http://', '').replace('.csv', '').replace('.txt', '').replace('/', '_')
    pathlib.Path(folder_name).mkdir(parents=True, exist_ok=True)
    file_name = url.split('/')[-1]
    file_path = folder_name + '/' + file_name
    
    if not pathlib.Path(file_path).exists():
        open(file_path, 'a').close()
    r = requests.get(url)
    if r.ok == False:
        print("Error downloading the file: {}\
            reason: {}\
            status code: {}".format(url,r.reason,r.status_code))
    else:
        print("OK pour url: {} - r.ok: {} - reason: {} - status code: {}".format(url,r.ok,r.reason,r.status_code))
        url_content = r.content.decode('utf-8').split('\n')
        try:
            with open(file_path,'r+') as f:
                print('aze')
                for line in url_content:
                    print('aze2')
                    if line:
                        print('aze3')
                        if line.startswith('#'):
                            print("AAA5")
                            pass
                        else:
                            print('aze4')
                            for excluded_line in excluded_lines:
                                print('aze5')
                                excluded_line_exist = re.findall(excluded_line,line)
                            if not excluded_line_exist:
                                try:
                                    print('aze6')
                                    domain_name = re.search(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}',line).group(0)
                                except Exception as e:
                                    print("domain_name definition error: {}".format(e))
                                    continue
                                print('aze6')
                                if type(domain_name) != type(None):
                                    if len(domain_name)>0:
                                        if domain_name in excluded_domains:
                                            print('aze7')
                                            pass
                                        else:
                                            print("domain_name {} is not in the exluded_domains list,will proceed to add the domain to the list".format(domain_name))
                                            new_line = domain_name + ',' + "{}".format(url) + "\n"
                                            print("saving new line:{} to file".format(new_line))
                                            line_exist=False
                                            for line in f:
                                                if new_line == line:
                                                    line_exist=True
                                                    print("line {} already exist in file".format(new_line))
                                            if line_exist == False:
                                                print("line {} does not exist in file, will be added to file".format(new_line))
                                                f.write(new_line)
                                            f.seek(0)
                                                
        except Exception as e:
            print('Error: ' + str(e))
