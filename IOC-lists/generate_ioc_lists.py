#!/usr/bin/env python

#work in progress

import requests
import pathlib
import re


urls =  {'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv': 'all',
        'http://data.phishtank.com/data/online-valid.csv': 'url',
        'https://dl.red.flag.domains/red.flag.domains.txt': 'domain',
        'https://dl.red.flag.domains/red.flag.domains_fr.txt': 'domain',
        'https://dl.red.flag.domains/red.flag.domains_ovh.txt': 'domain',
        'https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt': 'unknow',
        'https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt': 'unknow',
        'https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt': 'unknow',
        'https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt': 'unknow',
        'https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt': 'unknow',
        'https://malware-filter.gitlab.io/malware-filter/pup-filter-domains.txt': 'domain',
        'https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt': 'domain',
        'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt': 'domain',
        'https://malware-filter.gitlab.io/malware-filter/pup-filter-domains.txt': 'domain',
        'https://raw.githubusercontent.com/bigdargon/hostsVN/master/extensions/threat/hosts': 'unknow',
        'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt': 'domain',
        'https://raw.githubusercontent.com/cbuijs/ut1/master/malware/domains': 'domain',
        'https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt': 'domain',
        'https://raw.githubusercontent.com/KitsapCreator/pihole-blocklists/master/malware-malicious.txt': 'unknow',
        'https://raw.githubusercontent.com/KitsapCreator/pihole-blocklists/master/scam-spam.txt': 'unknow',
        'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/fake.txt': 'unknow',
        'https://www.openphish.com/feed.txt': 'unknow',
        'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains/output/domains/ACTIVE/list': 'domain',
        'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains/output/domains/INACTIVE/list': 'domain',
        'https://github.com/tetzispa/domains-names/tree/main/domainesq': 'domain'}


# domain type variables
excluded_domains=['twitter.com','github.com','google.com','gtly.to','pastebin.com']
excluded_lines_for_domain = ["r',url,http'"]
# url type variables

# ip type variables


#------------------Extractions------------------#
def extract_domain(my_line):
    try:
        global domain_name
        domain_name = re.search(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}',my_line).group(0)
    except Exception as e:
        print("domain_name definition error: {}".format(e))
        pass

def extract_url(get_line):
    pass
def extract_ip(get_line):
    pass

#------------------Add lines to files------------------#
def add_to_file(my_new_line):
    print("Checking line {}".format(my_new_line))
    #print("saving new line:{} to file".format(new_line))
    line_exist=False
    for line in f:
        if my_new_line == line:
            line_exist=True
            print("line {} already exist in file".format(my_new_line))
    if line_exist == False:
        print("line {} does not exist in file, it will be added to file".format(my_new_line))
        f.write(my_new_line)
    f.seek(0)

#------------------Get type functions------------------#
def get_domain(my_line):
    print(my_line)
    for excluded_line in excluded_lines_for_domain:
        excluded_line_exist = re.findall(excluded_line,my_line)
    if not excluded_line_exist:
        extract_domain(my_line)
        print(domain_name)
        if bool(domain_name) != False:
            if len(domain_name)>0:
                print('aze1')
                if not (domain_name in excluded_domains):
                    print('aze')
                    new_line = domain_name + ',' + "{}".format(url) + "\n"
                    print(new_line)
                    add_to_file(new_line)
# Extract url
def get_url(get_line):
    pass
# Extract IP address
def get_ip(get_line):
    pass

#------------------Main process------------------#
for url,filetype in  urls.items():
    folder_name = url.replace('https://', '').replace('http://', '').replace('.csv', '').replace('.txt', '').replace('/', '_')
    pathlib.Path(folder_name).mkdir(parents=True, exist_ok=True)
    file_name = url.split('/')[-1]
    file_path = folder_name + '/' + file_name
    def create_file(filepath,header):     
        if not pathlib.Path(filepath).exists():
            open(filepath, 'a').close()
            with open(filepath,'r+') as f:
                f.write(header)
    file_path_domain = file_path + '_domain_list.csv'
    domain_fields = "dest_nt_domain,metadata.source\n"
    file_path_url = file_path + '_url_list.csv'
    url_fields = "url,metadata.source\n"
    file_path_ip =  file_path + '_ip_list.csv'   
    ip_fields = "dest_ip,metadata.source\n"
    if filetype == 'all':
        create_file(file_path_domain,domain_fields)
        create_file(file_path_url,url_fields)
        create_file(file_path_ip,ip_fields)
    if filetype == 'domain':
        create_file(file_path_domain,domain_fields)
    if filetype == 'url':
        create_file(file_path_url,url_fields)
    if filetype == 'ip':
        create_file(file_path_ip,ip_fields)

    r = requests.get(url)
    if r.ok == False:
        print("Error downloading the file: {}\
            reason: {}\
            status code: {}".format(url,r.reason,r.status_code))
    else:
        print("OK for url: {} - r.ok: {} - reason: {} - status code: {}".format(url,r.ok,r.reason,r.status_code))
        url_content = r.content.decode('utf-8').split('\n')
        try:
            def openfile(filepath,get_funct):
                global f
                print(filepath)
                print(get_funct)
                with open(filepath,'r+') as f:
                    for line in url_content:
                        if line:
                            if line.startswith('#'):
                                pass
                            else:
                                if get_funct == "get_domain":
                                    get_domain(line)
                                if get_funct == "get_url":
                                    get_url(line)
                                if get_funct == "get_ip":
                                    get_ip(line)
            if filetype == 'all':
                print(filetype)
                openfile(file_path_domain,"get_domain")
                #openfile(file_path_url,"get_url")
                #openfile(file_path_ip,"get_ip")
            if filetype == 'domain':    
                openfile(file_path_domain,"get_domain")
            if filetype == 'url':
                #openfile(file_path_url,"get_url")
                pass
            if filetype == 'ip':
                #openfile(file_path_ip,"get_ip")
                pass
        except Exception as e:
            print("Error: {}".format(e))
