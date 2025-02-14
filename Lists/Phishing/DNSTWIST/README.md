## Description
`get_dnstwist.py` is a Python script that automates the process of running the `dnstwist` tool on a list of domains. It generates potential phishing domain variations, parses the output, and writes the results to CSV files for further analysis.

Example domain lists are generated here automatically every day using GitHub Actions.

## Prerequisites
- Python 3.x
- `dnstwist` installed (install via `pip install dnstwist`)

## Usage

### With domain arguments
```bash
python get_dnstwist.py domain1.com domain2.com
```

### With a file containing domains
Create domains.txt with one domain per line, then run:

```bash
python get_dnstwist.py domains_list.txt
```

### Splunk
Upload a lookup of your domain in Splunk to detect outgoing communication to a similar domains (potential phishing)
