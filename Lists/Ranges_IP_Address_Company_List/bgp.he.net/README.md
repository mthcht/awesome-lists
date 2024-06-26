# ASN and IP Range Retriever

This Python script retrieves Autonomous System Numbers (ASNs) and IP ranges associated with a given company using data from `bgp.he.net`. It can output the results in CSV or JSON format.

## Requirements

- Python 3.x
- Libraries: `requests`, `beautifulsoup4`, `pandas`

## Usage
The script can be run from the command line with the following options:

- `-name`: Specify a single company name to retrieve its IP ranges.
- `-list`: Provide a comma-separated list of company names to retrieve IP ranges for multiple companies.
- `-format`: Choose the output format (csv or json). Default is csv.

### Examples
 - Single company: `python3 get_ip_range.py -name "Microsoft" -format csv`
 - Multiple companies: `python get_ip_range.py -list "Microsoft,Google,Amazon,AS206728" -format json`

#### Output
The results are saved in the specified format with filenames based on the company name and the chosen format, e.g., Microsoft_IP_Ranges.csv.

### Logging
Debug Logs are written to get_ip_range_debug.log, which includes detailed information about the script's execution and any errors.

## Splunk 

### For Exclusions:
If Splunk is used, you can define a lookup difinition with the parameter `CIDR(dest_ip)` and use the lookup definition to exclude dest_ip in the list, example in a search SPL:

`NOT [|inputlookup microsoft_IP_Ranges | fields - metadata_*]`

You can setup a cron or a scheduled task to upload automatically updated lookups to Splunk with the script [upload_lookups_to_splunk.py](https://github.com/mthcht/lookup-editor_scripts#upload_lookups_to_splunkpy) (use lookup-editor app)

![2022-12-24 08_37_55-Windows 10 and later x64 - VMware Workstation](https://user-images.githubusercontent.com/75267080/209426409-1c3749a9-f504-4f74-b292-a9ecdebf6ed2.png)
