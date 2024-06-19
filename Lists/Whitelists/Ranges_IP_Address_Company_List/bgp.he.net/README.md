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
 - Multiple companies: `python get_ip_range.py -list "Microsoft,Google,Amazon" -format json`

#### Output
The results are saved in the specified format with filenames based on the company name and the chosen format, e.g., Microsoft_IP_Ranges.csv.

### Logging
Debug Logs are written to get_ip_range_debug.log, which includes detailed information about the script's execution and any errors.
