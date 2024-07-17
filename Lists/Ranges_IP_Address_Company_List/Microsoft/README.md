## Overview

This script downloads and processes Microsoft IP ranges data from specified URLs, converting the data to a standardized CSV format with specific headers (splunk friendly). The script is designed to handle two specific JSON structures to convert: `ServiceTags_Public.json` and `OfficeWorldWide-IPRanges.json`.

## Script Operations

1. **Download Data:**
   - The script fetches data from the following URLs:
     - Azure Public IP ranges: `https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519`
     - Microsoft Public IP ranges: `https://www.microsoft.com/en-us/download/confirmation.aspx?id=53602`
     - Office 365 Worldwide IP ranges: `https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7`

2. **Save Downloaded Data:**
   - The script saves the downloaded JSON and CSV data into the current working directory with the following filenames:
     - `ServiceTags_Public.json`
     - `MSFT_PublicIPs.csv`
     - `OfficeWorldWide-IPRanges.json`

3. **Process CSV Data:**
   - The Microsoft Public IP CSV file is processed to rename its headers to `dest_ip` and `metadata_comment`.
   
4. **Convert JSON to CSV:**
   - The `ServiceTags_Public.json` file is converted to `ServiceTags_Public.csv` with the following format:
     - `dest_ip` column contains IP ranges from `properties.addressPrefixes`.
     - Other fields in `properties` are prefixed with `metadata_`.
   - The `OfficeWorldWide-IPRanges.json` file is converted to `OfficeWorldWide-IPRanges.csv` with the following format:
     - `dest_ip` column contains IP ranges from `ips`.
     - Other fields in the entry are prefixed with `metadata_`.

## File Structure

- `ServiceTags_Public.json`: JSON file containing Azure service tag IP ranges.
- `MSFT_PublicIPs.csv`: CSV file containing Microsoft public IP ranges with headers renamed.
- `OfficeWorldWide-IPRanges.json`: JSON file containing Office 365 worldwide IP ranges.
- `ServiceTags_Public.csv`: Converted CSV file from `ServiceTags_Public.json`.
- `OfficeWorldWide-IPRanges.csv`: Converted CSV file from `OfficeWorldWide-IPRanges.json`.


## Using Lookups with Splunk

### Step 1: Configure Lookup Table Files

1. **Upload the CSV files to Splunk's `lookup` directory:**
   - `ServiceTags_Public.csv`
   - `OfficeWorldWide-IPRanges.csv`
   - `MSFT_PublicIPs.csv`

   Typically, this directory is located at `$SPLUNK_HOME/etc/apps/<your_app>/lookups/`.

2. **Create the lookup table files configuration:**

   Edit or create the `transforms.conf` file in `$SPLUNK_HOME/etc/apps/<your_app>/local/` and add the following entries:

   ```
   [service_tags_public]
   filename = ServiceTags_Public.csv

   [office_worldwide_ipranges]
   filename = OfficeWorldWide-IPRanges.csv
   
   [MSFT_PublicIPs]
   filename = MSFT_PublicIPs.csv
   ```

### Step 2: Configure Lookup Definitions

1. **Create the lookup definitions configuration:**

   Edit or create the `props.conf` file in `$SPLUNK_HOME/etc/apps/<your_app>/local/` and add the following entries to specify the CIDR(`dest_ip`) configuration for the lookups:
   
   ```
   [lookup_service_tags_public]
   external_type = cidr
   external_matcher = dest_ip
   lookup_table = service_tags_public

   [lookup_office_worldwide_ipranges]
   external_type = cidr
   external_matcher = dest_ip
   lookup_table = office_worldwide_ipranges
   
   [MSFT_PublicIPs]
   external_type = cidr
   external_matcher = dest_ip
   lookup_table = MSFT_PublicIPs
   ```

### Step 3: Using Lookups in Searches (examples)

You can use these lookups in your searches to include or exclude IP ranges from Microsoft in your searches. Here are examples of how to do this:

#### Including IP Ranges

To include events where the source IP address is in the IP ranges of the lookup office_worldwide_ipranges:

```sql
.... my search query ...
| lookup office_worldwide_ipranges dest_ip AS src_ip OUTPUT dest_ip AS matched_ip
| search matched_ip=*
```

or with inputlookup, this time include events where the destination IP address is in the IP ranges of the lookup office_worldwide_ipranges 
```sql
.... my search query ... [|inputlookup office_worldwide_ipranges | fields - "metadata_*"]
```


#### Excluding IP Ranges

To exclude events where the source IP address is in the IP ranges of the lookup service_tags_public:

```sql
.... my search query ...
| lookup service_tags_public dest_ip AS src_ip OUTPUT dest_ip AS matched_ip
| where isnull(matched_ip)
```

or with inputlookup, this time exclude events where the destination IP address is in the IP ranges of the lookup service_tags_public 
```sql
.... my search query ... NOT [|inputlookup service_tags_public | fields - "metadata_*"]
```

