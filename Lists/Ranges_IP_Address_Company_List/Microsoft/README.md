# Microsoft IP Ranges Processing Script

## Overview

This script downloads and processes Microsoft IP ranges data from official Microsoft sources, converting them to standardized, Splunk-friendly CSV files. Additionally, it extracts individual Azure service tag blocks into structured subfolders with separate files for full, IPv4, and IPv6 address ranges.

## Script Operations

### 1. **Download Data**

The script fetches data from the following sources:

- **Azure Service Tags (JSON):**  
  https://www.microsoft.com/en-us/download/details.aspx?id=56519

- **Microsoft Public IPs (CSV):**  
  https://www.microsoft.com/en-us/download/details.aspx?id=53602

- **Office 365 Worldwide IPs (JSON):**  
  https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7

### 2. **Output Files**

- `ServiceTags_Public.json`
- `MSFT_PublicIPs.csv`
- `OfficeWorldWide-IPRanges.json`

### 3. **CSV Processing**

- `MSFT_PublicIPs.csv`: Renames columns to `dest_ip` and `metadata_comment`.

- `ServiceTags_Public.json` ➝ `ServiceTags_Public.csv`:  
  - IPs from `addressPrefixes` → `dest_ip`  
  - Metadata in `properties` → `metadata_*` fields

- `OfficeWorldWide-IPRanges.json` ➝ `OfficeWorldWide-IPRanges.csv`:  
  - IPs from `ips` → `dest_ip`  
  - Remaining fields → `metadata_*` fields

### 4. **Per-ServiceTag Breakdown (New)**

The script extracts and organizes each Azure Service Tag into a dedicated folder:

```
serviceTags/
  ├─ ActionGroup/
  │   ├─ serviceTag.json
  │   ├─ ips.json
  │   ├─ ipv4.json
  │   └─ ipv6.json
  ├─ AzureMonitor/
  │   ├─ ...
```

Each folder contains:

- `serviceTag.json`: Full metadata for the service tag
- `ips.json`: All IPs
- `ipv4.json`: Only IPv4 subnets
- `ipv6.json`: Only IPv6 subnets

---

## File Structure Summary

| Filename                          | Description                                       |
|----------------------------------|---------------------------------------------------|
| `ServiceTags_Public.json`        | Raw Azure Service Tags JSON                      |
| `MSFT_PublicIPs.csv`             | Microsoft IPs with normalized headers            |
| `OfficeWorldWide-IPRanges.json`  | Raw Office365 IP Ranges                          |
| `ServiceTags_Public.csv`         | Normalized CSV of Azure Service Tags             |
| `OfficeWorldWide-IPRanges.csv`   | Normalized CSV of Office365 IPs                  |
| `serviceTags/<tag_name>/...`     | Folder of structured IPs per Azure service tag   |

---

## Using Lookups with Splunk

### 1. Upload Lookup CSVs

Place the following files in `$SPLUNK_HOME/etc/apps/<your_app>/lookups/`:

- `ServiceTags_Public.csv`
- `OfficeWorldWide-IPRanges.csv`
- `MSFT_PublicIPs.csv`

### 2. Configure `transforms.conf`

```ini
[service_tags_public]
filename = ServiceTags_Public.csv

[office_worldwide_ipranges]
filename = OfficeWorldWide-IPRanges.csv

[MSFT_PublicIPs]
filename = MSFT_PublicIPs.csv
```

### 3. Configure `props.conf`

```ini
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

---

## Example Splunk Searches

### Include Events Matching Microsoft IPs

```splunk
... | lookup office_worldwide_ipranges dest_ip AS src_ip OUTPUT dest_ip AS matched_ip
| search matched_ip=*
```

Or:

```splunk
... [| inputlookup office_worldwide_ipranges | fields - "metadata_*"]
```

### Exclude Events from Microsoft IPs

```splunk
... | lookup service_tags_public dest_ip AS src_ip OUTPUT dest_ip AS matched_ip
| where isnull(matched_ip)
```

Or:

```splunk
... NOT [| inputlookup service_tags_public | fields - "metadata_*"]
```

---

## Automation

This script is used in conjunction with a GitHub Actions workflow to update and commit IP ranges daily. See `.github/workflows/update-msft-ips.yml` for scheduling.
