Trying to retrieve all domains associated with this list of sinkholed name servers using zone files from **https://github.com/mthcht/awesome-lists/blob/main/Lists/Domains/ICANN/Get_all_the_domains_with_NS.md**


- [ ] automate with list generation with a github actions - todo: https://github.com/mthcht/awesome-lists/issues/26
- [x] Site sinkholed.github.io

## Github Action

fixme

## sinkholed.github.io

With **[sinkholed.github.io](https://sinkholed.github.io)**, you can automate the retrieval of **sinkholed domains** by applying specific filters based on **Name Server (NS) names** and/or **Top-Level Domains (TLDs)**

**Available Parameters in the url**:
- **`tld=`** → Filter by **Top-Level Domain (TLD)** (e.g., `.com`, `.net`, `.org`)
- **`ns=`** → Filter by a specific **Name Server (NS)**
- **`format=`** → Choose the output format: **`csv`** or **`json`**

**Example Usage**:
- Retrieve all `.net` domains associated with a specific sinkhole Name Server in JSON format: `curl -s https://sinkholed.github.io?tld=net&ns=conficker-sinkhole.com&format=json`
- Retrieve all `.com` sinkholed domains and get the output in CSV format: `https://sinkholed.github.io?tld=com&format=csv`
- Fetch only the domains linked to `ns1.fbi.seized.gov` (any TLD) in JSON format: `https://sinkholed.github.io?ns=ns1.fbi.seized.gov&format=json`

Allows the automated retrieval of sinkholed domain data based on your specific needs with a script using a headless browser!
