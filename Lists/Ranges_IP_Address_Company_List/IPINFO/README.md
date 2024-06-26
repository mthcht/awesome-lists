# IPINFO Script (not working for free account since 2024)

Request the site https://ipinfo.io/ to update regularly some companies range IP addresses into a csv file.
This can be use for detection rule exclusions (Data exfiltration for example)

Looks like this:

![image](https://user-images.githubusercontent.com/75267080/209302294-0bc14014-e5b2-4378-856a-13a90d304a9b.png)

## Splunk 

If Splunk is used, you can define a lookup difinition with the parameter `CIDR(dest_ip)` and use the lookup definition to exclude dest_ip in the list, example in a search SPL:

`NOT [|inputlookup webex.com_IP_Range_WL | fields - metadata.*]`

You can setup a cron or a scheduled task to upload automatically updated lookups to Splunk with the script [upload_lookups_to_splunk.py](https://github.com/mthcht/lookup-editor_scripts#upload_lookups_to_splunkpy) (use lookup-editor app)

![2022-12-24 08_37_55-Windows 10 and later x64 - VMware Workstation](https://user-images.githubusercontent.com/75267080/209426409-1c3749a9-f504-4f74-b292-a9ecdebf6ed2.png)
