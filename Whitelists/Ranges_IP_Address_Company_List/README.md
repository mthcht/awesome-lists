Request the  https://ipinfo.io/ to update regularly some companies range IP addresses into a csv file.
This can be use for detection rule exclusions (Data exfiltration for example)

Looks like this:

![image](https://user-images.githubusercontent.com/75267080/209302294-0bc14014-e5b2-4378-856a-13a90d304a9b.png)

If Splunk is used, you can defined a lookup difinition with the parameter `CIDR(dest_ip)` and use the lookup definition to exclude dest_ip in the list, example in a search SPL:

`NOT [|inputlookup webex.com_IP_Range_WL | fields - metadata.*]`
