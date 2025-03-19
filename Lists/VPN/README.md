I'm compiling lists of IP addresses for both IN (entry) and OUT (exit) connections used by popular VPN services. Gathering both types is challenging since most services only make their IN servers publicly available. If you know of any additional VPN services with IN server details—or even better, have information on OUT servers—please contribute!

Use these lists to monitor outbound network requests or analyze successful login connections in your environment.


[VPN_ALL_IP_List.csv](https://github.com/mthcht/awesome-lists/releases/download/big-files/VPN_ALL_IP_List.csv) will automatically aggregate all VPN list data from the subdirectories of this directory, the key fields are src_ip, src_ip_entry and src_ip_exit - you should merge these 3 fields into a single field for your searches.
