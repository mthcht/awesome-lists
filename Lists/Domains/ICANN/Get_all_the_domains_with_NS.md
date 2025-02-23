## ICANN (free)
(but no distribution allowed)

- register on https://czds.icann.org/
- request access to all the zone files of every TLDs (1136 TLDs at the moment)
- wait for approval, once the zones are available to download > use https://github.com/mthcht/czds-api-client-python to download all the zones and extract them
- execute `python3 download.py` (results are in /zones by default)


If you want to find sinkholed domains, search for these NS used for sinkhole domains https://github.com/mthcht/awesome-lists/blob/main/Lists/Others/sinkhole_ns_list.csv with [this simple script](https://github.com/mthcht/awesome-lists/Lists/Domains/sinkholed_servers/search_for_sinkholed_servers.py)
