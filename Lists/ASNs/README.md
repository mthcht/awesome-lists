## Description
This project contains scripts to fetch and process data related to bad Autonomous System Numbers (ASNs) most used in phishing attacks or abused by attackers. The data is fetched from multiple sources . This folders includes scripts to automatically update the list of bad ASNs and retrieve their corresponding IP ranges.

## Scripts and Files
1. `fetch_cybercrimeinfocenter_phishing_asn_stats.py`
This script automatically fetches the latest list of bad ASNs most used in phishing attacks from www.cybercrimeinfocenter.org and saves the output in a file named `latest_bad_asn_phishing_list.csv`

- This script performs the following steps:
  - Fetches the main page that lists all the quarterly reports.
  - Parses the HTML to find the latest URL for the "bad ASN" report.
  - Fetches the data from the latest URL.
  - Extracts the table and saves it to a CSV file named latest_bad_asn_phishing_list.csv.

2. `latest_bad_asn_phishing_list.csv`
This file contains the latest top bad ASNs most used in phishing attacks, fetched from www.cybercrimeinfocenter.org. The file is updated by the `fetch_cybercrimeinfocenter_phishing_asn_stats.py` script.

3. `fetch_IP_ranges_of_bad_ASN.py`
This script fetches the updated IP ranges of each bad ASN listed in the consolidated list of ASNs and saves the IP ranges of each ASN in the current folder.
Reads the list of ASNs from:
- latest_bad_asn_phishing_list.csv (Cybercrime Info Center).
- bad_asn_static_list.csv (my static List of ASNs).
- evild3ad-ASN-BlackList.csv (VPN ASNs from https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/main/Blacklists/ASN-Blacklist.csv)
- spamhaus_asn_list.csv (Spamhaus ASN Drop List).

- This script performs the following steps:
  - Fetches the ASN lists from the sources above.
  - Combines all ASNs into a single deduplicated list.
  - Constructs a command to execute the [get_ip_range.py](https://github.com/mthcht/awesome-lists/blob/main/Lists/Ranges_IP_Address_Company_List/bgp.he.net/get_ip_range.py) script with the AS numbers as arguments.
  - Executes the command to fetch the IP ranges of the listed ASNs and saves the results in the current folder.


## Details

### ALL IN ONE!

All the BAD ASNs ip ranges in one file: [_ALL_BAD_ASN_IP_Ranges_List.csv](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/_ALL_BAD_ASN_IP_Ranges_List.csv)

### VPN

#### Nordvpn 

<details>
  
- **[AS141039](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS141039_IP_Ranges.csv)**
- **[AS147049](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS147049_IP_Ranges.csv)**
- **[AS207137](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS207137_IP_Ranges.csv)**
- [AS6167](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS6167_IP_Ranges.csv)
- [AS7018](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS7018_IP_Ranges.csv)
- [AS8447](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS8447_IP_Ranges.csv)
- [AS9009](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS9009_IP_Ranges.csv)
- [AS10174](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS10174_IP_Ranges.csv)
- [AS11427](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS11427_IP_Ranges.csv)
- [AS12876](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS12876_IP_Ranges.csv)
- [AS14244](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS14244_IP_Ranges.csv)
- [AS20278](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS20278_IP_Ranges.csv)
- [AS20473](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS20473_IP_Ranges.csv)
- [AS24940](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS24940_IP_Ranges.csv)
- [AS25369](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS25369_IP_Ranges.csv)
- [AS33182](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS33182_IP_Ranges.csv)
- [AS33876](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS33876_IP_Ranges.csv)
- [AS36352](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS36352_IP_Ranges.csv)
- [AS39486](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS39486_IP_Ranges.csv)
- [AS40676](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS40676_IP_Ranges.csv)
- [AS41564](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS41564_IP_Ranges.csv)
- [AS41704](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS41704_IP_Ranges.csv)
- [AS42831](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS42831_IP_Ranges.csv)
- [AS43289](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS43289_IP_Ranges.csv)
- [AS43317](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS43317_IP_Ranges.csv)
- [AS46805](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS46805_IP_Ranges.csv)
- [AS47943](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS47943_IP_Ranges.csv)
- [AS49453](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS49453_IP_Ranges.csv)
- [AS49770](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS49770_IP_Ranges.csv)
- [AS49981](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS49981_IP_Ranges.csv)
- [AS50340](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS50340_IP_Ranges.csv)
- [AS51430](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS51430_IP_Ranges.csv)
- [AS51747](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS51747_IP_Ranges.csv)
- [AS57172](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS57172_IP_Ranges.csv)
- [AS58325](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS58325_IP_Ranges.csv)
- [AS60068](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS60068_IP_Ranges.csv)
- [AS60304](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS60304_IP_Ranges.csv)
- [AS61493](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS61493_IP_Ranges.csv)
- [AS62240](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS62240_IP_Ranges.csv)
- [AS63119](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS63119_IP_Ranges.csv)
- [AS64200](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS64200_IP_Ranges.csv)
- [AS64245](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS64245_IP_Ranges.csv)
- [AS131199](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS131199_IP_Ranges.csv)
- [AS136557](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS136557_IP_Ranges.csv)
- [AS136787](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS136787_IP_Ranges.csv)
- [AS137409](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS137409_IP_Ranges.csv)
- [AS198890](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS198890_IP_Ranges.csv)
- [AS199524](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS199524_IP_Ranges.csv)
- [AS200698](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS200698_IP_Ranges.csv)
- [AS205119](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS205119_IP_Ranges.csv)
- [AS207990](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS207990_IP_Ranges.csv)
- [AS212238](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS212238_IP_Ranges.csv)
- [AS262287](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS262287_IP_Ranges.csv)
- [AS263702](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS263702_IP_Ranges.csv)
- [AS396356](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS396356_IP_Ranges.csv)

</details>

#### PureVPN

<details>
  
- [AS174](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS174_IP_Ranges.csv)
- [AS834](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS834_IP_Ranges.csv)
- [AS1257](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS1257_IP_Ranges.csv)
- [AS1299](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS1299_IP_Ranges.csv)
- [AS1421](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS1421_IP_Ranges.csv)
- [AS2914](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS2914_IP_Ranges.csv)
- [AS3223](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS3223_IP_Ranges.csv)
- [AS3257](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS3257_IP_Ranges.csv)
- [AS3356](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS3356_IP_Ranges.csv)
- [AS3491](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS3491_IP_Ranges.csv)
- [AS3549](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS3549_IP_Ranges.csv)
- [AS3741](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS3741_IP_Ranges.csv)
- [AS4637](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS4637_IP_Ranges.csv)
- [AS6424](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS6424_IP_Ranges.csv)
- [AS6762](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS6762_IP_Ranges.csv)
- [AS6939](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS6939_IP_Ranges.csv)
- [AS7040](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS7040_IP_Ranges.csv)
- [AS7195](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS7195_IP_Ranges.csv)
- [AS8285](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS8285_IP_Ranges.csv)
- [AS8447](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS8447_IP_Ranges.csv)
- [AS8452](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS8452_IP_Ranges.csv)
- [AS8529](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS8529_IP_Ranges.csv)
- [AS8717](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS8717_IP_Ranges.csv)
- [AS9002](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS9002_IP_Ranges.csv)
- [AS9009](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS9009_IP_Ranges.csv)
- [AS9121](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS9121_IP_Ranges.csv)
- [AS12179](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS12179_IP_Ranges.csv)
- [AS12182](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS12182_IP_Ranges.csv)
- [AS13194](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS13194_IP_Ranges.csv)
- [AS13213](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS13213_IP_Ranges.csv)
- [AS14061](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS14061_IP_Ranges.csv)
- [AS15169](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS15169_IP_Ranges.csv)
- [AS15830](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS15830_IP_Ranges.csv)
- [AS16276](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS16276_IP_Ranges.csv)
- [AS16302](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS16302_IP_Ranges.csv)
- [AS16724](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS16724_IP_Ranges.csv)
- [AS18779](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS18779_IP_Ranges.csv)
- [AS20473](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS20473_IP_Ranges.csv)
- [AS20860](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS20860_IP_Ranges.csv)
- [AS21859](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS21859_IP_Ranges.csv)
- [AS23033](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS23033_IP_Ranges.csv)
- [AS28886](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS28886_IP_Ranges.csv)
- [AS29076](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS29076_IP_Ranges.csv)
- [AS32489](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS32489_IP_Ranges.csv)
- [AS35758](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS35758_IP_Ranges.csv)
- [AS36231](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS36231_IP_Ranges.csv)
- [AS36351](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS36351_IP_Ranges.csv)
- [AS36352](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS36352_IP_Ranges.csv)
- [AS37468](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS37468_IP_Ranges.csv)
- [AS37684](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS37684_IP_Ranges.csv)
- [AS38001](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS38001_IP_Ranges.csv)
- [AS38182](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS38182_IP_Ranges.csv)
- [AS39324](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS39324_IP_Ranges.csv)
- [AS40676](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS40676_IP_Ranges.csv)
- [AS42831](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS42831_IP_Ranges.csv)
- [AS44477](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS44477_IP_Ranges.csv)
- [AS45671](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS45671_IP_Ranges.csv)
- [AS45899](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS45899_IP_Ranges.csv)
- [AS45996](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS45996_IP_Ranges.csv)
- [AS46475](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS46475_IP_Ranges.csv)
- [AS50613](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS50613_IP_Ranges.csv)
- [AS51430](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS51430_IP_Ranges.csv)
- [AS51765](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS51765_IP_Ranges.csv)
- [AS52423](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS52423_IP_Ranges.csv)
- [AS53356](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS53356_IP_Ranges.csv)
- [AS54527](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS54527_IP_Ranges.csv)
- [AS55286](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS55286_IP_Ranges.csv)
- [AS56153](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS56153_IP_Ranges.csv)
- [AS56655](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS56655_IP_Ranges.csv)
- [AS56910](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS56910_IP_Ranges.csv)
- [AS57814](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS57814_IP_Ranges.csv)
- [AS58955](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS58955_IP_Ranges.csv)
- [AS60117](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS60117_IP_Ranges.csv)
- [AS61098](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS61098_IP_Ranges.csv)
- [AS62240](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS62240_IP_Ranges.csv)
- [AS63018](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS63018_IP_Ranges.csv)
- [AS63956](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS63956_IP_Ranges.csv)
- [AS132372](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS132372_IP_Ranges.csv)
- [AS133159](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS133159_IP_Ranges.csv)
- [AS133480](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS133480_IP_Ranges.csv)
- [AS134451](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS134451_IP_Ranges.csv)
- [AS137409](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS137409_IP_Ranges.csv)
- [AS138915](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS138915_IP_Ranges.csv)
- [AS151106](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS151106_IP_Ranges.csv)
- [AS197071](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS197071_IP_Ranges.csv)
- [AS197328](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS197328_IP_Ranges.csv)
- [AS197706](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS197706_IP_Ranges.csv)
- [AS199524](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS199524_IP_Ranges.csv)
- [AS202053](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS202053_IP_Ranges.csv)
- [AS202656](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS202656_IP_Ranges.csv)
- [AS203020](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS203020_IP_Ranges.csv)
- [AS206264](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS206264_IP_Ranges.csv)
- [AS209378](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS209378_IP_Ranges.csv)
- [AS210756](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS210756_IP_Ranges.csv)
- [AS212238](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS212238_IP_Ranges.csv)
- [AS262287](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS262287_IP_Ranges.csv)
- [AS263812](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS263812_IP_Ranges.csv)
- [AS270172](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS270172_IP_Ranges.csv)
- [AS327813](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS327813_IP_Ranges.csv)
- [AS394256](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS394256_IP_Ranges.csv)
- [AS396356](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS396356_IP_Ranges.csv)
- [AS396362](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS396362_IP_Ranges.csv)
- [AS396982](https://github.com/mthcht/awesome-lists/blob/main/Lists/ASNs/AS396982_IP_Ranges.csv)
  
</details>


fixme..
