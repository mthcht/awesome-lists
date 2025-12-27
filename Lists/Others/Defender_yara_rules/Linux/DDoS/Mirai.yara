rule DDoS_Linux_Mirai_PA_2147740683_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Mirai.PA!MTB"
        threat_id = "2147740683"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mirai" ascii //weight: 2
        $x_2_2 = "udpflood" ascii //weight: 2
        $x_2_3 = "tcpflood" ascii //weight: 2
        $x_2_4 = "udpfl00d" ascii //weight: 2
        $x_2_5 = "tcpfl00d" ascii //weight: 2
        $x_1_6 = "vseattack" ascii //weight: 1
        $x_1_7 = "killerstorm" ascii //weight: 1
        $x_1_8 = "KHserverHACKER" ascii //weight: 1
        $x_1_9 = "huaweiscanner_scanner_kill" ascii //weight: 1
        $n_10_10 = "com.bitdefender" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Mirai_YB_2147741875_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Mirai.YB!MTB"
        threat_id = "2147741875"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {47 45 54 20 2f 6c 6f 67 69 6e 2e 63 67 69 3f 63 6c 69 3d [0-16] 77 67 65 74 25 32 30 68 74 74 70 [0-2] 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e}  //weight: 5, accuracy: Low
        $x_5_2 = {24 28 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 [0-3] 2e [0-3] 2e [0-3] 2e}  //weight: 5, accuracy: Low
        $x_1_3 = "User-Agent: SEFA" ascii //weight: 1
        $x_1_4 = "POST /GponForm/diag_Form?images/" ascii //weight: 1
        $x_1_5 = "POST /picdesc.xml" ascii //weight: 1
        $x_1_6 = "POST /wanipcn.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Mirai_YC_2147742140_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Mirai.YC!MTB"
        threat_id = "2147742140"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 67 65 74 20 68 74 74 70 [0-2] 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f [0-96] 3b 20 63 68 6d 6f 64 20 37 37 37 20 2a 3b 20 2e 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "[antihoney] failed stage 1 honeypot detected!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Linux_Mirai_PB_2147745248_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Mirai.PB!MTB"
        threat_id = "2147745248"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[http flood]" ascii //weight: 1
        $x_1_2 = "HellInSide" ascii //weight: 1
        $x_1_3 = "[killer-kill-by-name]" ascii //weight: 1
        $x_1_4 = "attack_method_udpgeneric" ascii //weight: 1
        $x_1_5 = "attack_kill_all" ascii //weight: 1
        $x_1_6 = "killdirectories" ascii //weight: 1
        $x_1_7 = "tearing down connection to cnc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DDoS_Linux_Mirai_J_2147814697_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Mirai.J!xp"
        threat_id = "2147814697"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/usr/sbin/dropbear" ascii //weight: 2
        $x_1_2 = "suicide" ascii //weight: 1
        $x_1_3 = "t1nop4qzb35uac2yvr0xws" ascii //weight: 1
        $x_1_4 = "31.202.128.80" ascii //weight: 1
        $x_1_5 = "Usage: $0 {start|stop|restart}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Mirai_F_2147818700_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Mirai.F"
        threat_id = "2147818700"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "botnet" ascii //weight: 4
        $x_1_2 = "udirkgj(bsembhu(ita" ascii //weight: 1
        $x_1_3 = "23(752(443(46" ascii //weight: 1
        $x_1_4 = "45(432(473(764" ascii //weight: 1
        $x_1_5 = "91.198.220.108" ascii //weight: 1
        $x_1_6 = "23.254.215.102" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_Mirai_KA_2147850673_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Mirai.KA!MTB"
        threat_id = "2147850673"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 00 1c 3c ?? ?? 9c 27 21 e0 99 03 e0 ff bd 27 1c 00 bf af 18 00 b0 af 10 00 bc af 52 10 02 24 0c 00 00 00 ?? ?? 99 8f 06 00 e0 10 21 80 40 00 09 f8 20 03 00 00 00 00 10 00 bc 8f 00 00 50 ac ff ff 02 24 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27}  //weight: 2, accuracy: Low
        $x_1_2 = "main_instance_kill" ascii //weight: 1
        $x_1_3 = "attack_method_udpflood" ascii //weight: 1
        $x_1_4 = "attack_method_tcpflood" ascii //weight: 1
        $x_1_5 = "attack_free" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

