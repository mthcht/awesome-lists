rule Backdoor_Linux_Gyfgyt_BR_2147818912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gyfgyt.BR!MTB"
        threat_id = "2147818912"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gyfgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 50 3d 20 10 02 39 29 [0-4] 55 40 10 3a 7d ?? 4a 14 91 69 00 00 3d 20 10 02 39 29 [0-4] 55 40 10 3a 7d ?? 4a 14 80 09 00 00 7c 03 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gyfgyt_BO_2147819613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gyfgyt.BO!MTB"
        threat_id = "2147819613"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gyfgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "udp_flood" ascii //weight: 1
        $x_1_2 = "std_flood" ascii //weight: 1
        $x_1_3 = "hex_flood" ascii //weight: 1
        $x_1_4 = "processCmd" ascii //weight: 1
        $x_1_5 = "myfriendwhosnameisnoodlesisafegget" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Gyfgyt_BS_2147829267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gyfgyt.BS!MTB"
        threat_id = "2147829267"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gyfgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 62 10 21 af c2 00 0c 8f 82 80 18 [0-5] 8c 43 24 b8 8f c2 00 0c [0-5] 00 43 10 2b 10 40 00 0d [0-5] 8f c2 00 0c [0-5] 24 42 00 01 af c2 00 0c 8f 82 80 18 [0-5] 8c 42 24 b8 [0-5] 24 43 00 01 8f 82 80 18 [0-5] ac 43 24 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gyfgyt_BT_2147829268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gyfgyt.BT!MTB"
        threat_id = "2147829268"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gyfgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c0 b5 45 8c 08 00 c3 8f 0c 00 c2 8f [0-5] 23 20 62 00 18 80 82 8f 80 18 05 00 30 c4 42 24 21 10 62 00 00 00 44 ac 18 80 82 8f 80 18 05 00 30 c4 42 24 21 10 62 00 00 00 42 8c 21 e8 c0 03 20 00 be 8f 28 00 bd 27 08 00 e0 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Gyfgyt_BV_2147829269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gyfgyt.BV!MTB"
        threat_id = "2147829269"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gyfgyt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 00 19 00 00 38 12 00 00 30 10 00 a6 28 21 00 a0 30 21 8f 82 80 18 [0-5] 8c 42 1b 5c [0-5] 00 40 28 21 00 00 20 21 00 e5 18 21 00 67 40 2b 00 c4 10 21 01 02 20 21 00 80 10 21 af c3 00 1c af c2 00 18 8f c4 00 18 [0-5] 00 04 18 02 00 00 10 21 8f 82 80 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

