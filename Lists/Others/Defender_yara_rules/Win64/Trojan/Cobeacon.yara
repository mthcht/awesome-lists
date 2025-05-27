rule Trojan_Win64_Cobeacon_ARA_2147925943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobeacon.ARA!MTB"
        threat_id = "2147925943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 48 8b c1 49 f7 f1 42 0f b6 04 12 42 30 04 01 48 ff c1 48 3b cf 72 e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobeacon_ARAZ_2147929328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobeacon.ARAZ!MTB"
        threat_id = "2147929328"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c0 44 0f b6 44 05 10 45 30 43 ff 83 c6 ff 75 c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cobeacon_MBWJ_2147942275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cobeacon.MBWJ!MTB"
        threat_id = "2147942275"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2e 72 64 61 74 61 00 00 44 4a 01 00 00 c0 03 00 00 4c 01 00 00 b0 03 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 60 04 00 00 00 10 05 00 00 02 00 00 00 fc 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
        $x_1_2 = {65 78 74 00 00 00 37 aa 03 00 00 10 00 00 00 ac 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

