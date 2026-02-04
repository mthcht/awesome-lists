rule Trojan_Win64_Chrysalis_GVA_2147962398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Chrysalis.GVA!MTB"
        threat_id = "2147962398"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Chrysalis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 00 04 00 00 35 00 04 00 00 89 85 5c 37 00 00 8b 85 5c 37 00 00 48 8b 8d 60 37 00 00 8b 11 41 89 d0 41 83 c0 01 44 89 01 89 d1 88 44 0d c0 8b 85 7c 37 00 00 83 c0 04 89 85 7c 37 00 00 8b 85 78 37 00 00 83 c0 04 89 85 78 37 00 00 8b 85 7c 37 00 00 89 85 74 37 00 00 c7 85 6c 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Chrysalis_GVB_2147962399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Chrysalis.GVB!MTB"
        threat_id = "2147962399"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Chrysalis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f ba f8 0a 89 44 24 54 48 63 44 24 4c 0f b6 4c 24 54 88 8c 04 80 1c 00 00 8b 44 24 4c ff c0 89 44 24 4c 8b 44 24 50 83 c0 04 89 44 24 50 8b 44 24 44 83 c0 04 89 44 24 44 48 8d 4c 24 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

