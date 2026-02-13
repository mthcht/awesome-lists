rule Trojan_Win64_Zapchast_LM_2147962365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zapchast.LM!MTB"
        threat_id = "2147962365"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b 0e 48 ff c7 32 44 2f ff 88 44 0f ff}  //weight: 20, accuracy: High
        $x_10_2 = {8b cf c1 e9 05 03 4d 0c 8b c7 c1 e0 04 03 45 08 33 c8 41 8d 04 3c 33 c8 2b f1 8b 84 24 88 00 00 00 44 89 b4 24 88 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zapchast_ARR_2147963020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zapchast.ARR!MTB"
        threat_id = "2147963020"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_14_1 = {48 89 c2 83 e2 ?? 0f b6 54 14 5c 41 32 14 04 88 14 03 48 83 c0 ?? 48 39 c6 75}  //weight: 14, accuracy: Low
        $x_6_2 = {31 d2 4c 8d 05 ?? ?? ?? ?? 48 89 d9 66 89 50}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

