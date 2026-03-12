rule Trojan_Win64_Fareit_MK_2147964611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fareit.MK!MTB"
        threat_id = "2147964611"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {89 c3 42 0f b6 04 01 01 d8 44 31 c8 49 ff c8 41 89 d9 49 83 f8 07}  //weight: 15, accuracy: High
        $x_15_2 = {89 d8 42 0f b6 5c 01 08 01 c3 44 31 d3 49 ff c0 41 89 c2 49 83 f8 10}  //weight: 15, accuracy: High
        $x_20_3 = {89 c1 c1 e9 18 88 0a 89 c1 c1 e9 10 88 4a 01 88 62 02 88 42 03 89 d8 c1 e8 18 88 42 04 89 d8 c1 e8 10 88 42 05 88 7a 06 88 5a 07}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

