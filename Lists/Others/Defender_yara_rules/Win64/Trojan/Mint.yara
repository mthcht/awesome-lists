rule Trojan_Win64_Mint_SX_2147947159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mint.SX!MTB"
        threat_id = "2147947159"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b6 44 01 07 85 c0 75 43 0f b7 44 24 20 48 8b 4c 24 30 0f b6 44 01 05 88 44 24 28 0f b7 44 24 20 48 8b 4c 24 30 0f b6 44 01 04 88 44 24 29 0f b6 44 24 28 c1 e0 08 0f b6 4c 24 29 0b c1 48 8b 8c 24 80 00 00 00 66 89 41 10 eb 12}  //weight: 3, accuracy: High
        $x_2_2 = {48 8b 44 24 20 0f b6 00 89 04 24 8b 04 24 89 44 24 04 48 8b 44 24 20 48 ff c0 48 89 44 24 20 83 7c 24 04 00 74 1c 48 8b 44 24 08 48 c1 e0 05 48 03 44 24 08 48 63 0c 24 48 03 c1 48 89 44 24 08 eb be}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

