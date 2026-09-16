rule TrojanDownloader_Win64_Cerbu_AH_2147974165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Cerbu.AH!MTB"
        threat_id = "2147974165"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {66 0f 6f e0 f3 0f 6f d0 66 0f da e5 66 0f 6f d8 66 0f 74 e0 66 0f fc de f3 0f 6f 02 0f 54 dc 66 0f 6f cc 0f 55 c8 0f 56 d9 0f 54 dc 0f 55 e2 0f 56 dc f3 0f 7f 1a 48 83 c2 10 48 8b c2 48 2b c7 49 3b c0 7c}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Cerbu_A_2147978304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Cerbu.A!MTB"
        threat_id = "2147978304"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {24 40 4c 89 ?? 24 48 0f 10 4c 24 30 0f 10 54 24 40 66 0f 6f 84 24 f0 00 00 00 0f 57 c1 66 0f 7f 44 24 30 0f 57 94 24 00 01 00 00 66 0f 7f 54 24 40}  //weight: 30, accuracy: Low
        $x_10_2 = {48 8d 94 24 d0 00 00 00 48 8b cf e8 ?? ?? ?? ?? 48 8d 0c 3b 4c 8d 04 36 49 8b d7 e8 ?? ?? ?? ?? 33 c0 48 8b 8c 24 ?? ?? ?? ?? 66 89 04 4f 48 8b 94 24 b0 00 00 00 4c 8d 8c 24 a0 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

