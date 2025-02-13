rule TrojanDownloader_Win32_Satacom_BB_2147823846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Satacom.BB!MTB"
        threat_id = "2147823846"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c2 8b 4d 08 8b 11 03 d0 03 55 10 8b 45 0c 8b 08 2b ca 8b 55 0c 89 0a 8b 45 08 8b 4d 0c 8b 11 89 10 83 7d ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Satacom_ARA_2147830748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Satacom.ARA!MTB"
        threat_id = "2147830748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 04 39 88 04 3b 47 3b 7d 18 72 cd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Satacom_ARA_2147830748_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Satacom.ARA!MTB"
        threat_id = "2147830748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe c2 0f b6 d2 8b 4c ?? ?? 8d 04 0b 0f b6 d8 8b 44 ?? ?? 89 44 ?? ?? 89 4c ?? ?? 02 c8 0f b6 c1 8b 4d f8 8a 44 ?? ?? 30 04 ?? ?? 3b ?? fc 7c d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Satacom_ARA_2147830748_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Satacom.ARA!MTB"
        threat_id = "2147830748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 8b 4d dc 03 45 c8 33 d2 23 45 e0 d3 e0 b9 08 00 00 00 8a 55 eb 2b 4d dc d3 fa 03 c2 c1 e0 08 8d 04 40 03 c0 03 45 f0 05 6c 0e 00 00 83 fb 07 7c 34 8b d7 2b d6 89 55 a4 8b 4d a4 3b 4d bc 72 06 8b 55 bc 01 55 a4 8b 4d c0 8b 55 a4 8a 0c 11 88 4d ab 8d 95 ?? ?? ?? ?? 8a 4d ab e8 ?? ?? ?? ?? 88 45 eb eb 0e 8d 95 ?? ?? ?? ?? e8 ?? ?? ?? ?? 88 45 eb 8b 45 98 8a 4d eb 88 08 ff 45 ec ff 45 98 8b 45 c4 3b 45 bc 73 03 ff 45 c4 8b 55 c0 8a 4d eb 88 0c 3a 47 3b 7d bc 75 02}  //weight: 1, accuracy: Low
        $x_1_2 = "Cheyenne1\"0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Satacom_ASG_2147889416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Satacom.ASG!MTB"
        threat_id = "2147889416"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sBxr2yT9IOU2cT4g9nFHZL9UBPs7" wide //weight: 1
        $x_1_2 = "YW6WmF4AJBM5Y5hejQrG4umQaH4t" wide //weight: 1
        $x_1_3 = "rgodoa6XVlRnLh1ndb17jq3tNS31" wide //weight: 1
        $x_1_4 = "PUnXCjumfPKpp4n95LX28s9IxMP" wide //weight: 1
        $x_1_5 = "sbzsyhuioJK2Aa7KmibfNl5NaYJ" wide //weight: 1
        $x_1_6 = "sjnjsSkKwc11uW2acFGNQjjm4Z9b34" wide //weight: 1
        $x_1_7 = "s8uEZfD3JiN2gtT5nGGTZ8NMzQ5" wide //weight: 1
        $x_1_8 = "sN1q679a2n3ihkpkGACLTsZUBsEPbj" wide //weight: 1
        $x_1_9 = "3FjUvnWSMJWRWla95SDR2k32Wl5A" wide //weight: 1
        $x_1_10 = "5ldN1L3n62bp8D3Gyv6OKDrTde" wide //weight: 1
        $x_1_11 = "4NogK7w236GywADRPglS59Z5NiQ46" wide //weight: 1
        $x_1_12 = "HPlHkKMP48dOF1qydBEhS8KShgv" wide //weight: 1
        $x_1_13 = "jnjsSkKwc11uW2acFGNQjjm4Z9b34" wide //weight: 1
        $x_1_14 = "8uEZfD3JiN2gtT5nGGTZ8NMzQ5" wide //weight: 1
        $x_1_15 = "C84eUXxL39jHhJRLz4RWW855S6" wide //weight: 1
        $x_1_16 = "xVjmbeNt54ZO9DgQLe3EqavU3Vl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Satacom_A_2147896074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Satacom.A!MTB"
        threat_id = "2147896074"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 04 52 2b c8 8a 44 0d f0 8b 4d ec 32 04 3b 88 04 39 47 3b 7d 18 72 c4}  //weight: 10, accuracy: High
        $x_3_2 = "ollydbg.exe" ascii //weight: 3
        $x_3_3 = "URLDownloadToFileA" ascii //weight: 3
        $x_3_4 = "}id=28" ascii //weight: 3
        $x_3_5 = "GetTempPathA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Satacom_FV_2147896104_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Satacom.FV!MTB"
        threat_id = "2147896104"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 e4 8b 08 8b 45 e8 8b 10 8b 45 e8 8b 00 c1 e0 06 89 c3 8b 45 e8 8b 00 c1 e8 08 31 d8 8d 1c 02 8b 45 f0 ba 00 00 00 00 f7 75 dc 89 d0 8d 14 85 00 00 00 00 8b 45 0c 01 d0 8b 00}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

