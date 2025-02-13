rule TrojanDownloader_Win32_Wauchos_SIB_2147788244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wauchos.SIB!MTB"
        threat_id = "2147788244"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wauchos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 8b 75 08 ac 84 c0 74 ?? 0c ?? 30 c2 c1 c2 ?? eb ?? 89 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 5d 08 8b 43 3c 8d 44 18 18 8d 40 60 8b 00 85 c0 74 ?? 01 d8 89 45 ?? 8b 70 20 01 de 8b 48 18 85 c9 ad 01 d8 50 e8 ?? ?? ?? ?? 3b 45 0c 83 ee ?? 8b 45 01 2b 70 20 29 de d1 ee 01 de 03 70 24 0f b7 36 c1 e6 02 01 de 03 70 1c 8b 36 01 de 89 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Wauchos_RH_2147848497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wauchos.RH!MTB"
        threat_id = "2147848497"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wauchos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4e 04 03 c7 8a 04 08 32 06 8b 4c 24 14 32 c3 43 88 04 0f 66 3b 5e 02 72 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

