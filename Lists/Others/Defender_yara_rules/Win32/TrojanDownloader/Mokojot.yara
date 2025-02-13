rule TrojanDownloader_Win32_Mokojot_DA_2147899162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mokojot.DA!MTB"
        threat_id = "2147899162"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokojot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 89 45 f4 8b 45 f8 31 d2 f7 75 0c 8b 45 f4 0f be 34 10 8b 45 10 8b 4d f8 0f be 14 08 31 f2 88 14 08 8b 45 f8 83 c0 01 89 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

