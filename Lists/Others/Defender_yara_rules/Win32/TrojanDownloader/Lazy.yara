rule TrojanDownloader_Win32_Lazy_RDB_2147839570_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lazy.RDB!MTB"
        threat_id = "2147839570"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 01 89 45 fc 81 7d fc 10 04 00 00 73 18 8b 4d fc 0f b6 91 ?? ?? ?? ?? 83 f2 61 8b 45 fc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Lazy_MK_2147956578_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lazy.MK!MTB"
        threat_id = "2147956578"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_35_1 = "!slowloris" ascii //weight: 35
        $x_30_2 = "!httpflood" ascii //weight: 30
        $x_25_3 = "!DNS-QUERY-FLOOD" ascii //weight: 25
        $x_20_4 = "!httpbypass" ascii //weight: 20
        $x_15_5 = "karrum.txt" ascii //weight: 15
        $x_10_6 = "task_id" ascii //weight: 10
        $x_5_7 = "bot_id" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Lazy_MKA_2147967433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lazy.MKA!MTB"
        threat_id = "2147967433"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {0f 47 4d d8 0f b7 04 50 0f b7 55 24 6b c0 19 66 2b c2 ba 9a 06 00 00 66 2b 45 b4 66 03 46 02 8b 75 bc 66 2b c2 8b 55 b8 83 c6 02 89 75 bc 66 89 04 51 42 8b 7d ec 89 55 b8 3b 75 1c}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

