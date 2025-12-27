rule TrojanDownloader_Win32_ValleyRAT_EC_2147913491_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ValleyRAT.EC!MTB"
        threat_id = "2147913491"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01}  //weight: 10, accuracy: High
        $x_1_2 = {4e 00 54 00 55 00 53 00 45 00 52 00 2e 00 44 00 58 00 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_ValleyRAT_EC_2147913491_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ValleyRAT.EC!MTB"
        threat_id = "2147913491"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProcessKiller" ascii //weight: 1
        $x_1_2 = "runas" ascii //weight: 1
        $x_1_3 = "ZhuDongFangYu" ascii //weight: 1
        $x_1_4 = "SoftMgrLite" ascii //weight: 1
        $x_1_5 = "DumpUper" ascii //weight: 1
        $x_1_6 = "Winrar" ascii //weight: 1
        $x_1_7 = "safesvr" ascii //weight: 1
        $x_1_8 = "WINWORD.exe" ascii //weight: 1
        $x_1_9 = "wwlib.dll" ascii //weight: 1
        $x_1_10 = "xig.ppt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_ValleyRAT_A_2147958391_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/ValleyRAT.A!AMTB"
        threat_id = "2147958391"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 74 74 70 [0-1] 3a 2f 2f 31 31 31 32 2e 36 38 38 36 30 38 2e 78 79 7a 2f 77 62 2f 6d 32 2e 74 78 74}  //weight: 3, accuracy: Low
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_3 = "Downloading binary from:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

