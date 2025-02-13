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

