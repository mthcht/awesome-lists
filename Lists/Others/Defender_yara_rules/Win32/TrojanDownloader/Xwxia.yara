rule TrojanDownloader_Win32_Xwxia_A_2147642540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Xwxia.A"
        threat_id = "2147642540"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Xwxia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\npdrmv.jpg\" /q /f" ascii //weight: 1
        $x_1_2 = "%MYFILES%\\coopen_setup" ascii //weight: 1
        $x_1_3 = ".zuihouyi.com/" ascii //weight: 1
        $x_1_4 = "a.xwxiazai.com/" ascii //weight: 1
        $x_1_5 = ".07396.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

