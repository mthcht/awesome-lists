rule TrojanDownloader_Win32_Deepdo_2147618418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deepdo"
        threat_id = "2147618418"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deepdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoDL/1.0" ascii //weight: 1
        $x_1_2 = "\\Deepdo\\DeepdoBar\\Favorite" ascii //weight: 1
        $x_1_3 = {55 70 64 61 74 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "http://www." ascii //weight: 1
        $x_1_5 = "InternetReadFile" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "GetWindowsDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

