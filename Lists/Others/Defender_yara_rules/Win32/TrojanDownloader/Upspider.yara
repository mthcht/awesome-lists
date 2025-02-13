rule TrojanDownloader_Win32_Upspider_A_2147601233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upspider.A"
        threat_id = "2147601233"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upspider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{B0B678D8-ECB3-4FD6-A8D7-9F0F6C03C5FF}" ascii //weight: 1
        $x_1_2 = "upspider.com" ascii //weight: 1
        $x_1_3 = "\\WINDOWS\\system32\\DCB" ascii //weight: 1
        $x_1_4 = "system32\\dl07.dll" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_6 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

