rule TrojanDownloader_Win32_Sbrows_A_2147628965_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sbrows.A"
        threat_id = "2147628965"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sbrows"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AnyGraySession" ascii //weight: 1
        $x_1_2 = "CWebBrowser2" ascii //weight: 1
        $x_1_3 = ".php?mac=" ascii //weight: 1
        $x_1_4 = {3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 73 62 72 6f 77 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

