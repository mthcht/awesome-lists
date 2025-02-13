rule TrojanDownloader_Win32_Delfhost_A_2147599828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Delfhost.A"
        threat_id = "2147599828"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Delfhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "WebBrowser1NewWindow2" ascii //weight: 10
        $x_10_2 = "about:blank" wide //weight: 10
        $x_10_3 = ".asp?mac=" ascii //weight: 10
        $x_10_4 = "AppEvents\\Schemes\\Apps\\Explorer\\Navigating\\.Current" ascii //weight: 10
        $x_10_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3" ascii //weight: 10
        $x_10_6 = "ServiceExecute" ascii //weight: 10
        $x_1_7 = {ff ff 84 c0 74 30 2a 00 50 e8 ?? ?? ?? ff 6a 01 a1 ?? ?? ?? 00 50 e8 ?? ?? ?? ff e8 ?? ?? ff ff eb 46 6a 06 a1 ?? ?? ?? 00 50 e8 ?? ?? ?? ff e8}  //weight: 1, accuracy: Low
        $x_1_8 = {ff ff 84 c0 74 30 25 00 50 e8 ?? ?? ?? ff 6a 01 a1 ?? ?? ?? 00 50 e8 ?? ?? ?? ff eb 46 6a 06 a1 ?? ?? ?? 00 50 e8 ?? ?? ?? ff e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

