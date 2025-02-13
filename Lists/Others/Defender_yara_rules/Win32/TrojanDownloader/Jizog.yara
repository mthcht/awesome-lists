rule TrojanDownloader_Win32_Jizog_A_2147596372_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jizog.A"
        threat_id = "2147596372"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jizog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "beautifulcollegeview.com/jizhong/jizhong.exe" wide //weight: 1
        $x_1_3 = "NOTEDAD.EXE %1" wide //weight: 1
        $x_1_4 = "IExplorer.dll                                                              .dbt" wide //weight: 1
        $x_1_5 = "txtfile\\shell\\open\\command" wide //weight: 1
        $x_1_6 = "\\Windows\\CurrentVersion\\Run\\IESet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

