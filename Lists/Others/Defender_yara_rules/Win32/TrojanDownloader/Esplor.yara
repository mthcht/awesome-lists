rule TrojanDownloader_Win32_Esplor_A_2147627341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Esplor.A"
        threat_id = "2147627341"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Esplor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "|kpfw32.exe|rfwmain.exe|RSTray.exe|" wide //weight: 1
        $x_1_3 = "taskkill /f /pid " wide //weight: 1
        $x_1_4 = "net stop sharedacces" wide //weight: 1
        $x_1_5 = "C:\\Program Files\\vstart.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

