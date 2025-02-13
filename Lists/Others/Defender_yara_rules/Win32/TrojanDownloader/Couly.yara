rule TrojanDownloader_Win32_Couly_A_2147597061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Couly.A"
        threat_id = "2147597061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Couly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "couly.com/visit.php" ascii //weight: 1
        $x_1_2 = "couly.com/update.exe" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "data.alexa.com" ascii //weight: 1
        $x_1_5 = "botGoWay" ascii //weight: 1
        $x_1_6 = "URLDownloadToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

