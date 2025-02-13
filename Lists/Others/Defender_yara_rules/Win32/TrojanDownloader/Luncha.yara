rule TrojanDownloader_Win32_Luncha_B_2147598409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Luncha.B"
        threat_id = "2147598409"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Luncha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVCP60.dll" ascii //weight: 1
        $x_1_2 = "albania.556677889900.com" ascii //weight: 1
        $x_1_3 = "log-bin/lunch_load.php" ascii //weight: 1
        $x_1_4 = "module-bin/conf/lunch_xml.php" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "InternetReadFile" ascii //weight: 1
        $x_1_7 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

