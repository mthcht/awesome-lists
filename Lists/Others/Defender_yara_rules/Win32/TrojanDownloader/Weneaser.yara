rule TrojanDownloader_Win32_Weneaser_A_2147626322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Weneaser.A"
        threat_id = "2147626322"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Weneaser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-2005-search.com/new1.php" ascii //weight: 10
        $x_2_2 = "Timer: Clicked:" ascii //weight: 2
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\User Agent\\Post Platform" ascii //weight: 2
        $x_1_4 = "affiliat" ascii //weight: 1
        $x_1_5 = "advert" ascii //weight: 1
        $x_1_6 = "banner" ascii //weight: 1
        $x_1_7 = "download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

