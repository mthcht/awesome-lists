rule TrojanDownloader_Win32_Cjfee_A_2147605518_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cjfee.A"
        threat_id = "2147605518"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cjfee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot.cjfeeds.com/tasks.php?cj=%s&domain=%s&v=" ascii //weight: 1
        $x_1_2 = "cjb\\cjb8.exe" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "InternetCrackUrlA" ascii //weight: 1
        $x_1_5 = "CreateDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

