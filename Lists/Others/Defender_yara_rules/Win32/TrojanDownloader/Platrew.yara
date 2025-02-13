rule TrojanDownloader_Win32_Platrew_2147804051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Platrew"
        threat_id = "2147804051"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Platrew"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "platinumreward.co.kr/version/svcver.php" ascii //weight: 10
        $x_10_2 = "update.platinumreward.co.kr/platinum/backman/bdksvc.exe" ascii //weight: 10
        $x_10_3 = "update.platinumreward.co.kr/subX/HDaq.exe" ascii //weight: 10
        $x_10_4 = "update.platinumreward.co.kr/platinum/backman/recovery.exe" ascii //weight: 10
        $x_1_5 = "InternetReadFile" ascii //weight: 1
        $x_1_6 = "InternetCloseHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

