rule TrojanDownloader_Win32_Twipsense_A_2147689665_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Twipsense.A"
        threat_id = "2147689665"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Twipsense"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "D:\\developement\\projects\\flood_load\\Release\\flood_load.pdb" ascii //weight: 2
        $x_2_2 = "2ip.ru" ascii //weight: 2
        $x_2_3 = "/license_monitor/1.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

