rule TrojanDownloader_Win32_Gewner_A_2147651921_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gewner.A"
        threat_id = "2147651921"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gewner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "newg/getUpdate.php" ascii //weight: 1
        $x_1_2 = "config\\svchost.exe" ascii //weight: 1
        $x_1_3 = {8a 17 83 fe 1f 7c 02 33 f6 2a 96 ?? ?? ?? ?? 32 96 ?? ?? ?? ?? 46 8b c8 80 e1 01 80 f9 01 75 0c}  //weight: 1, accuracy: Low
        $x_1_4 = {83 ca fe 42 85 d2 75 0e 8a 10 2a 14 31 f6 d2 32 14 31 88 10 eb 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

