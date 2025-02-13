rule TrojanDownloader_Win32_Teginim_A_2147605506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Teginim.A"
        threat_id = "2147605506"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Teginim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {74 37 57 ff 75 f4 8d 85 d8 f6 ff ff 50 ff 75 ec e8 84 fe ff ff 83 c4 10 83 f8 ff 75 03 33 f6 46}  //weight: 3, accuracy: High
        $x_1_2 = "/mini/get.php?id=" ascii //weight: 1
        $x_1_3 = "%skmq%d.exe" ascii //weight: 1
        $x_1_4 = "_cls%d.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

