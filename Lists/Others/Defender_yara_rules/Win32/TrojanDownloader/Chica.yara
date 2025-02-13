rule TrojanDownloader_Win32_Chica_B_2147600062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chica.B"
        threat_id = "2147600062"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chica"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 55 d8 a1 68 6a 41 00 0f b7 40 08 e8 ?? 35 ff ff ff 75 d8 68 ?? 44 41 00 a1 58 6a 41 00 33 d2 52 50 8d 45 d4 e8}  //weight: 4, accuracy: Low
        $x_1_2 = "/bot/new.php" ascii //weight: 1
        $x_1_3 = "/bot/get.php?socks=" ascii //weight: 1
        $x_1_4 = "/bot/add.php?id=" ascii //weight: 1
        $x_1_5 = "winload.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

