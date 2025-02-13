rule TrojanClicker_Win32_Befeenk_A_2147622956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Befeenk.A"
        threat_id = "2147622956"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Befeenk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 4f 56 49 45 00 00 00 ff ff ff ff 10 00 00 00 77 77 77 2e 62 69 67 2d 70 69 6e 6b 2e 6e 65 74}  //weight: 2, accuracy: High
        $x_1_2 = {2d 62 6f 78 00 00 00 00 ff ff ff ff 05 00 00 00 56 49 44 45 4f 00 00 00 ff ff ff ff 12}  //weight: 1, accuracy: High
        $x_1_3 = {0b 00 00 00 72 65 67 20 64 65 6c 65 74 65 20 00 ff ff ff ff 16 00 00 00 20 2f 76 20 49 4d 45 5f}  //weight: 1, accuracy: High
        $x_1_4 = {3f 75 69 64 3d 00 00 00 ff ff ff ff 04 00 00 00 26 78 6e 3d 00 00 00 00 61 67 65 6e 74}  //weight: 1, accuracy: High
        $x_1_5 = "?exe=1&uid=" ascii //weight: 1
        $x_1_6 = {6e 6f 63 6f 6f 6b 69 65 00 00 00 00 ff ff ff ff 05 00 00 00 6e 6f 6b 65 79}  //weight: 1, accuracy: High
        $x_2_7 = "movie-h.com" ascii //weight: 2
        $x_1_8 = "check_pay.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

