rule TrojanDownloader_Win32_Merolcon_A_2147638340_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Merolcon.A"
        threat_id = "2147638340"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Merolcon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {21 64 77 6e 74 14 81 38 21 63 6c 6f 74 14 81 38 21 72 65 6d 74}  //weight: 3, accuracy: High
        $x_3_2 = {c7 00 6d 6f 64 65 83 c0 04 c7 00 3d 32 26 69 83 c0 04 c7 00 64 65 6e 74 83 c0 04 c6 00 3d}  //weight: 3, accuracy: High
        $x_1_3 = {30 30 30 30 00 48 31 4e 31 42 6f 74}  //weight: 1, accuracy: High
        $x_1_4 = "admin/bot.php" ascii //weight: 1
        $x_1_5 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 00 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

