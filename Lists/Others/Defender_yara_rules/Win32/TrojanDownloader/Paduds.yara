rule TrojanDownloader_Win32_Paduds_A_2147803996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Paduds.A"
        threat_id = "2147803996"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Paduds"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f 84 54 01 00 00 c6 45 f1 5a c6 45 f0 00 6a 00 6a 08}  //weight: 3, accuracy: High
        $x_3_2 = {7c 22 43 33 f6 ff 75 f8 8b 45 f4 ff 34 b0 68 ?? ?? ?? ?? 8d 45 f8 ba 03 00 00 00}  //weight: 3, accuracy: Low
        $x_1_3 = {68 73 74 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 64 73 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {61 75 70 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 73 79 73 74 65 6d 5c 63 6d 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

