rule Spammer_Win32_Emegrab_A_2147622377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Emegrab.A"
        threat_id = "2147622377"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Emegrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 06 6a 01 6a 02 ff 15 ?? ?? 01 05 8b e8 83 fd ff 0f 84 ?? ?? 00 00 68 d6 04 00 00 66 c7 44 24 08 02 00}  //weight: 2, accuracy: Low
        $x_2_2 = {81 39 52 61 72 21 75 06 b8 01 00 00 00 c3 8a 01 3c 37 75 0c 80 79 01 7a 75 06 b8 02 00 00 00 c3 3c 42 75 0c}  //weight: 2, accuracy: High
        $x_3_3 = {ff d6 8b 44 24 ?? 33 d2 b9 4e 15 00 00 f7 f1 8b c2 3d 13 09 00 00 7d 0e 47 81 ff e8 03 00 00 7c da b8 13 09 00 00}  //weight: 3, accuracy: Low
        $x_1_4 = ".0-9-]{1,}.(?:info|ru|net|biz|com|su|org))" ascii //weight: 1
        $x_1_5 = {39 34 2e 37 35 2e 03 00 2e 03 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3f 62 61 73 65 3d 00 00 69 6e 64 65 78 2e 70 68 70 00 00 00 47 45 54 20 2f 00}  //weight: 1, accuracy: High
        $x_1_7 = {45 6d 61 69 6c 47 72 61 62 62 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {46 54 50 5f 47 52 41 42 42 45 52 31 00}  //weight: 1, accuracy: High
        $x_1_9 = {70 63 72 65 5f 63 61 6c 6c 6f 75 74 00 70 63 72 65 5f 63 6f 6d 70 69 6c 65 00 70 63 72 65 5f 63 6f 6d 70 69 6c 65 32 00 70 63 72 65 5f 65 78 65 63 00 70 63 72 65 5f 66 72 65 65 00 70 63 72 65 5f 6d 61 6c 6c 6f 63 00 70 63 72 65 5f 73 74 61 63 6b 5f 66 72 65 65 00 70 63 72 65 5f 73 74 61 63 6b 5f 6d 61 6c 6c 6f 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

