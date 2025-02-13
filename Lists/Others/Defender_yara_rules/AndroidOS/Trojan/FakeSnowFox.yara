rule Trojan_AndroidOS_FakeSnowFox_A_2147740724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeSnowFox.A"
        threat_id = "2147740724"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeSnowFox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 48 52 30 63 48 4d 36 4c 79 39 68 63 47 6b 75 61 57 35 6d 62 32 31 76 59 6d 6b 75 62 57 55 76 59 57 45 76 62 6d 4d 3d 00}  //weight: 2, accuracy: High
        $x_2_2 = {2d 68 2d 74 2d 74 2d 70 3a 2f 2f 65 2d 6e 2e 73 2d 6e 2d 6f 2d 77 2d 66 2d 6f 2d 78 2e 31 2d 31 2d 32 2d 67 2d 73 2e 63 2d 6f 2d 6d 3a 38 2d 30 2d 38 2d 38 2f 73 2d 64 2d 6b 2f 61 2d 70 2d 69 2f 61 2d 64 2f 68 2d 75 2d 6c 2d 6c 5f 76 32 00}  //weight: 2, accuracy: High
        $x_2_3 = {64 61 74 61 2e 7a 69 70 00}  //weight: 2, accuracy: High
        $x_2_4 = {63 6f 6d 2e 69 6d 2e 4d 61 69 6e 00}  //weight: 2, accuracy: High
        $x_2_5 = {12 00 12 11 12 02 22 03 ?? ?? 6e 10 ?? ?? 0b 00 0c 04 6e 10 ?? ?? 0c 00 0c 05 6e 10 ?? ?? 0a 00 0c 06 70 56 ?? ?? 43 05 5b 93 ?? ?? 54 93 ?? ?? 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 03 12 34}  //weight: 2, accuracy: Low
        $x_2_6 = {58 52 6b 4a 43 63 51 59 6d 38 75 47 35 64 49 6a 54 61 6f 46 5a 4d 2f 33 76 45 6c 79 73 6e 69 2b 42 34 53 70 37 4c 72 41 68 36 74 7a 32 71 65 57 31 50 4b 56 62 48 77 39 78 66 30 44 55 4f 00}  //weight: 2, accuracy: High
        $x_2_7 = {1a 00 00 00 01 13 6e 10 ?? ?? 07 00 0a 02 35 23 44 00 6e 20 ?? ?? 37 00 0a 02 13 04 3d 00 32 42 38 00 62 04 ?? ?? 6e 20 ?? ?? 24 00 0a 02 71 10 ?? ?? 02 00 0c 02}  //weight: 2, accuracy: Low
        $x_2_8 = {0c 01 21 12 12 00 35 20 0c 00 48 03 01 00 df 03 03 10 8d 33 4f 03 01 00 d8 00 00 01 28 f5}  //weight: 2, accuracy: Low
        $x_1_9 = {4c 63 6f 6d 2f 69 6e 66 65 63 2f 75 6e 64 69 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

