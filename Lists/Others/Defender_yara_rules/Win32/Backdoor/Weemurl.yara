rule Backdoor_Win32_Weemurl_B_2147717444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Weemurl.B!dha"
        threat_id = "2147717444"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Weemurl"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 b8 83 c0 01 89 45 b8 8b 4d b8 3b 0d ?? ?? ?? ?? 73 3c 8b 55 b8 0f be 82 ?? ?? ?? ?? 33 c9 8a 0d ?? ?? ?? ?? 33 c1 8b 55 b8 88 82 ?? ?? ?? ?? 8b 45 b8 0f be 88 ?? ?? ?? ?? 33 d2 8a 15 ?? ?? ?? ?? 33 ca 8b 45 b8 88 88 ?? ?? ?? ?? eb b0}  //weight: 2, accuracy: Low
        $x_2_2 = {50 00 72 00 6f 00 62 00 65 00 53 00 63 00 72 00 69 00 70 00 74 00 46 00 69 00 6e 00 74 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {5c 73 79 73 70 72 65 70 5c 63 72 79 70 74 62 61 73 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {67 75 70 64 61 74 65 2e 65 78 65 00 63 72 79 70 74 62 61 73 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_5 = {32 da 32 d9 88 98 ?? ?? ?? ?? 40 3b c6 72 eb 12 00 8a 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 8a 98}  //weight: 2, accuracy: Low
        $x_1_6 = {62 62 62 62 43 72 79 70 74 42 61 73 65 44 4c 4c 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_3_7 = {3b 7d 7d 3b 6e 65 77 20 4d 41 49 4e 28 29 2e 46 69 72 65 28 29 3b 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

