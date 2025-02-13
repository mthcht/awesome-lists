rule Worm_Win32_Skuffbot_A_197774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Skuffbot.A"
        threat_id = "197774"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Skuffbot"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 04 01 88 45 ec 8b 45 fc 2b 45 f4 8b 4d 08 8a 44 01 01 88 45 ed 80 65 ee 00 6a 10 6a 00 8d 45 ec 50 e8}  //weight: 3, accuracy: High
        $x_1_2 = {73 6b 75 66 66 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {02 03 30 34 20 4e 65 77}  //weight: 1, accuracy: High
        $x_1_4 = {6e 69 67 67 61 00}  //weight: 1, accuracy: High
        $x_1_5 = {55 6e 6b 6e 6f 77 6e 20 65 72 72 6f 72 20 6f 63 63 75 72 72 65 64 20 77 68 69 6c 65 20 64 6f 77 6e 6c 6f 61 64 69 6e 67 20 3a 7c 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 4e 45 57 53 48 49 54 00}  //weight: 1, accuracy: High
        $x_1_7 = {46 61 69 6c 65 64 20 74 6f 20 73 74 61 72 74 20 64 6c 20 74 68 72 65 61 64 2e 00}  //weight: 1, accuracy: High
        $x_1_8 = {72 61 6e 20 6e 65 77 2c 20 71 75 69 74 74 69 6e 67 20 6f 6c 64 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_2_9 = {2f 00 75 00 70 00 64 00 00 00 00 00 2f 00 6e 00 65 00 77 00 00 00}  //weight: 2, accuracy: High
        $x_2_10 = {74 00 66 00 6e 00 00 00 5c 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_11 = {7b 44 4c 7d 3a 20 9b 20 25 73 20 28 25 73 29 20 2d 20 55 70 64 61 74 65 3a 20 25 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

