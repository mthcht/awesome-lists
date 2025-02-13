rule Backdoor_Win32_Vedratve_A_2147725626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vedratve.A!dha"
        threat_id = "2147725626"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vedratve"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c0 fc 50 51 0f 97 50 fe d9 c1 47 6f ab 63 ef 7d 33 e6 ca fe d3 58 da 3a ea b5 17 87 80 92 bd 96}  //weight: 4, accuracy: High
        $x_4_2 = {8a 0b 32 4c 24 14 88 08 40 43 4e 75 f3 80 20 00}  //weight: 4, accuracy: High
        $x_4_3 = {00 6d 61 6e 67 73 72 76 00 44 65 73 74 20 4e 65 74 77 6f 72 6b 00}  //weight: 4, accuracy: High
        $x_2_4 = {3d 36 27 00 00 74 22 3d 44 27 00 00 76 15 3d 46 27 00 00 76 14 3d 48 27 00 00 76 07 3d 4a 27 00 00 76 06}  //weight: 2, accuracy: High
        $x_2_5 = {6a 30 8d 85 ?? ff ff ff 5b 6a 44 5f 57 56 50 e8 ?? ?? 01 00}  //weight: 2, accuracy: Low
        $x_2_6 = {8a 08 32 4d 14 c1 6d 14 08 88 0c 07 40 4e 75 f0}  //weight: 2, accuracy: High
        $x_2_7 = {62 47 55 42 53 4a 10 11 0d 47 4f 4f 00}  //weight: 2, accuracy: High
        $x_2_8 = {6c 53 46 4d 70 60 6e 42 4d 42 44 46 51 62 00}  //weight: 2, accuracy: High
        $x_2_9 = {d6 80 d3 9a 9d 80 87 92 9f 9f 96 97 f9 00}  //weight: 2, accuracy: High
        $x_2_10 = {6b 78 65 74 72 61 79 2e 65 78 65 00 25 73 5c 25 73 2e 73 79 73}  //weight: 2, accuracy: High
        $x_2_11 = {54 4d 42 4d 53 52 56 2e 65 78 65 00 46 52 57 4b 5f 45 56 45 4e 54 5f 53 46 43 54 4c 43 4f 4d 5f 45 58 49 54}  //weight: 2, accuracy: High
        $x_2_12 = "%s -r debug -z 1" ascii //weight: 2
        $x_1_13 = "SYSTEMIOEVENT117" ascii //weight: 1
        $x_1_14 = "dFWpZPWFNgJQF@WLQZb" ascii //weight: 1
        $x_1_15 = {74 51 4a 57 46 73 51 4c 40 46 50 50 6e 46 4e 4c 51 5a 00}  //weight: 1, accuracy: High
        $x_1_16 = {64 46 57 70 5a 50 57 46 4e 67 4a 51 46 40 57 4c 51 5a 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

