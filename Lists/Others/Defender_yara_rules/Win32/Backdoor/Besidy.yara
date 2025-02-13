rule Backdoor_Win32_Besidy_A_2147725147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Besidy.A!bit"
        threat_id = "2147725147"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Besidy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 00 32 00 33 00 34 00 33 00 33 00 34 00 35 00 33 00 34 00 34 00 33 00 35 00 33 00 35 00 34 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00}  //weight: 3, accuracy: High
        $x_2_2 = {5c 00 6c 00 6f 00 67 00 67 00 65 00 64 00 2e 00 74 00 78 00 74 00 [0-32] 6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 74 00 78 00 74 00}  //weight: 2, accuracy: Low
        $x_2_3 = {00 00 77 00 65 00 62 00 63 00 61 00 6d 00 2e 00 6a 00 70 00 67 00}  //weight: 2, accuracy: High
        $x_2_4 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 6c 00 6f 00 67 00 69 00 6e 00 20 00 64 00 61 00 74 00 61 00 [0-32] 5c 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 2e 00 74 00 78 00 74 00}  //weight: 2, accuracy: Low
        $x_1_5 = {00 00 52 00 75 00 6e 00 43 00 4d 00 44 00 5f 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 44 00 77 00 6e 00 46 00 69 00 6c 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 00 52 00 75 00 6e 00 46 00 69 00 6c 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 00 57 00 68 00 61 00 74 00 53 00 73 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 00 53 00 63 00 72 00 65 00 65 00 6e 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 00 53 00 65 00 6e 00 64 00 50 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 00 00}  //weight: 1, accuracy: High
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

