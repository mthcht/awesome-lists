rule Backdoor_Win32_Dervec_2147651834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dervec"
        threat_id = "2147651834"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dervec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f be c9 c1 e0 04 03 c1 8b c8 42 81 e1 00 00 00 f0 74 0b 8b f1 c1 ee 18 33 c6 f7 d1 23 c1 8a 0a 84 c9 75 dc}  //weight: 2, accuracy: High
        $x_1_2 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {56 65 72 64 65 63 00 00 53 4f 46 54 57 41 52 45 5c 53 65 63 75 72 69 74 79 5c 43 6d 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 53 65 63 75 72 69 74 79 5c 53 76 63 5c 50 61 74 68 00}  //weight: 1, accuracy: High
        $x_1_5 = {67 6f 74 6f 77 69 6e 2e 45 6e 63 72 79 70 74 44 65 63 72 79 70 74 2e 53 69 6d 70 6c 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {4c 6f 67 30 6e 00 00 00 50 6f 6c 69 63 79 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 4e 65 74 43 43 25 64 2e 25 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 65 72 76 69 63 63 63 63 00 00 00 65 44 6c 6c}  //weight: 1, accuracy: High
        $x_1_9 = {77 77 77 2e 62 61 69 64 75 2e 63 6f 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

