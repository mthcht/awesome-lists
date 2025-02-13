rule Backdoor_Win32_Licat_2147571848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Licat"
        threat_id = "2147571848"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Licat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {be 92 7a 08 00 3b fe 0f 85 ce 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {c6 00 6d c6 40 01 73 c6 40 02 6e}  //weight: 2, accuracy: High
        $x_3_3 = {8a 44 30 06 3a c3 74 1c 3c 3b 74 18}  //weight: 3, accuracy: High
        $x_3_4 = {8a 44 37 06 3c 3b 74 1c 84 c0 74 18}  //weight: 3, accuracy: High
        $x_3_5 = {80 3c 30 73 8d 0c 30 75 7f 80 79 01 68 75 79 80 79 02 65 75 73 80 79 03 6c 75 6d 80 79 04 6c 75 67 80 79 05 20}  //weight: 3, accuracy: High
        $x_3_6 = {80 38 73 75 37 80 78 01 68 75 31 80 78 02 65 75 2b 80 78 03 6c 75 25 80 78 04 6c 75 1f 80 78 05 20}  //weight: 3, accuracy: High
        $x_3_7 = {40 00 80 38 6d 0f 85 ?? ?? 00 00 80 78 01 73 0f 85 ?? ?? 00 00 80 78 02 67 0f 85 ?? ?? 00 00 53}  //weight: 3, accuracy: Low
        $x_3_8 = {80 38 64 75 6e 80 78 01 6f 75 68 80 78 02 77 75 62 80 78 03 6e 75 5c 80 78 04 20}  //weight: 3, accuracy: High
        $x_3_9 = {80 3c 30 64 8d 0c 30 0f 85 dc 00 00 00 80 79 01 6f 0f 85 d2 00 00 00 80 79 02 77}  //weight: 3, accuracy: High
        $x_3_10 = {88 5d fb c6 45 fc 92 88 5d fd 88 5d fe 88 5d ff ff 15 ?? ?? 40 00 6a 50 8b f8}  //weight: 3, accuracy: Low
        $x_3_11 = {40 eb a7 83 c0 04 8b ?? 03 ?? 8a 08 80 f9 3a 75 05 38 48 01 74 06 88 0a 42 40 eb ee}  //weight: 3, accuracy: Low
        $x_4_12 = {53 56 57 8b f1 c6 85 ?? fe ff ff 47 c6 85 ?? fe ff ff 45 c6 85 ?? fe ff ff 54 c6 85}  //weight: 4, accuracy: Low
        $x_4_13 = {01 00 00 56 c6 85 ?? fe ff ff 47 c6 85 ?? fe ff ff 45 c6 85 ?? fe ff ff 54 c6 85}  //weight: 4, accuracy: Low
        $x_4_14 = {5f 57 49 4e 44 4f 57 00 00 4e 41 4d 45 5f 4f 46 5f 54 48 45 5f 57 49 4e 44 4f 57 43 4c 41 53 53 00 6f 70 65 6e}  //weight: 4, accuracy: High
        $x_4_15 = {80 3c 30 6d 75 65 80 7c 30 01 73 75 5e 80 7c 30 02 67 75 57}  //weight: 4, accuracy: High
        $x_4_16 = {c6 45 ea 4e c6 45 eb 48 c6 45 ec 69 c6 45 ed 64 c6 45 ee 64 c6 45 ef 65}  //weight: 4, accuracy: High
        $x_4_17 = {8d 45 e8 50 c6 45 e8 4d c6 45 e9 53 c6 45 ea 4e c6 45 eb 48 c6 45 ec 69 c6 45 ed 64}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((6 of ($x_3_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

