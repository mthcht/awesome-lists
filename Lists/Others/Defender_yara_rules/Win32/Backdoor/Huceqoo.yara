rule Backdoor_Win32_Huceqoo_A_2147602872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Huceqoo.A"
        threat_id = "2147602872"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Huceqoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {75 f7 68 88 13 00 00 ff d6 eb ee}  //weight: 3, accuracy: High
        $x_4_2 = {7e 0d 8a 0c 10 32 c8 88 0c 10 40 3b c3 7c f3 5f c6 04 1a 00}  //weight: 4, accuracy: High
        $x_4_3 = {99 b9 12 00 00 00 f7 f9 80 c2 42 88 54 34 0c 46 83 fe 08 7c e6}  //weight: 4, accuracy: High
        $x_3_4 = {8d 44 24 0c 6a 00 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 51}  //weight: 3, accuracy: High
        $x_2_5 = {83 ec 10 66 8b 44 24 18 8b 4c 24 14 56 6a 06 6a 01 6a 02 66 c7 44 24 10 02 00 66 89 44 24 12 89 4c 24 14}  //weight: 2, accuracy: High
        $x_3_6 = {6a 00 6a 01 68 c8 04 00 00 53 ff d5 6a 00 6a 01 68 c9 04 00 00 53 ff d5}  //weight: 3, accuracy: High
        $x_2_7 = {67 64 76 6b 6b 76 72 65 71 67 6b 66 69 00}  //weight: 2, accuracy: High
        $x_1_8 = {3a 62 79 65 62 79 65 00}  //weight: 1, accuracy: High
        $x_2_9 = {43 75 72 72 65 6e 74 55 73 65 72 00 2e 73 63 72}  //weight: 2, accuracy: High
        $x_1_10 = "if exist \"%s\" goto" ascii //weight: 1
        $x_2_11 = ":un: %s cn: %s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

