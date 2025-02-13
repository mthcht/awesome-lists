rule Worm_Win32_Mywife_2147555616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mywife"
        threat_id = "2147555616"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mywife"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {63 41 70 70 48 69 64 65 72 00}  //weight: 2, accuracy: High
        $x_2_2 = {53 70 72 65 61 64 5f 4e 65 74 77 6f 72 6b 00}  //weight: 2, accuracy: High
        $x_2_3 = {54 68 65 5f 42 65 67 69 6e 00}  //weight: 2, accuracy: High
        $x_4_4 = "WORM_Engin" ascii //weight: 4
        $x_4_5 = "BlackWorm." ascii //weight: 4
        $x_2_6 = {74 69 6d 62 6f 6d 62 00}  //weight: 2, accuracy: High
        $x_2_7 = "2AD00ED6" wide //weight: 2
        $x_1_8 = {72 65 67 41 50 49 00}  //weight: 1, accuracy: High
        $x_1_9 = {43 4e 65 74 77 6f 72 6b 45 6e 75 6d 00}  //weight: 1, accuracy: High
        $x_1_10 = {42 6c 6f 63 6b 49 6e 70 75 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {57 4e 65 74 45 6e 75 6d 52 65 73 6f 75 72 63 65 41 00}  //weight: 1, accuracy: High
        $x_1_12 = "HideApplication" ascii //weight: 1
        $x_1_13 = {71 6c 28 fd f5 00 00 00 00 db 6c 2c fd f5 10 00 00 00 c4 f5 10 00 00 00 c7 c4 04}  //weight: 1, accuracy: High
        $x_1_14 = {6c 14 00 04 7a ff 6c 0c 00 0a}  //weight: 1, accuracy: High
        $x_1_15 = {6c 28 00 f5 03 00 00 00 c7 6c 28 00 f5 04 00 00 00 c7 c5 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

