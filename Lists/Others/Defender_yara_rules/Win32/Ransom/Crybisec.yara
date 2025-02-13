rule Ransom_Win32_Crybisec_A_2147690269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crybisec.A"
        threat_id = "2147690269"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crybisec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2f 69 6e 76 6f 6b 65 2e 70 68 70 3f 70 72 65 66 69 78 3d 25 64 00}  //weight: 2, accuracy: High
        $x_2_2 = {2f 75 70 6c 6f 61 64 2e 70 68 70 3f 69 64 3d 25 73 26 66 69 6c 65 6e 61 6d 65 3d 25 73 5f 25 53 00}  //weight: 2, accuracy: High
        $x_1_3 = {62 6f 74 69 64 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {6c 61 6e 67 69 64 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {70 75 72 73 65 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {72 63 34 6b 65 79 00}  //weight: 1, accuracy: High
        $x_1_7 = {77 69 6e 76 65 72 3d 25 64 2e 25 64 2e 25 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {2a 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 2a 00 2e 00 2a 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {5c 00 77 00 73 00 5f 00 61 00 75 00 64 00 69 00 6f 00 5f 00 65 00 61 00 78 00 33 00 32 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {48 00 6f 00 77 00 54 00 6f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 73 00 72 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 76 00 73 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_2_13 = {e8 14 00 00 00 52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 00 48 f7 d2 68 59 36 fb db}  //weight: 2, accuracy: High
        $x_2_14 = {8b 12 31 c8 83 f7 10 31 ff 01 d0 09 d6 81 45 e4 87 00 00 00 39 da 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

