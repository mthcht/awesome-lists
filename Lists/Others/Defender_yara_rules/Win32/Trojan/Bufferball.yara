rule Trojan_Win32_Bufferball_B_2147742814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bufferball.B!dha"
        threat_id = "2147742814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bufferball"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 69 78 54 68 65 53 65 72 76 69 63 65 52 65 67 69 73 74 72 79 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 72 76 69 63 65 52 65 67 69 73 74 72 79 43 6c 65 61 6e 55 70 20 45 72 72 6f 72 20 3d 20 25 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 52 43 55 45 52 52 4f 52 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 75 61 72 64 52 65 67 69 73 74 72 79 43 6c 65 61 6e 55 70 20 45 72 72 6f 72 20 3d 20 25 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {4b 45 79 48 35 21 47 67 67 45 00}  //weight: 1, accuracy: High
        $x_1_6 = {6a 39 59 60 5a 45 77 65 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {44 65 63 72 79 70 74 20 46 61 69 6c 65 64 2e 00}  //weight: 1, accuracy: High
        $x_1_8 = {4e 6f 74 20 61 6e 20 65 78 65 63 75 74 61 62 6c 65 20 66 69 6c 65 2e 00}  //weight: 1, accuracy: High
        $x_1_9 = {41 44 35 43 39 35 38 35 33 28 53 72 76 29 00}  //weight: 1, accuracy: High
        $x_1_10 = {69 00 63 00 6e 00 6f 00 73 00 6c 00 74 00 6f 00 61 00 72 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {53 00 3a 00 28 00 4d 00 4c 00 3b 00 3b 00 4e 00 57 00 3b 00 3b 00 3b 00 4c 00 57 00 29 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {44 00 3a 00 28 00 41 00 3b 00 3b 00 47 00 41 00 3b 00 3b 00 3b 00 57 00 44 00 29 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 53 00 65 00 74 00 75 00 70 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 30 00 78 00 30 00 30 00 38 00 39 00 38 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {65 00 6c 00 76 00 38 00 36 00 42 00 30 00 42 00 38 00 00 00}  //weight: 1, accuracy: High
        $x_1_15 = {64 61 74 61 62 61 73 65 20 69 73 20 6e 65 65 64 65 64 2e 00}  //weight: 1, accuracy: High
        $x_1_16 = {70 3d 64 6c 26 65 3d 35 31 30 26 61 3d 00}  //weight: 1, accuracy: High
        $x_1_17 = {72 00 65 00 68 00 74 00 72 00 61 00 66 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = {72 00 65 00 68 00 74 00 72 00 61 00 66 00 63 00 75 00 70 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_19 = {66 00 70 00 69 00 6c 00 6c 00 61 00 65 00 66 00 6f 00 72 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_20 = {66 61 74 68 65 72 54 68 72 65 61 64 50 72 6f 63 31 00}  //weight: 1, accuracy: High
        $x_1_21 = {62 00 73 00 6e 00 61 00 65 00 73 00 76 00 65 00 69 00 72 00 6f 00 00 00}  //weight: 1, accuracy: High
        $x_1_22 = {70 6c 61 74 66 6f 72 6d 20 62 6f 6f 74 20 66 61 69 6c 65 64 2e 00}  //weight: 1, accuracy: High
        $x_1_23 = "ghiHIABcdkJYlCnefZajoKLRST9-UV5EFGbm67rP123tusNOwxyz0" ascii //weight: 1
        $x_1_24 = {73 6d 61 6c 6c 20 53 49 44 20 62 75 66 66 65 72 20 73 69 7a 65 00}  //weight: 1, accuracy: High
        $x_1_25 = "--- %02d/%02d/%04d %02d:%02d:%02d ---" ascii //weight: 1
        $x_1_26 = {25 73 20 45 52 52 4f 52 3a 20 5b 25 64 5d 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_27 = {74 00 79 00 69 00 73 00 65 00 6c 00 72 00 6c 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_28 = {26 63 73 6e 3d 25 73 26 69 6e 74 3d 25 64 26 70 72 69 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_29 = {3c 25 73 20 25 73 3d 27 25 64 27 20 25 73 3d 27 25 64 27 3e 25 64 3c 2f 25 73 3e 00}  //weight: 1, accuracy: High
        $x_1_30 = {3c 25 73 3e 25 64 2f 25 64 2f 25 64 20 25 64 3a 25 64 3a 25 64 3c 2f 25 73 3e 00}  //weight: 1, accuracy: High
        $x_1_31 = {3c 25 73 20 25 73 3d 27 25 64 27 3e 25 73 3c 2f 25 73 3e 00}  //weight: 1, accuracy: High
        $x_1_32 = {42 61 73 65 47 75 61 72 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

