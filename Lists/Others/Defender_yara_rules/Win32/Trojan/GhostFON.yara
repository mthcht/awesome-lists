rule Trojan_Win32_GhostFON_A_2147725910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostFON.A!dha"
        threat_id = "2147725910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostFON"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 49 2c 6d 20 4f 6e 6c 69 6e 65 2e 20 25 30 34 64 20 2d 20 25 30 32 64 20 2d 20 25 30 32 64 20 2d 20 25 30 32 64 20 2d 20 25 30 32 64 00}  //weight: 5, accuracy: High
        $x_5_2 = {00 6b 6a 69 65 32 33 39 34 38 5f 33 34 32 33 38 39 35 38 5f 4b 4a 32 33 38 37 34}  //weight: 5, accuracy: High
        $x_5_3 = {00 74 72 79 64 61 69 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 00}  //weight: 5, accuracy: High
        $x_5_4 = {00 66 6f 6c 6c 6f 77 67 68 6f 2e 62 79 65 74 68 6f 73 74 37 2e 63 6f 6d 00}  //weight: 5, accuracy: High
        $x_5_5 = {00 44 6f 77 6e 4c 6f 61 64 69 6e 67 20 25 30 32 78 2c 20 25 30 32 78 2c 20 25 30 32 78 00}  //weight: 5, accuracy: High
        $x_5_6 = {00 44 6f 77 6e 4c 6f 61 64 69 6e 67 20 46 69 72 73 74 00}  //weight: 5, accuracy: High
        $x_5_7 = {00 41 6c 6c 20 42 79 74 65 73 20 44 6f 77 6e 20 4c 6f 61 64 20 25 64 2c 20 25 64 00}  //weight: 5, accuracy: High
        $x_5_8 = {00 44 6f 77 6e 20 46 69 6c 65 20 43 72 65 61 74 65 20 46 69 6c 65 64 20 25 64 00}  //weight: 5, accuracy: High
        $x_5_9 = {00 53 70 79 20 41 6c 72 65 61 64 79 20 45 78 69 73 74 65 64 00}  //weight: 5, accuracy: High
        $x_5_10 = {00 47 65 74 20 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 50 61 74 68 20 46 61 69 6c 65 64 21 00}  //weight: 5, accuracy: High
        $x_5_11 = {00 6e 65 74 53 74 61 74 65 2e 64 6c 6c 00}  //weight: 5, accuracy: High
        $x_5_12 = {00 44 6f 77 6e 20 54 68 72 65 61 64 20 53 74 61 72 74 65 64 00}  //weight: 5, accuracy: High
        $x_5_13 = {00 44 6f 77 6e 50 61 74 68 20 3a 20 25 73 00}  //weight: 5, accuracy: High
        $x_5_14 = {00 43 6d 64 52 75 6e 33 32 6b 72 00}  //weight: 5, accuracy: High
        $x_5_15 = {00 4d 70 43 6d 64 52 75 6e 6b 72 2e 64 6c 6c 00}  //weight: 5, accuracy: High
        $x_5_16 = {00 47 48 4f 53 54 34 31 39 00}  //weight: 5, accuracy: High
        $x_3_17 = {00 69 78 65 6f ?? ?? ?? 2e 62 69 6e 00}  //weight: 3, accuracy: Low
        $x_1_18 = {00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 54 72 69 64 65 6e 74 2f 34 2e 30 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 29 00}  //weight: 1, accuracy: High
        $x_1_19 = {00 25 73 5c 72 65 73 75 6c 74 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_20 = {00 46 75 6e 63 74 69 6f 6e 20 49 6e 69 74 20 46 61 69 6c 65 64 00}  //weight: 1, accuracy: High
        $x_1_21 = {00 46 75 6e 63 74 69 6f 6e 20 49 6e 69 74 20 4f 4b 21 00}  //weight: 1, accuracy: High
        $x_1_22 = {00 47 65 74 20 46 75 6e 63 74 69 6f 6e 20 53 74 61 72 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_23 = {00 47 65 74 20 44 65 73 6b 74 6f 70 20 50 61 74 68 20 46 61 69 6c 65 64 21 00}  //weight: 1, accuracy: High
        $x_1_24 = {00 47 65 74 20 52 65 63 65 6e 74 20 50 61 74 68 20 46 61 69 6c 65 64 21 00}  //weight: 1, accuracy: High
        $x_1_25 = {00 4d 61 69 6e 20 54 68 72 65 61 64 20 53 74 61 72 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_26 = {00 4c 4f 47 5f 50 41 54 48 20 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_27 = {00 47 65 74 49 6e 66 6f 20 53 74 61 72 74 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_28 = {00 68 6f 73 74 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_29 = {00 25 73 3f 66 69 6c 65 6e 61 6d 65 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_30 = {00 55 70 6c 6f 61 64 20 46 75 6e 63 74 69 6f 6e 20 53 74 61 72 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_31 = {00 0d 0a 2d 2d 2d 2d 2d 2d 57 65 62 4b 69 74 46 6f 72 6d 42 6f 75 6e 64 61 72 79 77 68 70 46 78 4d 42 65 31 39 63 53 6a 46 6e 47 00}  //weight: 1, accuracy: High
        $x_1_32 = {00 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 3b 20 62 6f 75 6e 64 61 72 79 3d 2d 2d 2d 2d 57 65 62 4b 69 74 46 6f 72 6d 42 6f 75 6e 64 61 72 79 77 68 70 46 78 4d 42 65 31 39 63 53 6a 46 6e 47 00}  //weight: 1, accuracy: High
        $x_1_33 = {00 44 3a 5c 72 65 73 75 6c 74 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_34 = {00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 45 78 70 6f 72 74 46 75 6e 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_35 = {00 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_36 = {00 61 2e 62 61 74 00 00}  //weight: 1, accuracy: High
        $x_1_37 = {00 64 69 72 20 25 73 5c 20 3e 3e 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_38 = {00 64 69 72 20 2f 73 20 25 73 5c 20 3e 3e 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_39 = {00 73 79 73 74 65 6d 69 6e 66 6f 20 3e 3e 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_40 = {00 74 61 73 6b 6c 69 73 74 20 3e 3e 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_41 = {00 74 61 73 6b 6c 69 73 74 20 2f 4d 20 3e 3e 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_42 = {00 6e 65 74 73 74 61 74 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

