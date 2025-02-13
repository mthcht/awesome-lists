rule Trojan_Win32_RunningRAT_A_2147725911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RunningRAT.A!dha"
        threat_id = "2147725911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RunningRAT"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 52 4d 2d 4d 20 3a 20 53 74 61 72 74 00}  //weight: 5, accuracy: High
        $x_5_2 = {00 52 4d 2d 4d 20 3a 20 46 69 6e 64 52 65 73 6f 75 72 63 65 41 20 46 61 69 6c 65 64 00}  //weight: 5, accuracy: High
        $x_5_3 = {00 52 4d 2d 4d 20 3a 20 4c 6f 61 64 52 65 73 6f 75 72 63 65 20 66 61 69 6c 65 64 00}  //weight: 5, accuracy: High
        $x_5_4 = {00 52 4d 2d 4d 20 3a 20 4c 6f 61 64 52 65 73 6f 75 72 63 65 20 4f 4b 21 00}  //weight: 5, accuracy: High
        $x_5_5 = {00 52 4d 2d 4d 20 3a 20 75 6e 63 6f 6d 70 72 65 73 73 20 4f 4b 21 00}  //weight: 5, accuracy: High
        $x_5_6 = {00 52 4d 2d 4d 20 3a 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 20 46 61 69 6c 65 64 20 25 64 00}  //weight: 5, accuracy: High
        $x_5_7 = {00 52 4d 2d 4d 20 3a 20 4c 6f 61 64 4c 69 62 72 61 72 79 41 20 46 61 69 6c 65 64 20 25 73 20 2d 20 25 64 00}  //weight: 5, accuracy: High
        $x_5_8 = {00 52 4d 2d 4d 20 3a 20 45 6e 74 72 79 50 6f 69 6e 74 46 75 6e 63 20 4f 4b 21 00}  //weight: 5, accuracy: High
        $x_5_9 = {00 4d 52 20 2d 20 41 6c 72 65 61 64 79 20 45 78 69 73 74 65 64 00}  //weight: 5, accuracy: High
        $x_5_10 = {00 4d 52 20 3a 20 25 30 34 64 2d 25 30 32 64 2d 25 30 32 64 2d 25 30 32 64 2d 25 30 32 64 2d 25 30 32 64 00}  //weight: 5, accuracy: High
        $x_5_11 = {00 4d 52 20 46 69 72 73 74 20 53 74 61 72 74 65 64 2c 20 52 65 67 69 73 74 65 64 20 4f 4b 21 00}  //weight: 5, accuracy: High
        $x_5_12 = {00 53 79 73 74 65 6d 52 61 74 2e 64 6c 6c 00}  //weight: 5, accuracy: High
        $x_5_13 = {00 52 75 6e 6e 69 6e 67 52 61 74 00}  //weight: 5, accuracy: High
        $x_5_14 = {00 64 6b 65 6f 72 6b 63 6c 5f 65 6b 6c 73 64 6c 5f 31 32 33 5f 32 33 39 32 38 33 34 37 32 39}  //weight: 5, accuracy: High
        $x_5_15 = {00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 52 75 6e 6e 69 6e 67 52 61 74 00}  //weight: 5, accuracy: High
        $x_5_16 = {00 53 79 73 52 61 74 00}  //weight: 5, accuracy: High
        $x_3_17 = {00 69 78 65 6f 35 38 34 2e 62 69 6e 00}  //weight: 3, accuracy: High
        $x_1_18 = {00 50 61 72 65 6e 74 44 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_19 = "C:\\USERS\\Public\\result.log" ascii //weight: 1
        $x_1_20 = {00 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 20 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_21 = {00 50 61 72 65 6e 74 20 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_22 = {00 00 00 00 70 75 74 72 61 74 53 41 53 57 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_23 = {00 00 00 00 70 75 6e 61 65 6c 43 41 53 57 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_24 = {00 00 00 00 74 70 6f 6b 63 6f 73 74 65 73 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_25 = {00 00 00 00 74 63 65 6e 6e 6f 63 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_26 = {00 00 00 00 73 6e 6f 74 68 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_27 = {00 00 00 00 65 6d 61 6e 79 62 74 73 6f 68 74 65 67 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_28 = {00 00 00 00 74 65 6b 63 6f 73 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_29 = {00 00 00 00 74 63 65 6c 65 73 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_30 = {00 00 00 00 65 6d 61 6e 6b 63 6f 73 74 65 67 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_31 = {00 00 00 00 65 6d 61 6e 74 73 6f 68 74 65 67 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_32 = {00 00 00 00 74 65 6b 63 6f 73 65 73 6f 6c 63 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

