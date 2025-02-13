rule Trojan_Win32_GoldDragon_A_2147725909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GoldDragon.A!dha"
        threat_id = "2147725909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GoldDragon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "www.GoldDragon.com" ascii //weight: 5
        $x_5_2 = {00 0d 0a 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 72 65 67 6b 65 79 65 6e 75 6d 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 0d 0a 00}  //weight: 5, accuracy: High
        $x_5_3 = {00 00 00 00 69 6e 6b 2e 69 6e 6b 62 6f 6f 6d 2e 63 6f 2e 6b 72 00 00 00 00}  //weight: 5, accuracy: High
        $x_5_4 = {00 00 00 00 68 6f 73 74 2f 69 6d 67 2f 6a 70 67 2f 70 6f 73 74 2e 70 68 70 00 00 00 00}  //weight: 5, accuracy: High
        $x_5_5 = {00 00 00 00 68 6f 73 74 2f 69 6d 67 2f 6a 70 67 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 00 00 00 00}  //weight: 5, accuracy: High
        $x_5_6 = {00 00 00 00 64 6e 73 61 64 6d 69 6e 00 00 00 00}  //weight: 5, accuracy: High
        $x_5_7 = {00 0d 0a 4e 75 6d 62 65 72 20 6f 66 20 76 61 6c 75 65 73 3a 20 25 64 0d 0a 00}  //weight: 5, accuracy: High
        $x_5_8 = {00 0d 0a 4e 75 6d 62 65 72 20 6f 66 20 73 75 62 6b 65 79 73 3a 20 25 64 0d 0a 00}  //weight: 5, accuracy: High
        $x_5_9 = {00 5c 69 78 65 6f 30 30 30 2e 62 69 6e 00}  //weight: 5, accuracy: High
        $x_5_10 = {00 68 75 70 64 61 74 65 2e 65 78 00}  //weight: 5, accuracy: High
        $x_1_11 = {00 25 73 3f 66 69 6c 65 6e 61 6d 65 3d 25 73 26 63 6f 6e 74 69 6e 75 65 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 0d 0a 2d 2d 2d 2d 2d 2d 57 65 62 4b 69 74 46 6f 72 6d 42 6f 75 6e 64 61 72 79 77 68 70 46 78 4d 42 65 31 39 63 53 6a 46 6e 47 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 54 72 69 64 65 6e 74 2f 34 2e 30 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 29 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 3b 20 62 6f 75 6e 64 61 72 79 3d 2d 2d 2d 2d 57 65 62 4b 69 74 46 6f 72 6d 42 6f 75 6e 64 61 72 79 77 68 70 46 78 4d 42 65 31 39 63 53 6a 46 6e 47 00}  //weight: 1, accuracy: High
        $x_1_15 = {00 2f 63 20 73 79 73 74 65 6d 69 6e 66 6f 20 3e 3e 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_16 = {00 2f 63 20 64 69 72 20 25 73 5c 20 3e 3e 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_17 = {00 2f 63 20 74 61 73 6b 6c 69 73 74 20 3e 3e 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_18 = {00 32 2e 68 77 70 00}  //weight: 1, accuracy: High
        $x_1_19 = {00 68 77 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_20 = {00 5c 76 69 73 6f 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_21 = {00 31 2e 68 77 70 00}  //weight: 1, accuracy: High
        $x_1_22 = {00 5c 48 4e 43 5c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

