rule Trojan_Win32_RedLeaves_C_2147730368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLeaves.C!dha"
        threat_id = "2147730368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLeaves"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 20 00 4d 00 53 00 49 00 45 00 20 00 38 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 36 00 2e 00 31 00 3b 00 20 00 57 00 4f 00 57 00 36 00 34 00 3b 00 20 00 54 00 72 00 69 00 64 00 65 00 6e 00 74 00 2f 00 34 00 2e 00 30 00 3b 00 20 00 53 00 4c 00 43 00 43 00 32 00 3b 00 20 00 2e 00 4e 00 45 00 54 00 20 00 43 00 4c 00 52 00 20 00 32 00 2e 00 30 00 2e 00 35 00 30 00 37 00 32 00 37 00 3b 00 20 00 2e 00 4e 00 45 00 54 00 20 00 43 00 4c 00 52 00 20 00 33 00 2e 00 35 00 2e 00 33 00 30 00 37 00 32 00 39 00 3b 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 00 65 00 74 00 2d 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 3a 00 5c 00 62 00 2a 00 7b 00 2e 00 2b 00 3f 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 20 00 7b 00 5b 00 30 00 2d 00 39 00 5d 00 2b 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 4c 00 65 00 6e 00 67 00 74 00 68 00 3a 00 20 00 7b 00 5b 00 30 00 2d 00 39 00 5d 00 2b 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 00 68 00 61 00 72 00 73 00 65 00 74 00 3d 00 7b 00 5b 00 41 00 2d 00 5a 00 61 00 2d 00 7a 00 30 00 2d 00 39 00 5c 00 2d 00 5f 00 5d 00 2b 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5f 00 5f 00 64 00 61 00 74 00 61 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {5f 00 5f 00 73 00 65 00 72 00 69 00 61 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {5f 00 5f 00 75 00 70 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {73 65 6c 65 63 74 20 68 6f 73 74 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 20 66 72 6f 6d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 20 77 68 65 72 65 20 68 6f 73 74 6e 61 6d 65 20 6c 69 6b 65 20 22 6d 6f 7a 2d 70 72 6f 78 79 3a 2f 2f 25 73 25 25 22 3b 00}  //weight: 1, accuracy: High
        $x_1_10 = {6b 53 4f 46 54 57 41 52 45 5c 4d 6f 7a 69 6c 6c 61 5c 4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 00}  //weight: 1, accuracy: High
        $x_1_11 = {28 00 4e 00 54 00 20 00 25 00 64 00 2e 00 25 00 64 00 20 00 42 00 75 00 69 00 6c 00 64 00 20 00 25 00 64 00 29 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_5_12 = {49 6e 69 74 7c 00 44 6f 77 6e 00 00 52 65 73 65 74 00 4c 69 73 74 65 6e 00 00 49 64 6c 65 00 00 43 6f 6e 6e 65 63 74 51 75 65 72 79 00 00 53 68 61 64 6f 77 00 00}  //weight: 5, accuracy: High
        $x_5_13 = {44 69 73 63 6f 6e 6e 65 63 74 65 64 00 00 43 6f 6e 6e 65 63 74 65 64 00 41 63 74 69 76 65 00 00 3d 2a 00 00 4c 6f 67 6f 6e 55 73 65 72 4e 61 6d 65 00 53 65 73 73 69 6f 6e 49 64 00 57 69 6e 53 74 61 74 69 6f 6e 4e 61 6d 65 00 00 53 74 61 74 65}  //weight: 5, accuracy: High
        $x_1_14 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 4e 00 61 00 6d 00 65 00 50 00 69 00 70 00 65 00 5f 00 4d 00 6f 00 72 00 65 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_5_15 = {52 00 65 00 64 00 4c 00 65 00 61 00 76 00 65 00 73 00 43 00 4d 00 44 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 6f 00 72 00 4d 00 75 00 74 00 65 00 78 00 00 00}  //weight: 5, accuracy: High
        $x_1_16 = {49 20 63 61 6e 20 6e 6f 74 20 73 74 61 72 74 20 25 73 00 00}  //weight: 1, accuracy: High
        $x_5_17 = {52 00 4c 00 5f 00 43 00 50 00 47 00 75 00 69 00 64 00 00 00}  //weight: 5, accuracy: High
        $x_1_18 = {63 00 6c 00 69 00 65 00 6e 00 74 00 70 00 61 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_19 = {73 00 65 00 72 00 76 00 65 00 72 00 70 00 61 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_5_20 = {52 65 76 65 72 73 65 49 70 50 6f 72 74 00}  //weight: 5, accuracy: High
        $x_1_21 = {52 65 76 65 72 73 65 49 70 41 64 64 72 00}  //weight: 1, accuracy: High
        $x_1_22 = {64 77 43 6f 6e 6e 65 63 74 50 6f 72 74 00}  //weight: 1, accuracy: High
        $x_5_23 = {64 77 52 65 6d 6f 74 65 4c 61 6e 50 6f 72 74 00}  //weight: 5, accuracy: High
        $x_5_24 = {73 74 72 52 65 6d 6f 74 65 4c 61 6e 41 64 64 72 65 73 73 00}  //weight: 5, accuracy: High
        $x_5_25 = {73 74 72 4c 6f 63 61 6c 43 6f 6e 6e 65 63 74 49 70 00}  //weight: 5, accuracy: High
        $x_1_26 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 00 00}  //weight: 1, accuracy: High
        $x_5_27 = {43 00 3a 00 00 00 00 00 45 00 72 00 72 00 6f 00 72 00 21 00 00 00 00 00}  //weight: 5, accuracy: High
        $x_5_28 = {73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 76 00 65 00 72 00 63 00 6f 00 64 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_5_29 = {72 65 64 5f 61 75 74 75 6d 6e 61 6c 5f 6c 65 61 76 65 73 5f 64 6c 6c 6d 61 69 6e 2e 64 6c 6c 00 00}  //weight: 5, accuracy: High
        $x_5_30 = {2e 3f 41 56 4d 44 35 5f 43 54 58 40 40 00}  //weight: 5, accuracy: High
        $x_5_31 = {2e 3f 41 56 68 74 74 70 40 63 74 78 40 40 00}  //weight: 5, accuracy: High
        $x_5_32 = {2e 3f 41 56 43 6d 64 52 65 64 69 72 65 63 74 6f 72 40 40 00}  //weight: 5, accuracy: High
        $x_3_33 = {2e 3f 41 56 49 43 6f 6d 6d 40 40 00}  //weight: 3, accuracy: High
        $x_3_34 = {2e 3f 41 56 48 74 74 70 43 6f 6d 6d 40 40 00}  //weight: 3, accuracy: High
        $x_5_35 = {2e 3f 41 56 50 6f 72 74 4d 61 70 70 69 6e 67 53 6c 61 76 65 40 40 00}  //weight: 5, accuracy: High
        $x_3_36 = {2e 3f 41 56 54 63 70 43 6f 6d 6d 40 40 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RedLeaves_E_2147730369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLeaves.E!dha"
        threat_id = "2147730369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLeaves"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4b 04 3b 4b 08 75 4c 83 fa 20 73 1e bb 00 00 00 80 8b ca d3 eb 8d 4c 02 04 f7 d3 21 5c b8 44 fe 09 75 28 8b 4d 08 21 19 eb 21 8d 4a e0 bb 00 00 00 80 d3 eb 8d 4c 02 04 f7 d3 21 9c b8 c4 00 00 00 fe 09 75 06 8b 4d 08 21 59 04 8b 4d fc 8b 5d 0c eb 03}  //weight: 1, accuracy: High
        $x_10_2 = {55 8b ec 51 56 57 33 c0 b1 ?? 8a ?? ?? ?? ?? ?? 32 d1 88 ?? ?? ?? ?? ?? 40 3d ?? ?? ?? 00 7c ea 6a 40 68 00 10 00 00 68 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? ?? 85 c0 89 45 fc 75 08 5f 5e 8b e5 5d c2 04 00 b9 ?? ?? ?? 00 be ?? ?? ?? ?? 8b f8 f3 a5 [0-9] 8b ?? fc ?? ?? ff d0 5f b8 01 00 00 00 5e 8b e5 5d c2 04 00}  //weight: 10, accuracy: Low
        $x_10_3 = {c7 45 f8 00 00 00 00 eb 09 8b 45 f8 83 c0 01 89 45 f8 81 7d f8 ?? ?? ?? ?? 73 17 8b 4d f8 8a 91 ?? ?? ?? ?? 80 f2 40 8b 45 f8 88 90 ?? ?? ?? ?? eb d7 6a 40 68 00 10 00 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 89 45 fc 83 7d fc 00 75 04 33 c0 eb 32 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 4d fc 51 e8 ?? ?? ?? ?? 83 c4 0c 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c c1 c8 07 8b 45 fc ff d0 5f 5e 5b 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_1_4 = {57 8b 56 10 83 fa ff 0f 84 9f 00 00 00 8b 7e 08 8d 8e 18 20 00 00 8b c7 2b c6 83 e8 18 c1 f8 03 c1 e0 0c 03 c2 3b f9 89 45 fc 73 3a 8b 0f 8b 5d 08 3b cb 7c 1a 39 5f 04 76 15 53 51 50 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 75 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

