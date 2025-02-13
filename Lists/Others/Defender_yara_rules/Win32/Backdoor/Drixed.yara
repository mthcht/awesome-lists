rule Backdoor_Win32_Drixed_A_2147689612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.A"
        threat_id = "2147689612"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 cb 75 01 46 40 3b 75 08 7c ef 8d 88 ?? ?? ?? ?? 8a 01 3a c3 74 16 8b f1 8a d8 32 5d ff 8b c7 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {65 64 67 00 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 65 00 63 6d 64 2e 65 78 65 00 20 63 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 66 67 00 3c 00 63 6f 6e 66 69 67 20 62 ee 74 f0 65 e6 3d}  //weight: 1, accuracy: High
        $x_1_5 = {66 6f 72 6d 67 72 61 62 62 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {63 6c 69 63 6b 73 68 6f 74 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 74 74 70 69 6e 6a 65 63 74 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {6b 65 79 6c 6f 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Drixed_C_2147690082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.C"
        threat_id = "2147690082"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 63 6f 6e 6e 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 6f 74 5f 69 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 6f 74 5f 78 33 32 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 6c 69 63 6b 73 68 6f 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 74 74 70 73 68 6f 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {4e 6f 74 69 66 69 65 72 49 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {72 65 71 75 65 73 74 5f 75 72 69 00}  //weight: 1, accuracy: High
        $x_1_8 = {73 6f 63 6b 73 5f 78 33 32 00}  //weight: 1, accuracy: High
        $x_1_9 = {76 6e 63 5f 78 33 32 00}  //weight: 1, accuracy: High
        $x_1_10 = {76 6e 63 63 6f 6e 6e 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {56 6e 63 53 74 61 72 74 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_12 = {56 6e 63 53 74 6f 70 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_13 = {77 6f 72 6b 65 72 5f 78 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_14 = {7c 45 58 49 53 54 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_15 = {7c 4e 4f 4e 45 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_16 = {69 00 65 00 2e 00 7a 00 69 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = {73 00 6f 00 6c 00 2e 00 7a 00 69 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = {63 00 68 00 2e 00 63 00 61 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_19 = {66 00 66 00 2e 00 63 00 61 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_20 = {30 0c 3e 46 3b b0 ?? ?? 00 00 72 f1 33 c9 8d 45 ?? 50 8b 45 ?? 51 8d b0 00 08 00 00 56 50 51 51 89 4d ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_21 = {8b 45 fc 8b 4d 0c 03 c2 50 e8 ?? ?? ?? ?? 52 8b cb 8b f8 e8 ?? ?? ?? ?? 8a 00 30 07 42 3b 55 08 7c de}  //weight: 1, accuracy: Low
        $x_1_22 = {8b 43 04 8d 5c 03 10 81 3b ef be ad de 74 df eb 04 85 db 75 1d 0f b7 46 06}  //weight: 1, accuracy: High
        $x_1_23 = {81 be 00 04 00 00 ef be ad de 89 35 ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? b8 00 04 00 00 8d 4c 24 10}  //weight: 1, accuracy: Low
        $x_1_24 = {8a 0f 80 f9 23 0f 84 ?? ?? ?? ?? 80 f9 61 74 ?? 80 f9 67 74 ?? 80 f9 6c 74 ?? 80 f9 71 0f 85}  //weight: 1, accuracy: Low
        $x_1_25 = {47 8a 0f 80 f9 6d 75 ?? 47 80 3f 70 0f 85 ?? ?? ?? ?? 47 80 3f 3b 0f 85 ?? ?? ?? ?? c6 03 26 8d 4f 01}  //weight: 1, accuracy: Low
        $x_1_26 = {80 3f 43 75 ?? 47 80 3f 44 75 ?? 47 80 3f 41 75 ?? 47 80 3f 54 75 ?? 47 80 3f 41}  //weight: 1, accuracy: Low
        $x_1_27 = {80 7f 01 4f 75 ?? 80 7f 02 43 75 ?? 80 7f 03 54 75 ?? 80 7f 04 59 75 ?? 80 7f 05 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Backdoor_Win32_Drixed_C_2147691906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.C!!Drixed.gen!A"
        threat_id = "2147691906"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        info = "Drixed: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 63 6f 6e 6e 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 6f 74 5f 69 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 6f 74 5f 78 33 32 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 6c 69 63 6b 73 68 6f 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 74 74 70 73 68 6f 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {4e 6f 74 69 66 69 65 72 49 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {72 65 71 75 65 73 74 5f 75 72 69 00}  //weight: 1, accuracy: High
        $x_1_8 = {73 6f 63 6b 73 5f 78 33 32 00}  //weight: 1, accuracy: High
        $x_1_9 = {76 6e 63 5f 78 33 32 00}  //weight: 1, accuracy: High
        $x_1_10 = {76 6e 63 63 6f 6e 6e 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {56 6e 63 53 74 61 72 74 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_12 = {56 6e 63 53 74 6f 70 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_13 = {77 6f 72 6b 65 72 5f 78 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_14 = {7c 45 58 49 53 54 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_15 = {7c 4e 4f 4e 45 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_16 = {69 00 65 00 2e 00 7a 00 69 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = {73 00 6f 00 6c 00 2e 00 7a 00 69 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = {63 00 68 00 2e 00 63 00 61 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_19 = {66 00 66 00 2e 00 63 00 61 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_20 = {30 0c 3e 46 3b b0 ?? ?? 00 00 72 f1 33 c9 8d 45 ?? 50 8b 45 ?? 51 8d b0 00 08 00 00 56 50 51 51 89 4d ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_21 = {8b 45 fc 8b 4d 0c 03 c2 50 e8 ?? ?? ?? ?? 52 8b cb 8b f8 e8 ?? ?? ?? ?? 8a 00 30 07 42 3b 55 08 7c de}  //weight: 1, accuracy: Low
        $x_1_22 = {8b 43 04 8d 5c 03 10 81 3b ef be ad de 74 df eb 04 85 db 75 1d 0f b7 46 06}  //weight: 1, accuracy: High
        $x_1_23 = {81 be 00 04 00 00 ef be ad de 89 35 ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? b8 00 04 00 00 8d 4c 24 10}  //weight: 1, accuracy: Low
        $x_1_24 = {8a 0f 80 f9 23 0f 84 ?? ?? ?? ?? 80 f9 61 74 ?? 80 f9 67 74 ?? 80 f9 6c 74 ?? 80 f9 71 0f 85}  //weight: 1, accuracy: Low
        $x_1_25 = {47 8a 0f 80 f9 6d 75 ?? 47 80 3f 70 0f 85 ?? ?? ?? ?? 47 80 3f 3b 0f 85 ?? ?? ?? ?? c6 03 26 8d 4f 01}  //weight: 1, accuracy: Low
        $x_1_26 = {80 3f 43 75 ?? 47 80 3f 44 75 ?? 47 80 3f 41 75 ?? 47 80 3f 54 75 ?? 47 80 3f 41}  //weight: 1, accuracy: Low
        $x_1_27 = {80 7f 01 4f 75 ?? 80 7f 02 43 75 ?? 80 7f 03 54 75 ?? 80 7f 04 59 75 ?? 80 7f 05 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Backdoor_Win32_Drixed_E_2147693155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.E"
        threat_id = "2147693155"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 e0 93 04 00 85 d2 74 05 b8}  //weight: 1, accuracy: High
        $x_1_2 = {7e 02 8b f0 85 db 7e 08 8b c8 2b ce 3b d9 7e 04 2b c6 8b d8 85 db 7f 0e}  //weight: 1, accuracy: High
        $x_1_3 = {50 ff d6 89 45 08 39 7d 08 75 24 8b 45 fc 39 78 18 74 08 8b 40 18 8b 40 04 89 03 68 d1 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 0d 6a 10 8d 4d ec 51 ff 36 ff d0 89 45 fc 83 7d fc 00 74 13 c7}  //weight: 1, accuracy: High
        $x_1_5 = {eb 02 33 c0 89 43 04 6a 7c 8d 45 dc 50 6a 0e 8d 45 f0 e8}  //weight: 1, accuracy: High
        $x_2_6 = {32 5c 0d f4 41 88 5c 0d eb 83 f9 08 72 ef 8b 5d 08 33 ff 8a 4c 3d ec 84 c9 75 10 ff 45 fc 39 5d fc}  //weight: 2, accuracy: High
        $x_1_7 = {33 c0 66 8b 54 05 f8 66 33 17 83 c0 02 66 89 54 05 ee 83 c7 02 83 f8 08 72 e8 33 d2 0f}  //weight: 1, accuracy: High
        $x_1_8 = {80 79 05 61 75 25 80 79 04 74 75 1f 80 79 03 61 75 19 80 79 02 64 75 13 80 79 01 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Drixed_F_2147694148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.F"
        threat_id = "2147694148"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 1c 08 32 5c 0d f4 41 88 5c 0d eb 83 f9 08 72 ef 8b 5d 08 33 ff 8a 4c 3d ec 84 c9 75 10}  //weight: 3, accuracy: High
        $x_3_2 = {66 8b 54 05 f8 66 33 17 83 c0 02 66 89 54 05 ee 83 c7 02 83 f8 08 72 e8 33 d2 0f b7 44 55 f0}  //weight: 3, accuracy: High
        $x_1_3 = {59 56 68 00 32 80 00 56 56 56 68 ?? ?? ?? ?? 8b f8 8b 45 fc 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 ff d7}  //weight: 1, accuracy: Low
        $x_1_4 = {50 00 4f 00 53 00 54 00 00 00 00 00 2f 00 00 00 00 00 00 00 30 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b 40 14 83 f8 02 7c ?? 83 f8 05 7e ?? 83 f8 06 75}  //weight: 1, accuracy: Low
        $x_1_6 = {80 79 05 61 75 ?? 80 79 04 74 75 ?? 80 79 03 61 75 ?? 80 79 02 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Drixed_G_2147696461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.G"
        threat_id = "2147696461"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 5c d6 10 8b 6c d6 14 33 d8 89 5c 24 [0-1] 33 ef 89 7c 24 [0-1] 89 6c 24 [0-1] 8b e9 89 04 24 8b 74 24 [0-1] 8b 4c 24 [0-1] 8b 5c 24 [0-1] 8b 7c 24 [0-1] 0f be 44 2c [0-1] 85 c0 75 07 46 3b f7 7f 12 eb 08 3b f7 75 04 88 04 19 41 45 83 fd 08 72 e2 eb 9d}  //weight: 10, accuracy: Low
        $x_1_2 = {8b d7 c1 ea 02 f7 c7 03 00 00 00 8d 4a 01 0f 45 d1 85 d2 7e 08 31 34 98 43 3b da 7c f8}  //weight: 1, accuracy: High
        $x_1_3 = {0f 5e 73 82 ea 5e 73 82 ee bf f3 80 43 3d 1c ec 19 37 6e e5 5f 3c ad f6 63 3b b4 bf 5d 6c 64 b2 3f 60 7e 88 5f de 4f f1 67 3b 01 f4 79 01 1f fb 16 3e 07 a7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Drixed_D_2147696755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.D"
        threat_id = "2147696755"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 82 00 00 00 e8 ?? ?? ?? ?? 59 6a 40 68 00 30 00 00 68 60 28 00 00 53 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {c9 c3 6a 36 e8 ?? ?? ?? ?? 59 ff e0 6a 2b e8 ?? ?? ?? ?? 59 ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 28 00 00 57 e8 ?? ?? ?? ?? 6a 36 e8 ?? ?? ?? ?? 83 c4 0c 68 86 00 00 00 89 85 ?? ?? ff ff e8 ?? ?? ?? ?? 59 6a 76 89 85 ?? ?? ff ff e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Drixed_D_2147696755_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.D"
        threat_id = "2147696755"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 83 00 00 00 e8 ?? ?? ?? ?? 59 6a 40 68 00 30 00 00 68 60 28 00 00 53 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {c9 c3 6a 37 e8 ?? ?? ?? ?? 59 ff e0 6a 2c e8 ?? ?? ?? ?? 59 ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 28 00 00 57 e8 ?? ?? ?? ?? 6a 37 e8 ?? ?? ?? ?? 83 c4 0c 68 87 00 00 00 89 85 ?? ?? ff ff e8 ?? ?? ?? ?? 59 6a 77 89 85 ?? ff ff ff e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Drixed_I_2147706797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.I"
        threat_id = "2147706797"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 37 00 00 00 e8 ?? ?? ?? ?? 89 44 ?? ?? b8 87 00 00 00 e8 ?? ?? ?? ?? 89 44 ?? ?? b8 77 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 83 00 00 00 89 8c ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 40 68 00 30 00 00 68 60 28 00 00 6a 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 36 58 e8 ?? ?? ?? ?? 6a 00 ff 33 ff d0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Drixed_J_2147707069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.J"
        threat_id = "2147707069"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 18 b8 54 00 00 00 e8 ?? ?? 00 00 57 6a 08 ff 35 ?? ?? ?? 00 ff d0 59 5f c3 b8 52 00 00 00 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {80 7a 06 00 75 28 80 7a 05 61 75 22 80 7a 04 74 75 1c 80 7a 03 61 75 16 80 7a 02 64 75 10 80 7a 01 73 75 0a 80 3a 2e 75 05}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 53 6a 00 68 01 00 10 00 ff d0 8b f0 85 f6 74 04 33 ff eb bd e8 ?? ?? 00 00 b8 62 00 00 00 e8 ?? ?? 00 00 08 00 b8 62 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Drixed_M_2147707659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.M"
        threat_id = "2147707659"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 5c d6 10 8b 6c d6 14 33 d8 89 5c 24 10 33 ef 89 7c 24 04 89 6c 24 14 8b e9 89 04 24}  //weight: 4, accuracy: High
        $x_1_2 = {8b 44 cf 10 8b 7c cf 14 33 44 24 0c 33 7c 24 08 89 04 24 33 c0 89 7c 24 04 0f b7 3c 44}  //weight: 1, accuracy: High
        $x_4_3 = {68 00 80 00 00 6a 00 ff b0 1c 04 00 00 68 34 12 00 00 ff b0 20 07 00 00 ff e2}  //weight: 4, accuracy: High
        $x_4_4 = {74 0b 41 be 45 84 00 00 e9 a4 00 00 00 b9 96 69 00 00 41 be 45 84 00 00 49 8b 97 18 04 00 00}  //weight: 4, accuracy: High
        $x_1_5 = {8b 4c 24 04 8b 3c 24 8b 5c 24 2c 8b 74 d3 14 8b 44 d3 10 33 f1 89 74 24 14 33 c7 89 3c 24 89 44 24 10 8b c5 8b 6c 24 0c 8b 4c 24 08 8b 74 24 34 8b 7c 24 30 0f b7 5c 44 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Drixed_P_2147717987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.P"
        threat_id = "2147717987"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 ff 2d c4 25 b9 89}  //weight: 1, accuracy: High
        $x_1_2 = {81 ff 9a 07 e2 13 89}  //weight: 1, accuracy: High
        $x_1_3 = {b9 4d ac 70 b2 ba c9 3c 60 a6 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Drixed_Q_2147724634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drixed.Q"
        threat_id = "2147724634"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 9d 3a a3 9c b9 87 c2 cc 0c e8}  //weight: 1, accuracy: High
        $x_1_2 = {ba cd df 66 92 b9 87 c2 cc 0c e8}  //weight: 1, accuracy: High
        $x_1_3 = {ba 60 86 f7 a7 b9 2a 9f e2 75 e8}  //weight: 1, accuracy: High
        $x_1_4 = {ba f0 ff 84 bc b9 2a 9f e2 75 e8}  //weight: 1, accuracy: High
        $x_1_5 = {ba 5d 6c d0 60 b9 2a 9f e2 75 e8}  //weight: 1, accuracy: High
        $x_1_6 = {ba 59 65 1d ad b9 2a 9f e2 75 e8}  //weight: 1, accuracy: High
        $x_1_7 = {ba c6 0c 71 2d b9 2a 9f e2 75 e8}  //weight: 1, accuracy: High
        $x_1_8 = {ba c9 e9 34 2b b9 f2 4f ed f4 e8}  //weight: 1, accuracy: High
        $x_1_9 = {bf b1 f6 38 f8 bb f2 4f ed f4}  //weight: 1, accuracy: High
        $x_1_10 = "dll loaded, run?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

