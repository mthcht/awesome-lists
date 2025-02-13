rule Worm_Win32_Phorpiex_A_159755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.A"
        threat_id = "159755"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 b4 38 6a 10 8d 54 24 18 52 50 ff d3 46 81 fe f4 01 00 00 7c e9}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 02 75 1e 8a 06 0c 20 3c 61 74 16 3c 62 74 12}  //weight: 1, accuracy: High
        $x_1_3 = {8b c7 99 bd 07 00 00 00 f7 fd 8a 5c 3c 14 8b 44 24 4c 47 0f be 14 02 03 d6 0f b6 c3 03 c2 99 be 28 00 00 00 f7 fe 0f b7 c2 0f b7 f0 8a 44 34 14 32 c3}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 6a 01 6a 00 6a 11 ff d3 6a 00 6a 00 6a 00 6a 56 ff 15 ?? ?? ?? ?? 0f b6 c8 51 ff d3 6a 00 6a 03 6a 2d 6a 11 ff d3 6a 00 6a 00 6a 00 6a 0d ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Phorpiex_B_164473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.B"
        threat_id = "164473"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 09 00 00 00 f7 f9 52 e8 ?? ?? ?? ?? 99 b9 09 00 00 00 f7 f9 52 e8 ?? ?? ?? ?? 99 b9 09 00 00 00 f7 f9 52 e8 ?? ?? ?? ?? 99 b9 09 00 00 00 f7 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 02 75 (1c|19) 8a 06 0c 20 3c 61 74 (14|11) 3c 62 74 (10|0d)}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 0d 68 00 01 00 00 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 10 57 ff d5 6a 00 6a 00 6a 08 57 ff d5 6a 00 6a 00 6a 02 57 ff d5}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b7 c0 3d 01 04 00 00 7f 1f 74 13 83 f8 04 0f 85}  //weight: 1, accuracy: High
        $x_1_5 = {46 81 fe f4 01 00 00 7c d5 33 f6 8b 44 b4 38 6a 10 8d 54 24 18 52 50 ff d3 46 81 fe f4 01 00 00 7c e9}  //weight: 1, accuracy: High
        $x_1_6 = {8d 46 01 99 be 28 00 00 00 f7 fe bb 28 00 00 00 41 0f b7 c2 0f b7 f0 0f b6 44 34 14 03 c7 99 bf 28 00 00 00 f7 ff 0f b7 c2 0f b7 f8}  //weight: 1, accuracy: High
        $x_1_7 = {84 c9 74 0c 8a 4e 01 8a 5a 01 46 42 32 d9 74 f0 80 3a 00 74 0f}  //weight: 1, accuracy: High
        $x_1_8 = {f7 de 1b f6 8b 44 b3 0c 83 c6 04 80 38 23 74 22 8b 03 6a 21 50 e8}  //weight: 1, accuracy: High
        $x_1_9 = {83 7d 08 10 76 13 e8 ?? ?? ?? ?? 99 b9 0d 00 00 00 f7 f9 83 c2 03}  //weight: 1, accuracy: Low
        $x_1_10 = {25 73 5c 72 6d 72 66 25 69 25 69 25 69 25 69 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {3a 20 61 74 74 61 63 68 6d 65 6e 74 3b 20 66 69 6c 65 6e 61 6d 65 3d 20 22 49 4d 47 00 2d 4a 50 47 2e 7a 69 70}  //weight: 1, accuracy: High
        $x_1_12 = {49 4d 47 25 73 2d 4a 50 47 2e 73 63 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Phorpiex_Q_177620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.Q"
        threat_id = "177620"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 80 00 00 00 8d 84 24 b4 00 00 00 50 6a 0c 8d 4c 24 20 51 68 00 14 2d 00 57 ff 15 ?? ?? ?? ?? 85 c0 74 6b 8b 94 24 b8 00 00 00 8a 84 14 a8 00 00 00 8d 94 14 a8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 ff 03 00 00 8d 94 24 ?? ?? 00 00 52 56 ff d3 85 c0 75 cc 8b 6c 24 14 56 8b 35 ?? ?? 40 00 ff d6 55 ff d6 57}  //weight: 1, accuracy: Low
        $x_1_3 = {51 6a 62 8d 54 24 ?? 52 55 ff d3 85 c0 74 ?? 57 90 83 7c 24 ?? 00 74 ?? 33 ff 80 7c 24 ?? 00 74}  //weight: 1, accuracy: Low
        $x_1_4 = {71 65 6d 75 00 00 00 00 76 69 72 74 75 61 6c 00 76 6d 77 61 72 65 00 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 62 69 65 44 6c 6c 2e 64 6c 6c 00 53 62 69 65 44 6c 6c 58 2e 64 6c 6c 00 00 00 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 5c 25 73 2e 65 78 65 00 00 00 6f 70 65 6e 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Phorpiex_A_186324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.gen!A"
        threat_id = "186324"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 14 2d 00 57 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 8b 94 24 ?? 00 00 00 8a 84 14 ?? 00 00 00 8d 94 14 ?? 00 00 00 84 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {01 00 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 0f 85 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d6 85 c0 0f 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d6 85 c0 0f 85 02 00 68 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Phorpiex_P_186671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.P"
        threat_id = "186671"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 0a 00 00 00 f7 f9 52 56 68 ?? ?? ?? ?? 56 (ff d3|e8 ?? ?? ?? ??) 83 c4 10 83 ef 01 75 ?? 5f c6 46}  //weight: 1, accuracy: Low
        $x_1_2 = {80 38 00 74 ?? 50 8d 44 24 ?? 50 (ff d7|e8 ?? ?? ?? ??) 83 c4 08 85 c0 75 ?? 46 83 fe 03 72}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Phorpiex_S_195254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.S"
        threat_id = "195254"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 4e 6a 00 6a 00 6a 00 6a 11 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 56 e8 ?? ?? ?? ?? 6a 00 6a 02 6a 00 6a 56 e8 ?? ?? ?? ?? 6a 00 6a 02 6a 00 6a 11 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {54 43 68 61 74 52 69 63 68 45 64 69 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "images.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Phorpiex_T_195317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.T"
        threat_id = "195317"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 c1 e8 10 25 ff 7f 00 00 25 03 00 00 80 79 05 48 83 c8 fc 40 8b 4c 84 ?? 51 8d 54 24 ?? 52 e9}  //weight: 2, accuracy: Low
        $x_1_2 = {83 c0 02 83 c1 02 84 d2 75 ?? 33 c0 eb 05 1b c0 83 d8 ff 85 c0 74 ?? 8d 4c 24 ?? 51 56 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {25 73 5c 72 6d 72 66 25 69 25 69 25 69 25 69 2e 62 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Phorpiex_V_195696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.V"
        threat_id = "195696"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 83 c4 04 c6 06 00 ff [0-5] 50 e8 ?? ?? ?? ?? 83 c4 04 [0-21] 99 b9 0a 00 00 00 f7 f9 52 56 68}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f0 83 c4 04 88 1e ff [0-5] 50 e8 ?? ?? ?? ?? 83 c4 04 [0-21] 99 b9 0a 00 00 00 f7 f9 52 56 68}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 07 00 00 00 be ?? ?? ?? ?? 8d 7c 24 ?? f3 a5 66 a5 8d 84 24 ?? ?? 00 00 50 68 04 01 00 00 a4 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {25 73 5c 25 73 2e 65 78 65 00 00 0a 00 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {00 25 73 25 64 00 00 [0-80] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 55 73 65 72 73 5c 73 5c 44 65 73 6b 74 6f 70 5c 47 65 74 5c 52 65 6c 65 61 73 65 5c 47 4c 6f 61 64 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_7 = {50 61 69 6e 74 00 00 00 41 6e 20 75 6e 64 65 66 69 6e 65 64 20 65 72 72 6f 72 20 68 61 73 20 6f 63 63 75 72 72 65 64 20 2d 20 25 75 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Phorpiex_W_198451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.W"
        threat_id = "198451"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 25 73 5c 25 73 25 69 25 69 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 44 6f 77 6e 6c 6f 61 64 5d 3a [0-16] 5b 4d 61 69 6e 5d 3a}  //weight: 1, accuracy: Low
        $x_10_3 = {81 39 50 45 00 00 0f 85 ?? ?? ?? ?? 8b 7d 0c 8b 81 a0 00 00 00 2b 79 34 8b 91 a4 00 00 00 03 c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Phorpiex_X_200278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.X"
        threat_id = "200278"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\winsvcon.txt" ascii //weight: 1
        $x_1_2 = {80 f9 30 7c 1f 80 f9 39 7f 1a 0f be c9 83 f1 30 8d 14 92 46 8d 14 51 8a 0e bf 01 00 00 00 84 c9 75 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Phorpiex_Y_203702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.Y"
        threat_id = "203702"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 02 83 c1 02 84 d2 75 ?? 33 c0 eb 05 1b c0 83 d8 ff 85 c0 74 ?? 8d 4c 24 ?? 51 56 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {25 73 5c 72 6d 72 66 25 69 25 69 25 69 25 69 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 48 6f 6d 65 5c 43 6f 64 65 5c 53 6b 79 70 65 72 [0-2] 5c 52 65 6c 65 61 73 65 5c 53 6b 79 70 65 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 78 5c 44 65 73 6b 74 6f 70 5c 48 6f 6d 65 5c 43 6f 64 65 5c 49 4d 77 6f 72 6d [0-2] 5c 52 65 6c 65 61 73 65 5c 53 6b 79 70 65 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_5 = "TZapCommunicator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Phorpiex_AB_204549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.AB"
        threat_id = "204549"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 0c 56 ff d3 8b 3d ?? ?? ?? ?? 6a 64 ff d7 6a 00 6a 0d 68 00 01 00 00 56 ff d3 6a 64 ff d7 6a 00 68 ?? ?? ?? ?? ff d5 5f 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 20 03 00 00 eb 03 8d 49 00 6a 00 6a 26 68 00 01 00 00 56 ff d7 83 eb 01 75 ef}  //weight: 1, accuracy: High
        $x_1_3 = "tSkMainForm.UnicodeClass" ascii //weight: 1
        $x_1_4 = {5c 55 73 65 72 73 5c 73 5c 44 65 73 6b 74 6f 70 5c 53 6b 79 70 65 72 [0-3] 5c 52 65 6c 65 61 73 65 5c 53 6b 79 70 65 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Phorpiex_AC_208343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.AC"
        threat_id = "208343"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 14 2d 00 57 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 8b 94 24 ?? 00 00 00 8a 84 14 ?? 00 00 00 8d 94 14 ?? 00 00 00 84 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {01 00 00 ff d5 e8 ?? ?? ?? ?? 84 c0 0f 85 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d6 85 c0 0f 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d6 85 c0 0f 85 02 00 68 90}  //weight: 1, accuracy: Low
        $x_1_3 = "tSkMainForm.UnicodeClass" ascii //weight: 1
        $x_1_4 = {71 65 6d 75 00 00 00 00 76 69 72 74 75 61 6c 00 76 6d 77 61 72 65 00 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Phorpiex_SKA_226022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.SKA"
        threat_id = "226022"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 f4 01 00 00 ff 15 ?? ?? 41 00 e8 ?? ?? ?? ?? 0f b6 c0 85 c0 75 1e 68 ?? ?? 41 00 ff 15 ?? ?? 41 00 85 c0 75 0f 68 ?? ?? 41 00 ff 15 ?? ?? 41 00 85 c0 74 08}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e8 03 00 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f b6 c0 85 c0 75 1e 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 75 0f 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 74 08}  //weight: 1, accuracy: Low
        $x_1_3 = {53 62 69 65 44 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 62 69 65 44 6c 6c 58 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {74 53 6b 4d 61 69 6e 46 6f 72 6d 2e 55 6e 69 63 6f 64 65 43 6c 61 73 73 00}  //weight: 1, accuracy: High
        $x_10_6 = {5c 49 4d 77 6f 72 6d 5c 52 65 6c 65 61 73 65 5c 53 6b 79 70 65 2e 70 64 62 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Phorpiex_SKC_226425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.SKC"
        threat_id = "226425"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Interop.SKYPE4COMLib.dll" wide //weight: 1
        $x_1_2 = "68747470733A2F2F696E666F726D6163696F6E373637362E776F726470726573732E636F6D" wide //weight: 1
        $x_1_3 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 65 00 78 00 65 00 ?? ?? 5c 00 4a 00 61 00 76 00 61 00 2e 00 65 00 78 00 65 00 ?? ?? 5c 00 41 00 64 00 6f 00 62 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_10_4 = "\\Nte\\Nte\\bin\\Release\\hola.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Phorpiex_C_241594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.C!bit"
        threat_id = "241594"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 4d 10 99 f7 f9 0f b6 54 15 c8 8b 45 0c 0f be 08 33 d1 8b 45 0c 88 10 8b 4d 0c 83 c1 01 89 4d 0c e9 37 ff ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {83 7d 08 10 76 13 e8 ?? ?? ?? ?? 99 b9 0d 00 00 00 f7 f9 83 c2 03}  //weight: 5, accuracy: Low
        $x_2_3 = "autorun.inf" wide //weight: 2
        $x_2_4 = ":Zone.Identifier" wide //weight: 2
        $x_2_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_1_6 = "qemu" wide //weight: 1
        $x_1_7 = "vmware" wide //weight: 1
        $x_1_8 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Phorpiex_AF_252213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.AF!bit"
        threat_id = "252213"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%stldr.php?new=1" ascii //weight: 1
        $x_1_2 = "%stldr.php?on=1" ascii //weight: 1
        $x_1_3 = "\\winsvcs.txt" wide //weight: 1
        $x_1_4 = "/c start _ & _\\DeviceManager.exe & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Phorpiex_BS_257022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.BS!MTB"
        threat_id = "257022"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://92.63.197.153/" wide //weight: 1
        $x_1_2 = "%ls\\%d%d.exe" wide //weight: 1
        $x_1_3 = "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\WindowsDefender.exe" wide //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Phorpiex_AJY_289222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phorpiex.AJY!MSR"
        threat_id = "289222"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://worm.ws/" ascii //weight: 1
        $x_1_2 = "http://seuufhehfueughek.ws/" ascii //weight: 1
        $x_1_3 = "http://tsrv4.ws/" ascii //weight: 1
        $x_1_4 = "%s\\%s\\DriveMgr.exe" wide //weight: 1
        $x_1_5 = "/c start __ & __\\DriveMgr.exe & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

