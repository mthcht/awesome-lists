rule Ransom_Win32_Tobfy_A_2147658778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.A"
        threat_id = "2147658778"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 ff d6 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 6a 01 ff d6 a1 ?? ?? ?? ?? 6a 00 6a 00 68 04 02 00 00 50 ff d7 eb a5}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d7 6a 00 6a 02 8b f8 ff d3 8b f0 83 fe ff 74 ?? 8d 44 24 ?? 50 56 c7 44 24 ?? 28 01 00 00 ff d5 85 c0 74 ?? 8b 5c 24 ?? 8d 4c 24 ?? 51 56 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tobfy_B_2147659097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.B"
        threat_id = "2147659097"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 c9 0d 66 19 00 81 c1 5f f3 6e 3c 30 0c 3e}  //weight: 1, accuracy: High
        $x_1_2 = {f0 0d cd 27 b1 91 89 82 6d af c6 bb c8 bf 88 64 f0 38 24 19 c6 d6 39 52 6e 09 78 6b c5 08 7f 6d e6 a1 b9 86 d3 38 ec 33 8c 45 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tobfy_F_2147664042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.F"
        threat_id = "2147664042"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 73 6e 61 70 7a 2e 64 69 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 67 65 74 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 03 56 56 6a 50 8b f8 68 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 56 68 00 00 00 04 56 56 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 89 45 ?? ff 15 ?? ?? ?? ?? ff 75 08 be ?? ?? ?? ?? ff 75 ?? 89 45 ?? 56 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tobfy_H_2147666731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.H"
        threat_id = "2147666731"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 67 65 74 75 6e 6c 6f 63 6b 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 08 52 50 ff 51 2c [0-16] 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 e9 03 00 00 56 ff 15 ?? ?? ?? ?? 68 e8 03 00 00 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 67 6d 6a 7b 73 42 5d 6b 6c 6c 7b 70 6a 5d 71 70 6a 6c 71 72 4d 7b 6a 42 5d 71 70 6a 6c 71 72 42 4d a6 78 7b 5c 71 71 6a 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 01 52 68 c8 00 00 00 68 ?? 01 00 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 99 2b c2 d1 f8 2d 85 00 00 00 50 68 00 00 00 50 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Tobfy_J_2147668029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.J"
        threat_id = "2147668029"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 69 63 74 75 72 65 2e 70 68 70 00}  //weight: 2, accuracy: High
        $x_2_2 = {75 6e 6c 6f 63 6b 2e 70 68 70 00}  //weight: 2, accuracy: High
        $x_1_3 = {47 6f 6f 67 6c 65 43 68 72 6f 6d 65 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 6a 02 ff d0 8b f0 83 fe ff 74 ?? 8d 85 ?? ?? ff ff 50 56 c7 85 ?? ?? ff ff 28 01 00 00 (ff d7|e8)}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 54 24 04 33 c0 eb 09 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1 c3 55 8b ec 8b 45 08 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tobfy_K_2147669164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.K"
        threat_id = "2147669164"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 26 80 ac c8 6a 01 e8 ?? ?? ff ff 59 59 68 ?? ?? ?? ?? ff d0 eb ?? 68 26 80 ac c8}  //weight: 1, accuracy: Low
        $x_1_2 = {be d5 fc 4f ad bd 7e 00 aa 00 80 3d ?? ?? ?? ?? 4b 0f 84 ?? ?? 00 00 89 3d ?? ?? ?? ?? 68 3b b5 52 02 6a 03 e8 ?? ?? ff ff 59 59 57 68 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {be f5 72 99 3d 47 56 57 e8 ?? ?? ff ff 59 59 57 ff d0 68 ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {68 5a fb 7e bf 6a 03 e8 ?? ?? ff ff 59 59 ff 75 ?? ff 75 ?? ff 75 ?? ff 75 ?? ff 75 ?? ff 75 ?? ff 75 ?? ff 75 ?? ff 75 ?? ff 75 ?? ff 75 ?? ff 75 ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Tobfy_L_2147673908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.L"
        threat_id = "2147673908"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 f9 2b ce 74 18 8b 4d 08 80 34 02 ?? 42 8d 71 01 8a 19 41 84 db}  //weight: 1, accuracy: Low
        $x_1_2 = {68 ec 09 00 00 ff 75 f4 6a 58 ff 75 08 ff d7 8b 1d ?? ?? ?? ?? 50 ff d3 68 ec 09 00 00 ff 75 fc 89 45 f0 6a 5a ff 75 08 ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = {68 ee 02 00 00 2d 77 01 00 00 68 e8 03 00 00 50 8b 45 ?? 99 2b c2 d1 f8 2d f4 01 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "L-0-ck_ER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Tobfy_N_2147678721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.N"
        threat_id = "2147678721"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 ee 02 00 00 68 e8 03 00 00 8b 85 ?? ?? ?? ?? 99 2b c2 d1 f8 2d 77 01 00 00 50 8b 85 ?? ?? ?? ?? 99 2b c2 d1 f8 2d f4 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {03 55 f8 0f be 02 83 f0 01 8b 4d fc 03 4d f8 88 01 eb af}  //weight: 1, accuracy: High
        $x_1_3 = {83 fa 4f 74 0c 0f be 05 ?? ?? ?? ?? 83 f8 4b 75 19 e8}  //weight: 1, accuracy: Low
        $x_1_4 = "L-0-ck_ER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Tobfy_O_2147678945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.O"
        threat_id = "2147678945"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 68 f5 72 99 3d 6a 01 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 57 4f 52 4b 5c 57 4f 52 4b 5f 50 45 43 45 50 42 5c [0-32] 5c 69 6e 6a 63 5c 52 65 6c 65 61 73 65 5c 69 6e 6a 63 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = {03 55 f8 0f be 02 83 f0 01 8b 4d fc 03 4d f8 88 01 eb af}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tobfy_Q_2147679185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.Q"
        threat_id = "2147679185"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "175"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {8f 45 80 81 45 80 d0 01 00 00 68 20 00 cc 00 6a 00 6a 00 ff 75 e4 6a 25 6a 64 ff 75 80 ff 75 84 ff 75 ec e8}  //weight: 100, accuracy: High
        $x_50_2 = {eb 72 3d c9 00 00 00 75 0f 68 a7 a7 a7 00 ff 75 10 e8 ?? ?? 00 00 eb 5c 3d ca 00 00 00}  //weight: 50, accuracy: Low
        $x_30_3 = {83 6d f8 78 83 45 f4 19 6a 00 ff 35 ?? ?? ?? 00 68 c9 00 00 00 ff 75 08 6a 10 68 00}  //weight: 30, accuracy: Low
        $x_30_4 = {81 45 f8 2e 03 00 00 81 45 f4 9e 00 00 00 6a 00 ff 75 08 6a 71 68 96 00 00 00 ff 75 f4 ff 75 f8 68 00 00 00 40 68}  //weight: 30, accuracy: High
        $x_25_5 = "2C_D1C1A_FA_0R_2" ascii //weight: 25
        $x_25_6 = {52 75 6e 00 77 6d 69 61 70 73 76 72}  //weight: 25, accuracy: High
        $x_20_7 = {81 45 f4 36 01 00 00 81 45 f8 62 02 00 00 6a 00 ff 35 ?? ?? ?? 00 6a 00 ff 75 08 6a 0d 6a 0d}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 2 of ($x_25_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_30_*) and 1 of ($x_25_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_30_*) and 2 of ($x_25_*))) or
            ((1 of ($x_100_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_30_*) and 1 of ($x_25_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_25_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tobfy_R_2147679286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.R"
        threat_id = "2147679286"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ab 37 f4 63 16 f1 92 72 2c ae 80 1d 3b 1f 04 50 5e 61 f3}  //weight: 10, accuracy: High
        $x_1_2 = {e3 40 fe 45 fd 0f b6 45 fd 0f b6 14 38 88 55 ff 00 55 fc 0f b6 45 fc 8a 14 38 88 55 fe 0f b6 45 fd 88 14 38 0f b6 45 fc 8a 55 ff 88 14 38 8a 55 ff 02 55 fe 8a 14 3a 8b 45 f8 30 14 30 ff 45 f8 e2 c0 8a 45 fd 88 03 8a 45 fc 88 43 01}  //weight: 1, accuracy: High
        $x_1_3 = {3d c9 00 00 00 75 0f 68 a7 a7 a7 00 ff 75 10 e8 ?? ?? 00 00 eb ?? 3d ca 00 00 00 75 ?? 6a 00 ff 75 10 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {d7 84 c0 78 f7 8a e0 c0 e8 04 c0 e4 04 0b d0 49 78 28 ac d7 84 c0 78 f7 8a e0 c0 e8 02 c0 e4 06 c1 e0 08 0b d0 49 78 12 ac d7 84 c0 78 f7 c1 e0 10 0b d0 89 17}  //weight: 1, accuracy: High
        $x_10_5 = "MoneyPak" wide //weight: 10
        $x_10_6 = {23 33 32 37 37 30 00 41 32 41 5f 30 33}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tobfy_S_2147679980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.S"
        threat_id = "2147679980"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "picture.php?pin=" ascii //weight: 1
        $x_1_2 = "/hcybnq/vzt.wct" ascii //weight: 1
        $x_1_3 = "gnfxzte.rkr" ascii //weight: 1
        $x_1_4 = {0f be 02 85 c0 74 62 8b 4d 08 0f be 11 83 fa 61 7c 26 8b 45 08 0f be 08 83 f9 7a 7f 1b 8b 55 08 0f be 02 83 e8 54 99 b9 1a 00 00 00 f7 f9 83 c2 61 8b 45 08 88 10}  //weight: 1, accuracy: High
        $x_1_5 = {8a 01 3c 61 7c 15 3c 7a 7f 11 0f be c0 83 e8 54 6a 1a 99 5f f7 ff 80 c2 61 eb 17 3c 41 7c 15 3c 5a 7f 11 0f be c0 83 e8 34 6a 1a 99 5f f7 ff 80 c2 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Tobfy_S_2147679980_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.S"
        threat_id = "2147679980"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e0 00 10 00 00 6a 04 68 00 20 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 45 ?? 52 c6 45 ?? 74 c6 45 ?? 70 c6 45 ?? 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7e 20 8b 36 81 7f 0c 33 00 32 00 75 ef 89 55 fc 8b (45|4d) fc}  //weight: 1, accuracy: Low
        $x_1_3 = {68 20 00 cc 00 [0-16] 68 ee 02 00 00 [0-10] e8 03 00 00 [0-32] 2d f4 01 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {70 69 63 74 75 72 65 2e 70 68 70 3f 70 69 6e 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {67 65 74 75 6e 6c 6f 63 6b 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 5c 31 2e 62 6d 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 73 5c 31 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_2_8 = {74 72 67 68 61 79 62 70 78 2e 63 75 63 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tobfy_U_2147680327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.U"
        threat_id = "2147680327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {38 38 38 38 38 61 72 65 5c 63 6c 61 73 73 65 73 00 00 00 00 63 73 73 66 69 6c 65 5c 64 65 66 61 75 6c 74 69 63 6f 6e 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 35 00 36 00 32 00 31 00 31 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 83 ec 18 8b 45 08 89 45 ec 8b 4d 0c 89 4d fc 8b 55 ec 89 55 f8 8b 45 fc 89 45 f4 8b 4d f8 89 4d f0 8b 55 f4 89 55 e8 8b 45 f0 8b 08 33 4d e8 8b 55 f0 89 0a 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {05 fc 57 09 00 50 8b 4d 08 03 0d 74 d0 40 00 51 e8 c3 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tobfy_T_2147680358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.T"
        threat_id = "2147680358"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 c6 45 e8 50 c6 45 e9 72 c6 45 ea 6f c6 45 eb 67 c6 45 ec 72 c6 45 ed 61 c6 45 ee 6d c6 45 ef 20 c6 45 f0 4d c6 45 f1 61 c6 45 f2 6e c6 45 f3 61 c6 45 f4 67 c6 45 f5 65 c6 45 f6 72 8d 7d f7 ab 66 ab aa}  //weight: 1, accuracy: High
        $x_1_2 = {50 6a 01 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 0c 6a ff 56 ff 15 ?? ?? ?? ?? 56 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tobfy_W_2147684627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tobfy.W"
        threat_id = "2147684627"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get.php?os=%s&arch=%s&pin=%s" ascii //weight: 1
        $x_1_2 = {64 8b 35 30 00 00 00 8b 76 0c 8b 76 1c 8b 56 08 8b 7e 20 8b 36 81 7f 0c 33 00 32 00 75 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

