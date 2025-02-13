rule Trojan_Win32_Miuref_A_2147684676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.A"
        threat_id = "2147684676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 25 73 25 69 2e 25 69 2e 25 69 2e 25 69 2f 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 06 7b ff 37 8d 46 01 6a ?? 6a ?? 50 e8 ?? ?? ?? ?? c6 46 09 2d 0f b7 47 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_A_2147684676_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.A"
        threat_id = "2147684676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 83 3c 4e 5c 75 03 89 4d fc 41 3b c8 72 f1}  //weight: 2, accuracy: High
        $x_2_2 = "setup.dat" wide //weight: 2
        $x_2_3 = {b8 4d 5a 00 00 66 39 45 00 75 f1 56 8b 75 3c 03 f5 81 3e 50 45 00 00 74 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_A_2147684677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.gen!A"
        threat_id = "2147684677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 54 03 41 3c 57 e8 ?? ?? ?? ?? 8b 4d 08 8b 41 3c 03 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 8b 48 28 85 c9 74 ?? 8b 46 04 03 c1 74 ?? 6a ff 6a 01 6a 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_B_2147685038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.B"
        threat_id = "2147685038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "19"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 33 c0 89 (73|7b) 04 89 43 0c 89 43 08 89 43 10 8b (46|47) 54 03 ?? 3c}  //weight: 1, accuracy: Low
        $x_1_2 = {80 e3 0f 6a 01 80 fb 03 77 ?? 6a 06 58 e8 ?? ?? ?? ?? 8b f8 59 6a 2e 58 66 89 07 [0-1] 0f b6 c3 66 83 c0 30 66 89 47 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_C_2147686089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.C"
        threat_id = "2147686089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 04 03 c1 74 ?? 6a ff 6a 01 57 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 0a 8b d9 81 e3 00 f0 ff ff 81 fb 00 30 00 00 75 0d 8b 5d 08 81 e1 ff 0f 00 00 03 cf 01 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_D_2147686320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.D"
        threat_id = "2147686320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 8b 48 28 85 c9 74 1a 8b 46 04 03 c1 74 13 6a ff 6a 01 6a 00 ff d0 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {c7 40 44 02 00 00 00 c7 40 48 4d dd eb 5a c7 40 4c a1 ce eb 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_E_2147686974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.E"
        threat_id = "2147686974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 3c 24 81 2c 24 78 54 cb 32 58 50 89 1c 24 bb 78 54 cb 32 01 d8 5b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_F_2147688184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.F"
        threat_id = "2147688184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {8b 06 8b 48 28 85 c9 74 1a 8b 46 04 03 c1 74 13 6a ff 6a 01 6a 00 ff d0}  //weight: 16, accuracy: High
        $x_2_2 = {bb 6b 09 14 00 74 34 8a 0c 3a 80 f9 61 7c 0d 80 f9 7a 7f 08 0f be c9 83 e9 20 eb 03 0f be c9 6b db 1f 03 d9 47 3b fe 72 de 81 fb c7 50 58 e8}  //weight: 2, accuracy: High
        $x_1_3 = {b8 6b 09 14 00 74 ?? 8a 0c 16 80 f9 61 7c 0d 80 f9 7a 7f 08 0f be c9 83 e9 20 eb 03 0f be c9 6b c0 1f 03 c1 42 3b d7 72 de}  //weight: 1, accuracy: Low
        $x_1_4 = {3d c7 50 58 e8 75 ?? c7 05 ?? ?? ?? ?? 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_16_*) and 2 of ($x_1_*))) or
            ((1 of ($x_16_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Miuref_A_2147688625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.A!!Miuref"
        threat_id = "2147688625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        info = "Miuref: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 25 73 25 69 2e 25 69 2e 25 69 2e 25 69 2f 00}  //weight: 1, accuracy: High
        $x_1_2 = {bb 6b 09 14 00 74 34 8a 0c 3a 80 f9 61 7c 0d 80 f9 7a}  //weight: 1, accuracy: High
        $x_2_3 = {c6 06 7b ff 37 8d 46 01 6a ?? 6a ?? 50 e8 ?? ?? ?? ?? c6 46 09 2d 0f b7 47 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Miuref_F_2147688626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.F!!Miuref"
        threat_id = "2147688626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        info = "Miuref: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {8b 06 8b 48 28 85 c9 74 1a 8b 46 04 03 c1 74 13 6a ff 6a 01 6a 00 ff d0}  //weight: 16, accuracy: High
        $x_2_2 = {bb 6b 09 14 00 74 34 8a 0c 3a 80 f9 61 7c 0d 80 f9 7a 7f 08 0f be c9 83 e9 20 eb 03 0f be c9 6b db 1f 03 d9 47 3b fe 72 de 81 fb c7 50 58 e8}  //weight: 2, accuracy: High
        $x_1_3 = {b8 6b 09 14 00 74 ?? 8a 0c 16 80 f9 61 7c 0d 80 f9 7a 7f 08 0f be c9 83 e9 20 eb 03 0f be c9 6b c0 1f 03 c1 42 3b d7 72 de}  //weight: 1, accuracy: Low
        $x_1_4 = {3d c7 50 58 e8 75 ?? c7 05 ?? ?? ?? ?? 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_16_*) and 2 of ($x_1_*))) or
            ((1 of ($x_16_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Miuref_G_2147689279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.G"
        threat_id = "2147689279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 3d c7 50 58 e8 75 ?? c7 05 ?? ?? ?? ?? 01 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {50 6a 40 68 00 04 00 00 ff 75 f4 ff 15 ?? ?? ?? ?? 85 c0 74 37 6a 04 8d 45 fc 50 68 00 04 00 00 ff 75 f4 e8 ?? ?? ?? ?? 83 c4 10 68 60 ea 00 00 ff 15 ?? ?? ?? ?? 6a 04 8d 45 fc 50 68 00 04 00 00 ff 75 f4 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f8 8b 00 83 78 28 00 74 2e 8b 45 f8 8b 00 8b 4d f8 8b 49 04 03 48 28 89 4d fc 74 1b 6a ff 6a 01 ff 75 0c ff 55 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Miuref_G_2147689297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.G!!Miuref"
        threat_id = "2147689297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        info = "Miuref: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 3d c7 50 58 e8 75 ?? c7 05 ?? ?? ?? ?? 01 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {50 6a 40 68 00 04 00 00 ff 75 f4 ff 15 ?? ?? ?? ?? 85 c0 74 37 6a 04 8d 45 fc 50 68 00 04 00 00 ff 75 f4 e8 ?? ?? ?? ?? 83 c4 10 68 60 ea 00 00 ff 15 ?? ?? ?? ?? 6a 04 8d 45 fc 50 68 00 04 00 00 ff 75 f4 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f8 8b 00 83 78 28 00 74 2e 8b 45 f8 8b 00 8b 4d f8 8b 49 04 03 48 28 89 4d fc 74 1b 6a ff 6a 01 ff 75 0c ff 55 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Miuref_H_2147689414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.H"
        threat_id = "2147689414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {65 72 6e 65 6c 33 32 00 00 00 00 13}  //weight: 3, accuracy: High
        $x_2_2 = "Any-Video-Converter.com" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_I_2147689933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.I"
        threat_id = "2147689933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 2c 8b 07 0f b7 48 14 83 65 f8 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b d3 85 d2 75 15 f6 c1 40 74 05 8b}  //weight: 1, accuracy: High
        $x_1_3 = {c1 ea 1d 83 e2 01 8b d9 c1 eb}  //weight: 1, accuracy: High
        $x_1_4 = {73 7a 53 56 8d 71 24 8b 0e 8b d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_K_2147696140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.K"
        threat_id = "2147696140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loader_u.dll" ascii //weight: 1
        $x_1_2 = {6b d2 1f 03 d1 83 c0 02}  //weight: 1, accuracy: High
        $x_1_3 = {3d 75 c0 8e 88}  //weight: 1, accuracy: High
        $x_1_4 = {3d a5 d3 d5 4b}  //weight: 1, accuracy: High
        $x_1_5 = {3d ee 86 47 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_L_2147696295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.L"
        threat_id = "2147696295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 73 37 8b 85 ?? ?? ?? ?? 33 d2 b9 1a 00 00 00 f7 f1 83 c2 41 8b 85 ?? ?? ?? ?? 66 89 94 45 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 69 c9 83 00 00 00 83 c1 07 06 00 83 bd}  //weight: 1, accuracy: Low
        $x_1_2 = {3d ee 86 47 cf}  //weight: 1, accuracy: High
        $x_1_3 = {77 6f 72 6b 73 00 00 00 74 69 6f 6e 00 00 00 00 73 6f 66 74 00 00 00 00 69 63 73 00 6d 65 64 69 61 00 00 00 50 61 63 6b}  //weight: 1, accuracy: High
        $x_1_4 = {2e 00 69 00 64 00 78 00 00 00 00 00 2e 00 6c 00 63 00 6b 00 00 00 00 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_M_2147696692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.M"
        threat_id = "2147696692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6b d2 1f 03 d1 83 c0 02 0f b7 08 66 85 c9 75 d3 8b c2 c3}  //weight: 10, accuracy: High
        $x_1_2 = {3d ee 86 47 cf}  //weight: 1, accuracy: High
        $x_1_3 = {3d a5 d3 d5 4b}  //weight: 1, accuracy: High
        $x_1_4 = {3d c7 50 58 e8}  //weight: 1, accuracy: High
        $x_10_5 = {2e 00 69 00 64 00 78 00 00 00 00 00 2e 00 6c 00 63 00 6b 00 00 00 00 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Miuref_O_2147696852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.O"
        threat_id = "2147696852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 80 f2 ?? 80 ea ?? 41 88 10 81 f9 00 2c 00 00 72 e7 06 00 8d 81 ?? ?? ?? 10}  //weight: 1, accuracy: Low
        $x_1_2 = {be 80 38 01 00 33 ff ff 15 ?? ?? ?? 10 ff 35 ?? ?? ?? 10 83 c6 50 ff 15 ?? ?? ?? 10 83 c7 32 3b fe 7c e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_P_2147696888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.P"
        threat_id = "2147696888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff ff 15 ?? ?? ?? 10 68 ?? ?? ?? 10 33 c0 50 50 6a 28 50 ff 15 ?? ?? ?? 10 81 c6 20 03 00 00 81 c7 f4 01 00 00 3b fe 7c d8 05 00 be ?? ?? 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {71 02 10 34 ?? 2c ?? 88 82 ?? 71 02 10 42 81 fa 00 2c 00 00 72 e7 03 00 8a 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Miuref_R_2147716203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miuref.R"
        threat_id = "2147716203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miuref"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 6b 09 14 00 74 ?? 8a 0c 16 80 f9 61 7c 0d 80 f9 7a 7f 08 0f be c9 83 e9 20 eb 03 0f be c9 6b c0 1f 03 c1 42 3b d7 72 de}  //weight: 1, accuracy: Low
        $x_1_2 = {3d c7 50 58 e8 75 [0-17] c7 05 ?? ?? ?? ?? 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 06 7b ff 37 8d 46 01 6a ?? 6a ?? 50 e8 ?? ?? ?? ?? c6 46 09 2d 0f b7 47 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

