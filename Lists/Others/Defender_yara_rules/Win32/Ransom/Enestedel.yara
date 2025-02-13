rule Ransom_Win32_Enestedel_A_2147720082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.A!rsm"
        threat_id = "2147720082"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "310"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {d2 16 03 00}  //weight: 100, accuracy: High
        $x_100_2 = {62 00 00 00}  //weight: 100, accuracy: High
        $x_100_3 = {db 52 00 00}  //weight: 100, accuracy: High
        $x_10_4 = {00 10 0f be 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_5 = {00 10 0f bf 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_6 = {01 10 0f be 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_7 = {01 10 0f bf 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_8 = {00 10 0f be 05 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_5_9 = {05 00 40 00 62 02 00 80}  //weight: 5, accuracy: Low
        $x_5_10 = {05 00 40 00 46 02 00 80}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_5_*))) or
            ((3 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_D_2147720083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.D!rsm"
        threat_id = "2147720083"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_40_1 = {01 40 99 f7 fe a2 08 00 0f be f0 0f be 05}  //weight: 40, accuracy: Low
        $x_30_2 = {01 40 8b ca 99 f7 f9 89 07 00 01 40 0f be 15 0c 00 0f bf 05}  //weight: 30, accuracy: Low
        $x_10_3 = {01 40 0f be 15 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_4 = {01 40 0f be 0d 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_5 = {01 40 0f bf 15 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_6 = {01 40 0f bf 15 05 00 0f bf 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 2 of ($x_10_*))) or
            ((1 of ($x_40_*) and 1 of ($x_10_*))) or
            ((1 of ($x_40_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_C_2147720086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.C!rsm"
        threat_id = "2147720086"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {01 10 99 f7 f9 89 05 00 01 10 a1 0a 00 0f be 0d}  //weight: 30, accuracy: Low
        $x_30_2 = {01 10 99 f7 f9 89 05 00 01 10 a1 0a 00 0f bf 0d}  //weight: 30, accuracy: Low
        $x_30_3 = {01 10 99 f7 f9 89 07 00 01 10 0f be 0c 00 0f bf}  //weight: 30, accuracy: Low
        $x_10_4 = {01 10 0f be 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_5 = {01 10 0f bf 05 05 00 0f be 0d}  //weight: 10, accuracy: Low
        $x_10_6 = {01 10 0f bf 15 05 00 0f bf 0d}  //weight: 10, accuracy: Low
        $x_10_7 = {01 10 0f be 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 2 of ($x_10_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_E_2147720087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.E!rsm"
        threat_id = "2147720087"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {0f bf c9 83 c1 ?? 89 85 ?? ?? ff ff 8b c2 99 f7 f9 8b 07 00 0f b7 0d}  //weight: 30, accuracy: Low
        $x_30_2 = {00 10 99 f7 f9 0f bf 07 00 00 10 0f bf 0d 0c 00 0f bf 05}  //weight: 30, accuracy: Low
        $x_10_3 = {00 10 0f be 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_4 = {00 10 0f bf 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_5_5 = {00 10 0f bf c0 05 00 0f b7 05}  //weight: 5, accuracy: Low
        $x_5_6 = {00 10 0f be d2 05 00 0f b6 15}  //weight: 5, accuracy: Low
        $x_5_7 = {00 10 0f be c0 05 00 0f b6 05}  //weight: 5, accuracy: Low
        $x_5_8 = {00 10 0f be d2 05 00 0f b7 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 4 of ($x_5_*))) or
            ((1 of ($x_30_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_30_*) and 2 of ($x_10_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_F_2147720088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.F!rsm"
        threat_id = "2147720088"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {10 67 99 f7 fd 89 07 00 10 67 0f bf 2d 0c 00 0f bf 05}  //weight: 30, accuracy: Low
        $x_10_2 = {10 67 0f bf 2d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_3 = {10 67 0f be 05 05 00 0f be 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Enestedel_G_2147720106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.G!rsm"
        threat_id = "2147720106"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "500"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {6a 01 68 00 00 00 80 68 [0-2] 00 10 ff 05 00 6a 50 6a 03}  //weight: 100, accuracy: Low
        $x_100_2 = {05 00 40 00 4d 02 00 80}  //weight: 100, accuracy: Low
        $x_100_3 = {05 00 40 00 62 02 00 80}  //weight: 100, accuracy: Low
        $x_100_4 = {02 00 40 00 47 02 00 80}  //weight: 100, accuracy: Low
        $x_100_5 = {68 00 10 00 00 [0-5] ff 54 [0-12] c7 [0-2] 07 00 01 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Enestedel_B_2147720107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.B!rsm"
        threat_id = "2147720107"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {6a 50 6a 03 50 6a 01 68 00 00 00 80 52 ff}  //weight: 30, accuracy: High
        $x_10_2 = {00 10 0f be 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_3 = {00 10 0f bf 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_4 = {00 10 0f b7 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_5 = {00 10 0f be 05 05 00 0f be 0d}  //weight: 10, accuracy: Low
        $x_10_6 = {00 10 0f be 05 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_7 = {00 10 0f bf 15 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_8 = {00 10 0f be 05 05 00 0f bf 15}  //weight: 10, accuracy: Low
        $x_10_9 = {00 10 0f be 35 05 00 0f be 0d}  //weight: 10, accuracy: Low
        $x_10_10 = {00 10 0f bf 89 05 00 0f bf 81}  //weight: 10, accuracy: Low
        $x_10_11 = {00 10 0f bf 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            ((1 of ($x_30_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_I_2147720139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.I!rsm"
        threat_id = "2147720139"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "600"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {6a 50 6a 03 6a 00 6a 01 68 00 00 00 80 68 [0-2] 00 10 ff}  //weight: 100, accuracy: Low
        $x_100_2 = {6a 04 68 00 10 00 00 6a 04 [0-4] ff 55 [0-12] c7 [0-2] 07 00 01 00}  //weight: 100, accuracy: Low
        $x_100_3 = {00 10 0f bf 0d 05 00 0f bf 05}  //weight: 100, accuracy: Low
        $x_100_4 = {00 10 0f bf 05 05 00 0f bf 0d}  //weight: 100, accuracy: Low
        $x_100_5 = {00 10 0f bf 3d 05 00 0f bf 15}  //weight: 100, accuracy: Low
        $x_100_6 = {00 10 0f bf 0d 05 00 0f bf 35}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Enestedel_K_2147720176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.K!rsm"
        threat_id = "2147720176"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "240"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {d2 16 03 00 03 00 c7 45}  //weight: 100, accuracy: Low
        $x_100_2 = {b6 14 00 00 03 00 c7 45}  //weight: 100, accuracy: Low
        $x_100_3 = {10 15 03 00 03 00 c7 45}  //weight: 100, accuracy: Low
        $x_100_4 = {88 13 00 00 03 00 c7 45}  //weight: 100, accuracy: Low
        $x_10_5 = {00 10 0f bf 15 05 00 0f bf 0d}  //weight: 10, accuracy: Low
        $x_10_6 = {00 10 0f bf 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_7 = {00 10 0f be 0d 05 00 0f bf 15}  //weight: 10, accuracy: Low
        $x_10_8 = {00 10 0f be 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_9 = {00 10 0f bf 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_10 = {00 10 0f bf 0d 05 00 0f bf 15}  //weight: 10, accuracy: Low
        $x_10_11 = {00 10 0f bf 05 05 00 0f bf 15}  //weight: 10, accuracy: Low
        $x_10_12 = {00 10 0f be 05 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_13 = {00 10 0f bf 05 05 00 0f bf 0d}  //weight: 10, accuracy: Low
        $x_10_14 = {00 10 0f be 0d 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_15 = {05 00 40 00 4d 02 00 80}  //weight: 10, accuracy: Low
        $x_10_16 = {00 10 0f be 15 05 00 0f be 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 4 of ($x_10_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_L_2147720177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.L!rsm"
        threat_id = "2147720177"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 10 0f bf 0d 05 00 0f bf 15}  //weight: 10, accuracy: Low
        $x_10_2 = {01 10 0f be 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_3 = {01 10 0f bf 05 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_4 = {01 10 0f bf 15 05 00 0f bf 0d}  //weight: 10, accuracy: Low
        $x_10_5 = {01 10 0f bf 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_6 = {02 00 40 00 02 00 81}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Enestedel_J_2147720198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.J!rsm"
        threat_id = "2147720198"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 10 0f be 0d ?? ?? 00 10 99 81 e9 ?? ?? ?? ?? f7 f9}  //weight: 10, accuracy: Low
        $x_10_2 = {00 10 99 f7 f9 a2 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_3 = {00 10 0f be 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_4 = {00 10 0f bf 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_5 = {00 10 0f be 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_6 = {00 10 0f be 0d 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_7 = {00 10 0f be 15 05 00 0f be 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Enestedel_N_2147720226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.N!rsm"
        threat_id = "2147720226"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {10 15 03 00 c7 45 ?? 62 00 00 00 c7 45 ?? 88 13 00 00}  //weight: 100, accuracy: Low
        $x_10_2 = {6a 50 6a 03 ?? 6a 01 68 00 00 00 80 8d [0-8] ff d0}  //weight: 10, accuracy: Low
        $x_10_3 = {6a 00 6a 50 6a 03 6a 00 6a 01 68 00 00 00 80 68 ?? ?? 00 10 ff}  //weight: 10, accuracy: Low
        $x_10_4 = {6a 50 6a 03 ?? 6a 01 68 00 00 00 80 68 [0-8] ff d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_O_2147720227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.O!rsm"
        threat_id = "2147720227"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 50 6a 03 6a 00 6a 01 68 00 00 00 80}  //weight: 10, accuracy: High
        $x_10_2 = {80 b8 02 00 40 00 47}  //weight: 10, accuracy: High
        $x_10_3 = {80 b8 05 00 40 00 4d}  //weight: 10, accuracy: High
        $x_10_4 = {00 10 0f bf 15 05 00 0f bf 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Enestedel_O_2147720227_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.O!rsm"
        threat_id = "2147720227"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 fa 62 75 09 83 f9 0b 75 04 89 6c 24 ?? 0f be b0 02 00 40 00 83 fe 47 75 0e 83 fa 46 75 09 83 f9 0b 75 04 89 6c 24 ?? 83 fe 52 75 0d 80 b8 06 00 40 00 46}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 00 6a 50 6a 03 6a 00 6a 01 68 00 00 00 80 68}  //weight: 1, accuracy: High
        $x_1_3 = {80 b8 02 00 40 00 47}  //weight: 1, accuracy: High
        $x_1_4 = {80 b8 05 00 40 00 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_P_2147720265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.P!rsm"
        threat_id = "2147720265"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {10 15 03 00}  //weight: 100, accuracy: High
        $x_100_2 = {88 13 00 00}  //weight: 100, accuracy: High
        $x_100_3 = {6a 50 6a 03 ?? 6a 01 68 00 00 00 80 68 [0-2] 00 10 ff}  //weight: 100, accuracy: Low
        $x_10_4 = {00 10 0f be 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_5 = {00 10 0f bf 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_6 = {00 10 0f be 05 05 00 0f be 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_Q_2147720284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.Q!rsm"
        threat_id = "2147720284"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 e4 f8 e8 ?? 00 00 00 e8 ?? 00 00 00 33 c0 [0-24] 19 c8 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Enestedel_R_2147720285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.R!rsm"
        threat_id = "2147720285"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "120"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {19 c8 00 00 c7 45 ?? 88 13 00 00 03 00 c7 45}  //weight: 100, accuracy: Low
        $x_10_2 = {00 10 0f bf 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_3 = {00 10 0f be 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_4 = {00 10 0f be 1d 05 00 0f be 0d}  //weight: 10, accuracy: Low
        $x_20_5 = {6a 00 6a 50 6a 03 6a 00 6a 01 68 00 00 00 80 68 ?? ?? 00 10 ff}  //weight: 20, accuracy: Low
        $x_20_6 = {53 6a 50 6a 03 53 6a 01 68 00 00 00 80 68 ?? ?? 00 10 ff}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_S_2147720386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.S!rsm"
        threat_id = "2147720386"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1210"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {6a 00 6a 50 6a 03 6a 00 6a 01 68 00 00 00 80 68 ?? ?? 00 10 [0-16] ff}  //weight: 1000, accuracy: Low
        $x_1000_2 = {6a 50 6a 03 (57|53|52|56) 6a 01 68 00 00 00 80 68 ?? ?? 00 10 [0-16] ff}  //weight: 1000, accuracy: Low
        $x_100_3 = {02 00 40 00 00}  //weight: 100, accuracy: High
        $x_100_4 = {02 00 40 00 47}  //weight: 100, accuracy: High
        $x_100_5 = {05 00 40 00}  //weight: 100, accuracy: High
        $x_10_6 = {c7 06 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_7 = {c7 07 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_8 = {c7 00 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_9 = {c7 01 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_10 = {c7 02 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_11 = {c7 03 07 00 01 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 2 of ($x_100_*) and 1 of ($x_10_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_100_*))) or
            ((2 of ($x_1000_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_U_2147720451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.U!rsm"
        threat_id = "2147720451"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "510"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {c6 05 00 00 00 00 02}  //weight: 100, accuracy: High
        $x_100_2 = {05 00 40 00 62 02 00 80}  //weight: 100, accuracy: Low
        $x_100_3 = {05 00 40 00 4d 02 00 80}  //weight: 100, accuracy: Low
        $x_100_4 = {05 00 40 00 46 02 00 80}  //weight: 100, accuracy: Low
        $x_100_5 = {06 00 40 00 46 02 00 80}  //weight: 100, accuracy: Low
        $x_10_6 = {00 10 0f be 1d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_7 = {00 10 0f be 3d 05 00 0f be 1d}  //weight: 10, accuracy: Low
        $x_10_8 = {00 10 0f be 35 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_9 = {00 10 0f be 35 05 00 0f be 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_T_2147720461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.T!rsm"
        threat_id = "2147720461"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 06 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_2 = {c7 07 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_3 = {c7 00 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_4 = {c7 01 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_5 = {c7 02 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_6 = {c7 03 07 00 01 00}  //weight: 10, accuracy: High
        $x_10_7 = {00 10 0f bf 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_8 = {00 10 0f bf 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_9 = {00 10 0f bf 05 05 00 0f bf 15}  //weight: 10, accuracy: Low
        $x_10_10 = {00 10 0f bf 0d 05 00 0f bf 15}  //weight: 10, accuracy: Low
        $x_10_11 = {00 10 0f be 05 05 00 0f bf 15}  //weight: 10, accuracy: Low
        $x_10_12 = {00 10 0f be 15 05 00 0f be 0d}  //weight: 10, accuracy: Low
        $x_10_13 = {00 10 0f be 05 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_14 = {00 10 0f be 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_15 = {00 10 50 0f b7 0d ?? ?? 00 10 51 0f b6 15 ?? ?? 00 10 52 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_16 = {00 10 52 0f b7 05 ?? ?? 00 10 50 0f b6 0d ?? ?? 00 10 51 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_17 = {01 10 0f be 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_18 = {01 10 0f bf 05 05 00 0f bf 15}  //weight: 10, accuracy: Low
        $x_10_19 = {01 10 0f be 05 05 00 0f bf 15}  //weight: 10, accuracy: Low
        $x_10_20 = {01 10 0f bf 15 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_21 = {00 10 51 0f bf 15 ?? ?? 00 10 52 e8 05 00 0f b7 0d}  //weight: 10, accuracy: Low
        $x_10_22 = {00 10 50 0f bf 0d ?? ?? 00 10 51 e8 05 00 0f b7 05}  //weight: 10, accuracy: Low
        $x_10_23 = {0f bf d0 89 15 ?? ?? 00 10 0f be 85 ?? ?? ff ff 0f be 8d ?? ?? ff ff 23}  //weight: 10, accuracy: Low
        $x_10_24 = {0f bf c8 89 0d ?? ?? 00 10 0f be 95 ?? ?? ff ff 0f be 85 ?? ?? ff ff 23}  //weight: 10, accuracy: Low
        $x_10_25 = {ff ff f7 d2 88 95 ?? ?? ff ff 0f be 85 ?? ?? ff ff 0f be 8d 05 00 0f be 95}  //weight: 10, accuracy: Low
        $x_10_26 = {01 10 0f be 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_27 = {52 66 0f be 05 ?? ?? 00 10 50 0f bf 0d ?? ?? 00 10 51 e8}  //weight: 10, accuracy: Low
        $x_10_28 = {00 10 0f bf 15 05 00 0f be 0d}  //weight: 10, accuracy: Low
        $x_10_29 = {00 10 0f be 0d 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_30 = {00 10 0f bf 15 05 00 0f bf 0d}  //weight: 10, accuracy: Low
        $x_10_31 = {51 66 0f be 15 ?? ?? 00 10 52 0f bf 05 ?? ?? 00 10 50 e8}  //weight: 10, accuracy: Low
        $x_10_32 = {ff ff 00 00 80 00 04 00 c7 85}  //weight: 10, accuracy: Low
        $x_10_33 = {ff ff 50 00 00 00 04 00 c7 85}  //weight: 10, accuracy: Low
        $x_10_34 = {ff ff 03 00 00 00 04 00 c7 85}  //weight: 10, accuracy: Low
        $x_20_35 = {50 6a 50 6a 03 50 6a 01 68 00 00 00 80 68 ?? ?? 00 10 ff}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_V_2147720527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.V!rsm"
        threat_id = "2147720527"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "210"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {68 00 00 00 80 34 00 6a 50 [0-24] 6a 03 [0-32] 6a 01}  //weight: 100, accuracy: Low
        $x_100_2 = {6a 40 68 00 30 00 00 [0-16] 68 96 02 00}  //weight: 100, accuracy: Low
        $x_100_3 = {68 96 02 00 00 10 00 68 00 30 00 00 18 00 6a 40}  //weight: 100, accuracy: Low
        $x_10_4 = {05 00 40 00 46}  //weight: 10, accuracy: High
        $x_10_5 = {06 00 40 00 46}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_V_2147720527_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.V!rsm"
        threat_id = "2147720527"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c1 99 f7 7d ?? 8b 45 ?? 8a 8a ?? ?? ?? ?? c0 e1 03 88 08 8b 4d ?? 30 08 41 3b ce 89 4d ?? 7c d7}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 03 6a 00 ff 30 51 68 ?? ?? ?? ?? ff 55 ?? 8b f0 6a 00 56 ff 55}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 04 8b f0 57 c7 06 00 80 00 00 ff 55 ?? 6a 04 57 89 45 ?? c7 00 01 00 00 00 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_W_2147720534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.W!rsm"
        threat_id = "2147720534"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "340"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {96 02 00 00 c7 45}  //weight: 100, accuracy: High
        $x_100_2 = {96 02 00 00 c7 85}  //weight: 100, accuracy: High
        $x_100_3 = {ff ff 00 00 80 00 04 00 c7}  //weight: 100, accuracy: Low
        $x_100_4 = {ff ff 50 00 00 00 24 00 01 00 00 00 c7 [0-8] 03 00 00 00 c7 [0-8] 00 00 00 00 c7}  //weight: 100, accuracy: Low
        $x_10_5 = {00 10 0f be 0d 05 00 0f be 05}  //weight: 10, accuracy: Low
        $x_10_6 = {00 10 0f be 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_7 = {00 10 0f bf 0d 05 00 0f bf 05}  //weight: 10, accuracy: Low
        $x_10_8 = {00 10 0f bf 05 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_9 = {00 10 52 0f be 05 ?? ?? 00 10 50 e8 05 00 0f be 15}  //weight: 10, accuracy: Low
        $x_10_10 = {00 10 52 0f be 05 ?? ?? 00 10 50 e8 05 00 0f bf 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 4 of ($x_10_*))) or
            ((4 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_X_2147720595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.X!rsm"
        threat_id = "2147720595"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "310"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {3c 00 40 00 8b ?? 80 00 40 00}  //weight: 100, accuracy: Low
        $x_100_2 = {02 00 40 00 8b}  //weight: 100, accuracy: High
        $x_100_3 = {6a 50 6a 03}  //weight: 100, accuracy: High
        $x_10_4 = {6a 50 6a 40 ff 15 ?? ?? 00 10}  //weight: 10, accuracy: Low
        $x_10_5 = {6a 1e 6a 40 ff 15 ?? ?? 00 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enestedel_Z_2147720597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enestedel.Z!rsm"
        threat_id = "2147720597"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enestedel"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "310"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {33 c0 c6 00 02}  //weight: 100, accuracy: High
        $x_100_2 = {02 00 40 00 47 75}  //weight: 100, accuracy: High
        $x_100_3 = {05 00 40 00 4d 75}  //weight: 100, accuracy: High
        $x_10_4 = {00 10 0f bf 0d 05 00 0f (be|bf) 15}  //weight: 10, accuracy: Low
        $x_10_5 = {00 10 0f bf 15 05 00 0f (be|bf) 0d}  //weight: 10, accuracy: Low
        $x_10_6 = {00 10 0f be 2d 05 00 0f (be|bf) 15}  //weight: 10, accuracy: Low
        $x_10_7 = {00 10 0f be 0d 05 00 0f (be|bf) 05}  //weight: 10, accuracy: Low
        $x_10_8 = {00 10 0f be 15 05 00 0f (be|bf) 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

