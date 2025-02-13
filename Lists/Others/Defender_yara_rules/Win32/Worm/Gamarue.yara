rule Worm_Win32_Gamarue_A_2147649318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.A"
        threat_id = "2147649318"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "burumaga.net/www/stat3.php" ascii //weight: 1
        $x_1_2 = "andromeda" ascii //weight: 1
        $x_1_3 = "D:(A;;KRWD;;;WD)" ascii //weight: 1
        $x_3_4 = "id:%lu|bv:%lu|sv:%lu|la:%lu" ascii //weight: 3
        $x_3_5 = "id:%lu|tid:%lu|result:%lu" ascii //weight: 3
        $x_3_6 = {8b 45 f0 8b 4d ec 81 7c 01 fb 2e 63 6f 6d 75 24 33 c9 51 51 6a 03 51 6a 01 68 00 00 00 80 ff 75 f0}  //weight: 3, accuracy: High
        $x_10_7 = {68 65 78 65 00 68 63 6c 74 2e 68 77 75 61 75 8b d4 33 c0 50 50 6a 03 50 6a 01 68 00 00 00 80 52 ff 55 f8}  //weight: 10, accuracy: High
        $x_1_8 = {b0 68 aa 8b 45 9c ab b0 c3 aa}  //weight: 1, accuracy: High
        $x_1_9 = {ac 84 c0 74 09 0c 23 32 d0 c1 c2 11 eb f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_B_2147649931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.B"
        threat_id = "2147649931"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 65 78 65 00 68 6f 73 74 2e 68 73 76 63 68 8b ?? 33 ?? ?? ?? 6a 03 ?? 6a 01 68 00 00 00 80 ?? ff 55 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 68 aa 8b 45 ?? ab b0 c3 aa 8b 5d ?? 03 5b 3c}  //weight: 1, accuracy: Low
        $x_1_3 = "id:%lu|tid:%lu" ascii //weight: 1
        $x_1_4 = {64 8b 1d 30 00 00 00 8b 5b 0c 8b 5b 0c 83 c3 24 8b 5b 04 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Gamarue_C_2147650797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.C"
        threat_id = "2147650797"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VXBkYXRlIHNlcnZpY2U=" ascii //weight: 1
        $x_2_2 = "XHdpbnN2Y2hvc3Rcc3ZjaG9zdC5leGU=" ascii //weight: 2
        $x_5_3 = "L2dldGNtZC5waHA//" ascii //weight: 5
        $x_1_4 = "\\SmartFTP\\Client 2.0\\Favorites\\Quick Connect\\*.xml" ascii //weight: 1
        $x_1_5 = "\\FileZilla\\recentservers.xml" ascii //weight: 1
        $x_5_6 = "program=FlashFXP&website=" ascii //weight: 5
        $x_1_7 = "\\GHISLER\\wcx_ftp.inis" ascii //weight: 1
        $x_1_8 = "\\Estsoft\\ALFTP\\QData.dat" ascii //weight: 1
        $x_1_9 = "Lmh0dHBmbG9vZA==" ascii //weight: 1
        $x_1_10 = "LnBvc3RodHRwZmxvb2Q=" ascii //weight: 1
        $x_1_11 = "XFdpblNvY2tzLnN3" ascii //weight: 1
        $x_1_12 = "LnVwZGF0ZQ==" ascii //weight: 1
        $x_1_13 = "LmRvd25sb2Fk" ascii //weight: 1
        $x_5_14 = "U3lzdGVtLmV4ZQ==" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_D_2147652494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.D"
        threat_id = "2147652494"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 1d 30 00 00 00 8b 5b 0c 8b 5b 0c 83 c3 24 8b 5b 04}  //weight: 1, accuracy: High
        $x_1_2 = {68 65 78 65 00 68 6f 73 74 2e 68 73 76 63 68 8b dc}  //weight: 1, accuracy: High
        $x_1_3 = {51 51 51 ff 75 bc ff 75 a8 ff 55 c8}  //weight: 1, accuracy: High
        $x_1_4 = {ac 84 c0 74 09 0c ?? 32 d0 c1 c2 ?? eb fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Gamarue_E_2147652912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.E"
        threat_id = "2147652912"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 63 6c 74 2e 68 77 75 61 75 eb 0f 68 65 78 65 00 68 6f 73 74 2e 68 73 76 63 68}  //weight: 1, accuracy: High
        $x_1_2 = {b0 68 aa 8b 45 ?? ab b0 c3 aa 8b 5d ?? 03 5b 3c}  //weight: 1, accuracy: Low
        $x_1_3 = "id:%lu|tid:%lu" ascii //weight: 1
        $x_1_4 = {64 8b 1d 30 00 00 00 8b 5b 0c 8b 5b 0c 8b 1b 8b 1b 83 c3 18 8b 1b e8 00 00 00 00 5a 81 ea ?? ?? ?? ?? 8d b2 ?? ?? ?? ?? 8d 7d fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Gamarue_F_2147653472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.F"
        threat_id = "2147653472"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5c 73 79 73 ab b8 74 65 6d 33 ab b8 32 5c 77 75 ab b8 61 75 63 6c ab b8 74 2e 65 78 ab b8 65 00 00 00 ab}  //weight: 1, accuracy: High
        $x_1_2 = {64 8b 1d 30 00 00 00 8b 5b 0c 8b 5b 0c 8b 1b 8b 43 18 89 45 ?? 8b 1b 8b 43 18 89 45 ?? e8 00 00 00 00 8f 45}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 3e 8b 4e 04 83 e9 08 d1 e9 83 c6 08 33 c0 66 ad a9 00 30 00 00 74 ?? 25 ff 0f 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = "id:%lu|tid:%lu" ascii //weight: 1
        $x_1_5 = {8b 43 3c 8d 44 18 18 8b 40 10 03 c3 6a 00 6a 00 ff 75 ?? ff d0 6a 00 6a ff ff 55}  //weight: 1, accuracy: Low
        $x_1_6 = {66 81 78 04 4d 5a 74 20 81 78 04 50 4b 03 04 0f 85 ?? ?? 00 00 ff 75 ?? e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? 00 00 89 45 ?? 6a 04 68 00 10 00 00 68 00 80 00 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 75 08 81 7e 03 70 3a 2f 2f 75 03 8d 76 07 56 ff 75 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Gamarue_I_2147656754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.I"
        threat_id = "2147656754"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 6c 6f 6c 00 8b c4 50 6a 00 68 01 00 1f 00 ff 55}  //weight: 1, accuracy: High
        $x_1_2 = {68 64 6c 6c 00 68 64 6c 6c 2e 68 73 62 69 65 8b c4 50 ff 55 ?? 83 c4 0c 85 c0 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {b0 68 aa 8b 45 08 2b 45 ?? 03 45 ?? ab b0 c3 aa c7 85 ?? ?? ff ff 02 00 01 00 8d 85 ?? ?? ff ff 50}  //weight: 1, accuracy: Low
        $x_1_4 = {03 40 3c 8d 40 18 8b 40 38 89 45 ?? 33 c9 89 4d ?? 51 68 00 00 00 08 6a 40 03 00 8b 45}  //weight: 1, accuracy: Low
        $x_1_5 = {c0 bd f0 ff c7 45 ?? ff ff ff ff 8d 45 ?? 50 6a 00 e8 ?? ?? 00 00 33 c9 89 4d ?? 89 4d ?? 6a 40 51 6a 01 8d 45 ?? 50 51 51 51 8d 45 ?? 50}  //weight: 1, accuracy: Low
        $x_1_6 = {64 8b 15 30 00 00 00 8b 52 18 68 04 01 00 00 6a 08 52 ff d0}  //weight: 1, accuracy: High
        $x_1_7 = {ff d0 03 45 ?? c7 00 5c 2a 2e 64 (c7|83 c0 04) 6c 6c 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {8b c8 8b 45 0c 89 38 f3 a4 b0 e9 aa 8d 46 ?? 2b c7 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Gamarue_M_2147665882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.M"
        threat_id = "2147665882"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?i=%s&u=%s&l=%s&f=%d&a=%s" ascii //weight: 1
        $x_1_2 = {83 e9 0e 74 2d 83 e9 3e 8b 75 14 74 08 81 e9 c4 00 00 00 eb 04 83 7e 08 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_N_2147679217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.N"
        threat_id = "2147679217"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 5c 56 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 89 45 e4 6a 40 b8 00 10 00 00 50 50 53 ff 15 ?? ?? ?? ?? 8b f8 56 ff 75 e4 6a 01 57 e8 ?? ?? ?? ?? 83 c4 10 89 5d fc ff d7}  //weight: 10, accuracy: Low
        $x_10_2 = {74 42 57 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 8b f0 6a 40 68 00 10 00 00 56 53 ff 15 ?? ?? ?? ?? 89 45 e4 57 56 6a 01 50 e8 ?? ?? ?? ?? 83 c4 10 89 5d fc ff 55 e4}  //weight: 10, accuracy: Low
        $x_10_3 = {74 30 57 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 6a 40 68 00 10 00 00 8b f0 56 53 ff 15 ?? ?? ?? ?? 57 56 8b d8 6a 01 53 e8 ?? ?? ?? ?? 83 c4 10 ff d3}  //weight: 10, accuracy: Low
        $x_10_4 = {75 2f 53 ff 75 f8 ff 15 ?? ?? ?? ?? 6a 40 68 00 10 00 00 8b f0 56 53 ff 15 ?? ?? ?? ?? 53 8b f8 8d 45 ?? 50 56 57 ff 75 f8 ff 15 ?? ?? ?? ?? ff d7}  //weight: 10, accuracy: Low
        $x_10_5 = {74 29 38 5d 13 75 24 6a 40 be 00 10 00 00 56 56 53 ff 15 ?? ?? ?? ?? 53 8b f8 8d 45 ?? 50 56 57 ff 75 f8 ff 15 ?? ?? ?? ?? ff d7}  //weight: 10, accuracy: Low
        $x_10_6 = {83 c0 02 66 3b cb 75 ea 6a 40 be 00 10 00 00 56 56 53 ff 15 ?? ?? ?? ?? 53 68 80 00 00 00 6a 03 53 6a 01 68 00 00 00 80 57 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3}  //weight: 10, accuracy: Low
        $x_10_7 = {8d 78 fe 66 8b 4f 02 83 c7 02 66 3b ce 75 f4 be ?? ?? ?? ?? a5 a5 a5 a5 33 f6 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 50 ff 15}  //weight: 10, accuracy: Low
        $x_10_8 = {8d 7b fe 66 8b 47 02 83 c7 02 66 3b c6 75 f4 6a 05 59 be ?? ?? ?? ?? f3 a5 33 f6 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 53 ff 15}  //weight: 10, accuracy: Low
        $x_10_9 = {66 8b 4f 02 83 c7 02 66 3b cb 75 f4 53 be ?? ?? ?? ?? a5 68 80 00 00 00 6a 03 a5 53 6a 01 a5 68 00 00 00 80 50 a5 ff 15}  //weight: 10, accuracy: Low
        $x_10_10 = {83 c0 02 66 3b cf 75 ea 6a 40 be ?? ?? ?? ?? 56 56 57 ff 15 ?? ?? ?? ?? 57 68 80 00 00 00 6a 03 57 6a 01 68 00 00 00 80 53 a3 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
        $x_10_11 = {8d 78 fe 66 8b 4f 02 83 c7 02 66 3b ce 75 f4 6a 05 59 be ?? ?? ?? ?? f3 a5 33 f6 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 50 ff 15}  //weight: 10, accuracy: Low
        $x_2_12 = {64 6c 6c 5f 64 6f 77 6e 5f 65 78 65 63 2e 64 6c 6c 00 5f 66 6e 64 6f 74 40 31 36 00}  //weight: 2, accuracy: High
        $x_2_13 = {64 6c 6c 5f 64 6f 77 6e 5f 65 78 65 63 2e 64 6c 6c 00 5f 6c 64 72 40 31 36 00}  //weight: 2, accuracy: High
        $x_2_14 = {64 6c 6c 5f 64 6f 77 6e 5f 65 78 65 63 2e 64 6c 6c 00 5f 72 65 76 40 31 36 00}  //weight: 2, accuracy: High
        $x_2_15 = {64 6c 6c 5f 64 6f 77 6e 5f 65 78 65 63 2e 64 6c 6c 00 63 72 79 73 00}  //weight: 2, accuracy: High
        $x_2_16 = {6f 6d 67 2e 64 6c 6c 00 63 72 79 73 00}  //weight: 2, accuracy: High
        $x_2_17 = {64 61 66 61 6b 2e 64 6c 6c 00 63 72 79 73 00}  //weight: 2, accuracy: High
        $x_2_18 = {66 61 72 61 77 61 79 2e 64 6c 6c 00 63 72 79 73 00}  //weight: 2, accuracy: High
        $x_2_19 = {6c 6f 6f 61 6f 61 6f 61 6f 2e 64 6c 6c 00 63 72 79 73 00}  //weight: 2, accuracy: High
        $x_2_20 = {6e 74 64 6c 6c 2e 64 6c 6c 00 (63 72|6b 72) 00}  //weight: 2, accuracy: Low
        $x_2_21 = {75 73 65 72 33 32 2e 64 6c 6c 00 (63 72|6b 72) 00}  //weight: 2, accuracy: Low
        $x_2_22 = {6b 65 72 6e 65 6c 62 61 73 65 2e 64 6c 6c 00 (63 72|6b 72) 00}  //weight: 2, accuracy: Low
        $x_2_23 = {77 69 6e 69 6e 65 74 2e 64 6c 6c 00 (63 72|6b 72) 00}  //weight: 2, accuracy: Low
        $x_2_24 = {6f 6c 65 33 32 2e 64 6c 6c 00 (63 72|6b 72) 00}  //weight: 2, accuracy: Low
        $x_2_25 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 (63 72|6b 72) 00}  //weight: 2, accuracy: Low
        $x_2_26 = {66 77 66 77 65 2e 64 6c 6c 00 63 72 79 73 00}  //weight: 2, accuracy: High
        $x_2_27 = {73 78 72 68 64 2e 64 6c 6c 00 (63 72|6b 72) 00}  //weight: 2, accuracy: Low
        $x_2_28 = {73 78 72 73 68 64 2e 64 6c 6c 00 (63 72|6b 72) 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_S_2147680361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.S"
        threat_id = "2147680361"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a5 a5 a5 a5 33 f6 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 50 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 f8 ff 74 1a 56 68 20 30 00 10 53 ff 35 18 30 00 10 50 ff 15 08 20 00 10 ff 15 18 30 00 10}  //weight: 1, accuracy: Low
        $x_1_2 = {65 78 70 6c 6f 72 65 00 64 00 65 00 73 00 6b 00 00 00 00 00 74 00 6f 00 70 00 2e 00 69 00 6e 00 69 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_T_2147681935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.T"
        threat_id = "2147681935"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 83 f1 4e [0-2] 39 ?? ?? ?? ?? ?? 76 14 8a 14 30 32 d1 80 c2 ?? 88 14 30 46 3b 35 ?? ?? ?? ?? 72 ec ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_U_2147681937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.U"
        threat_id = "2147681937"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f0 4e 39 0d 40 30 00 10 76 14 8a 14 0e 32 d0 80 c2 42 88 14 0e 41 3b 0d 40 30 00 10 72 ec ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_V_2147682002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.V"
        threat_id = "2147682002"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 d1 80 c2 42 88 14 30 46 3b 35 ?? ?? ?? ?? 72 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_W_2147682094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.W"
        threat_id = "2147682094"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 02 88 45 e7 c7 45 fc ?? 00 00 00 0f b6 4d e7 83 f1 ?? 89 4d ec}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 4d 08 8a 11 80 c2 01 8b 45 08 88 10 eb de}  //weight: 2, accuracy: High
        $x_1_3 = {64 65 73 6b 74 6f 70 2e 69 6e 69 00 6f 00 70 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_B_2147682184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.gen!B"
        threat_id = "2147682184"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 07 fd e5 4c 0f 84 ?? ?? 00 00 3d 6c 32 81 81 0f 84 ?? ?? 00 00 3d af 33 e2 31 0f 84 ?? ?? 00 00 3d f6 7d d4 91 0f 84 ?? ?? 00 00 3d 54 dc cd e8 0f 84 ?? ?? 00 00 3d 6c 6d 8c 00 0f 84 ?? ?? 00 00 3d 0e ba d0 a8 0f 84 ?? ?? 00 00 3d 0e 3c ef a4 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_B_2147682184_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.gen!B"
        threat_id = "2147682184"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 32 44 dd 99 0f 84 ?? ?? 00 00 3d b4 9d 85 2d 0f 84 ?? ?? 00 00 3d ce 0d 34 64 0f 84 ?? ?? 00 00 3d 74 44 c5 63 0f 84 ?? ?? 00 00 3d 8b 9c 9c 34 0f 84 ?? ?? 00 00 3d ce eb 46 34 0f 84 ?? ?? 00 00 3d fe b1 a9 5b 0f 84 ?? ?? 00 00 3d f3 be e2 3c 0f 84 ?? ?? 00 00 3d 2b f0 46 3d 0f 84 ?? ?? 00 00 3d f7 10 ae 77 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_X_2147682237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.X"
        threat_id = "2147682237"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 1f 8b 15 ?? ?? ?? ?? 03 55 ?? 0f b6 02 33 45 ?? 03 45 fc 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 eb cd ff 15 ?? ?? ?? ?? 81 7d 14 00 70 00 00 75 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_Z_2147682244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.Z"
        threat_id = "2147682244"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 6f 00 00 00 66 89 45 e8 b9 70 00 00 00 66 89 4d ea ba 65 00 00 00 66 89 55 ec b8 6e 00 00 00 66 89 45 ee 33 c9 66 89 4d f0}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 fc 42 00 00 00 0f b6 [0-5] 83 ?? 4e}  //weight: 1, accuracy: Low
        $x_1_4 = {c6 45 c8 64 c6 45 c9 65 c6 45 ca 73 c6 45 cb 6b c6 45 cc 74 c6 45 cd 6f c6 45 ce 70 c6 45 cf 2e c6 45 d0 69 c6 45 d1 6e c6 45 d2 69}  //weight: 1, accuracy: High
        $x_1_5 = {c6 45 bc 64 c6 45 bd 65 c6 45 be 73 c6 45 bf 6b c6 45 c0 74 c6 45 c1 6f c6 45 c2 70 c6 45 c3 2e c6 45 c4 69 c6 45 c5 6e c6 45 c6 69}  //weight: 1, accuracy: High
        $x_1_6 = {c6 45 d4 64 c6 45 d5 65 c6 45 d6 73 c6 45 d7 6b c6 45 d8 74 c6 45 d9 6f c6 45 da 70 c6 45 db 2e c6 45 dc 69 c6 45 dd 6e c6 45 de 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Gamarue_AA_2147682250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AA"
        threat_id = "2147682250"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 1f 8b 15 ?? ?? ?? ?? 03 55 ?? 0f b6 02 33 45 ?? 03 45 fc 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 eb cd ff 15 ?? ?? ?? ?? 81 7d 14 ff ff ff 07 75 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_AB_2147682301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AB"
        threat_id = "2147682301"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b e5 5d c2 10 00 20 00 a1 ?? ?? ?? ?? 03 45 ?? 88 10 eb ?? 81 7d 14 ?? ?? ?? ?? 75 05 e8 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7d 14 88 88 88 08 75 05 e8 ?? ?? ?? ?? 8b e5 5d c2 10 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b e5 5d c2 10 00 13 00 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 eb ?? ff 15 01}  //weight: 1, accuracy: Low
        $x_10_4 = {6a 40 68 00 10 00 00 68 00 10 00 00 6a 00 ff 55}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_AJ_2147682937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AJ"
        threat_id = "2147682937"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 a0 1f 00 00 f7 f9 6a 04 [0-5] 68 00 10 00 00 8d 72 01 8b de 6b db 07}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 a0 1f 00 00 f7 f9 8d 7a 01 8b f7 6b f6 07}  //weight: 1, accuracy: High
        $x_1_3 = {4e 8d 50 01 8a 08 40 84 c9 75 f9 2b c2 8b c8 0f 31 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Gamarue_AL_2147687832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AL!!Gamarue.gen!A"
        threat_id = "2147687832"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 50 4b 00 00 66 3b c1 75 32}  //weight: 2, accuracy: High
        $x_1_2 = {81 39 2e 74 65 78}  //weight: 1, accuracy: High
        $x_1_3 = "5cjni" ascii //weight: 1
        $x_1_4 = {35 63 72 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {b8 00 68 6e 70}  //weight: 1, accuracy: High
        $x_1_6 = {35 4e 1a 4d a5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_AM_2147687862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AM"
        threat_id = "2147687862"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 50 4b 00 00 66 3b c1 75 32}  //weight: 2, accuracy: High
        $x_1_2 = {81 39 2e 74 65 78}  //weight: 1, accuracy: High
        $x_1_3 = "5cjni" ascii //weight: 1
        $x_1_4 = {35 63 72 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {b8 00 68 6e 70}  //weight: 1, accuracy: High
        $x_1_6 = {35 4e 1a 4d a5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_I_2147688060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.I!!Gamarue.gen!A"
        threat_id = "2147688060"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 6c 6f 6c 00 8b c4 50 6a 00 68 01 00 1f 00 ff 55}  //weight: 1, accuracy: High
        $x_1_2 = {68 64 6c 6c 00 68 64 6c 6c 2e 68 73 62 69 65 8b c4 50 ff 55 ?? 83 c4 0c 85 c0 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {b0 68 aa 8b 45 08 2b 45 ?? 03 45 ?? ab b0 c3 aa c7 85 ?? ?? ff ff 02 00 01 00 8d 85 ?? ?? ff ff 50}  //weight: 1, accuracy: Low
        $x_1_4 = {03 40 3c 8d 40 18 8b 40 38 89 45 ?? 33 c9 89 4d ?? 51 68 00 00 00 08 6a 40 03 00 8b 45}  //weight: 1, accuracy: Low
        $x_1_5 = {c0 bd f0 ff c7 45 ?? ff ff ff ff 8d 45 ?? 50 6a 00 e8 ?? ?? 00 00 33 c9 89 4d ?? 89 4d ?? 6a 40 51 6a 01 8d 45 ?? 50 51 51 51 8d 45 ?? 50}  //weight: 1, accuracy: Low
        $x_1_6 = {64 8b 15 30 00 00 00 8b 52 18 68 04 01 00 00 6a 08 52 ff d0}  //weight: 1, accuracy: High
        $x_1_7 = {ff d0 03 45 ?? c7 00 5c 2a 2e 64 (c7|83 c0 04) 6c 6c 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {8b c8 8b 45 0c 89 38 f3 a4 b0 e9 aa 8d 46 ?? 2b c7 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Gamarue_AN_2147688539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AN"
        threat_id = "2147688539"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef}  //weight: 1, accuracy: High
        $x_1_2 = {b8 fc fd fe ff fd ab 2d 04 04 04 04 e2 f8 fc}  //weight: 1, accuracy: High
        $x_1_3 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 fc c7 84 05 e0 fe ff ff 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Gamarue_AN_2147689388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AN!!Gamarue.gen!A"
        threat_id = "2147689388"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef}  //weight: 1, accuracy: High
        $x_1_2 = {b8 fc fd fe ff fd ab 2d 04 04 04 04 e2 f8 fc}  //weight: 1, accuracy: High
        $x_1_3 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 fc c7 84 05 e0 fe ff ff 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Gamarue_AO_2147689396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AO"
        threat_id = "2147689396"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0c 6a ff c7 45 ec 07 80 00 00 ff 50 18 e8 ?? ?? ?? ?? 8d 98 ?? ?? ?? ?? ff 73 10 8b 45 0c 8d 73 ?? 56 33 ff 57 89 5d d8 ff 50 10}  //weight: 1, accuracy: Low
        $x_1_2 = {80 3e eb 75 1b 0f b6 46 01 84 c0 79 05 0d 00 ff ff ff 8d 74 06 02 83 7d 18 0a 75 c2 33 c0 eb 27 8b 45 08 57 8b 7d 10 53 56 57 ff 50 30 2b f7 8d 04 3b c6 00 e9 83 ee 05 89 70 01 8b 45 14 89 38}  //weight: 1, accuracy: High
        $x_1_3 = {80 3e eb 75 13 0f b6 46 01 84 c0 79 05 0d 00 ff ff ff 8d 74 06 02 eb b9 50 56 ff 75 f8 ff 55 dc 8b 45 f8 8b 4d fc c6 04 08 e9 8b 45 f8 8b 4d fc 2b f0 83 ee 05 89 74 08 01}  //weight: 1, accuracy: High
        $x_5_4 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef}  //weight: 5, accuracy: High
        $x_5_5 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_AP_2147690726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AP"
        threat_id = "2147690726"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 eb 0b 0f be c9 33 c8 c1 c1 0a 8b c1 42 8a 0a 84 c9 75 ef 35 3e c7 a6 13 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d fc 8b 55 dc 8b 75 e4 03 ca 89 0e 8b 4d fc 8d 3c 0a 8b c8 03 d0 8b f3 f3 a4 8b 4d fc c6 04 0a e9 8b 4d fc 2b c2 2b c1 8d 44 18 fb 8b 5d e4 89 44 0a 01 83 c2 05 89 55 dc eb 03}  //weight: 1, accuracy: High
        $x_1_3 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_AS_2147693197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AS"
        threat_id = "2147693197"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 63 6a 6e 69 50 8d 85 e4 fd ff ff 53 50 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {8b 56 1c 81 f9 4b 43 41 50 75 46 57 52 8d 7e 2c 57 53 e8}  //weight: 1, accuracy: High
        $x_1_3 = {4b 00 42 00 25 00 30 00 38 00 6c 00 75 00 2e 00 65 00 78 00 65 00 00 00 25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 00 00 25 00 54 00 4d 00 50 00 25 00 5c 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 6d 00 73 00 25 00 73 00 2e 00 65 00 78 00 65 00 00 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {45 00 6e 00 61 00 62 00 6c 00 65 00 4c 00 55 00 41 00 00 00 48 00 69 00 64 00 65 00 53 00 43 00 41 00 48 00 65 00 61 00 6c 00 74 00 68 00 00 00 54 00 61 00 73 00 6b 00 62 00 61 00 72 00 4e 00 6f 00 4e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = "{\"id\":%lu,\"tid\":%lu,\"err\":%lu,\"w32\":%lu}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_AS_2147693198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AS!!Gamarue.gen!A"
        threat_id = "2147693198"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 63 6a 6e 69 50 8d 85 e4 fd ff ff 53 50 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {8b 56 1c 81 f9 4b 43 41 50 75 46 57 52 8d 7e 2c 57 53 e8}  //weight: 1, accuracy: High
        $x_1_3 = {4b 00 42 00 25 00 30 00 38 00 6c 00 75 00 2e 00 65 00 78 00 65 00 00 00 25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 00 00 25 00 54 00 4d 00 50 00 25 00 5c 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 6d 00 73 00 25 00 73 00 2e 00 65 00 78 00 65 00 00 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {45 00 6e 00 61 00 62 00 6c 00 65 00 4c 00 55 00 41 00 00 00 48 00 69 00 64 00 65 00 53 00 43 00 41 00 48 00 65 00 61 00 6c 00 74 00 68 00 00 00 54 00 61 00 73 00 6b 00 62 00 61 00 72 00 4e 00 6f 00 4e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = "{\"id\":%lu,\"tid\":%lu,\"err\":%lu,\"w32\":%lu}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Gamarue_AT_2147695665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AT"
        threat_id = "2147695665"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 6d 58 6a 73 66 89 45 ?? 58 6a 69 66 89 45 ?? 58 6a 65 [0-3] 66 89 45 ?? 58 6a 78 8b c8 66 89 4d ?? 59 66 89 4d ?? 6a 63 8b c8 66 89 4d ?? 59 6a 2e 66 89 4d ?? 59 66 89 4d ?? 8b c8 [0-6] 6a 78}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 08 81 f9 09 13 ac 01 74 34 81 f9 00 1e 4d 7e 74 27 81 f9 01 1e 4d 7e 74 1a 81 f9 00 00 ce ba 74 0d 81 f9 00 e0 1c ca 75 19 8b 4d 10}  //weight: 2, accuracy: High
        $x_2_3 = {2b f3 8d 04 0b 2b f1 83 ee 05 83 c1 05 c6 00 e9 89 70 01 81 f9 00 40 00 00 77 ?? ff [0-3] 8b [0-3] 8b 45 ?? 8d 04 c8 8d 48 04 83 39 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_AO_2147696025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AO!!Gamarue.gen!A"
        threat_id = "2147696025"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0c 6a ff c7 45 ec 07 80 00 00 ff 50 18 e8 ?? ?? ?? ?? 8d 98 ?? ?? ?? ?? ff 73 10 8b 45 0c 8d 73 ?? 56 33 ff 57 89 5d d8 ff 50 10}  //weight: 1, accuracy: Low
        $x_5_2 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef}  //weight: 5, accuracy: High
        $x_5_3 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_AP_2147696026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AP!!Gamarue.gen!A"
        threat_id = "2147696026"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 eb 0b 0f be c9 33 c8 c1 c1 0a 8b c1 42 8a 0a 84 c9 75 ef 35 3e c7 a6 13 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d fc 8b 55 dc 8b 75 e4 03 ca 89 0e 8b 4d fc 8d 3c 0a 8b c8 03 d0 8b f3 f3 a4 8b 4d fc c6 04 0a e9 8b 4d fc 2b c2 2b c1 8d 44 18 fb 8b 5d e4 89 44 0a 01 83 c2 05 89 55 dc eb 03}  //weight: 1, accuracy: High
        $x_1_3 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_AQ_2147696027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AQ!!Gamarue.gen!A"
        threat_id = "2147696027"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3e eb 75 1b 0f b6 46 01 84 c0 79 05 0d 00 ff ff ff 8d 74 06 02 83 7d 18 0a 75 c2 33 c0 eb 27 8b 45 08 57 8b 7d 10 53 56 57 ff 50 30 2b f7 8d 04 3b c6 00 e9 83 ee 05 89 70 01 8b 45 14 89 38}  //weight: 1, accuracy: High
        $x_5_2 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef}  //weight: 5, accuracy: High
        $x_5_3 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_AR_2147696028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AR!!Gamarue.gen!A"
        threat_id = "2147696028"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3e eb 75 13 0f b6 46 01 84 c0 79 05 0d 00 ff ff ff 8d 74 06 02 eb b9 50 56 ff 75 f8 ff 55 dc 8b 45 f8 8b 4d fc c6 04 08 e9 8b 45 f8 8b 4d fc 2b f0 83 ee 05 89 74 08 01}  //weight: 1, accuracy: High
        $x_5_2 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef}  //weight: 5, accuracy: High
        $x_5_3 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_AT_2147696029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AT!!Gamarue.gen!A"
        threat_id = "2147696029"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 6d 58 6a 73 66 89 45 ?? 58 6a 69 66 89 45 ?? 58 6a 65 8b 75 ?? 66 89 45 ?? 58 6a 78 8b c8 66 89 4d ?? 59 66 89 4d ?? 6a 63 8b c8 66 89 4d ?? 59 6a 2e 66 89 4d ?? 59 66 89 4d ?? 8b c8 66 89 45 ?? 33 c0 6a 78}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 08 81 f9 09 13 ac 01 74 34 81 f9 00 1e 4d 7e 74 27 81 f9 01 1e 4d 7e 74 1a 81 f9 00 00 ce ba 74 0d 81 f9 00 e0 1c ca 75 19 8b 4d 10}  //weight: 2, accuracy: High
        $x_2_3 = {2b f3 8d 04 0b 2b f1 83 ee 05 83 c1 05 c6 00 e9 89 70 01 81 f9 00 40 00 00 77 ?? ff 44 24 ?? 8b 4c 24 ?? 8b 45 ?? 8d 04 c8 8d 48 04 83 39 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_AU_2147696544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AU"
        threat_id = "2147696544"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 00 68 6e 70}  //weight: 1, accuracy: High
        $x_1_2 = {35 63 72 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "5tixe" ascii //weight: 1
        $x_1_4 = "5cjni" ascii //weight: 1
        $x_1_5 = {81 f9 4b 43 41 50}  //weight: 1, accuracy: High
        $x_1_6 = "5tsil" ascii //weight: 1
        $x_1_7 = {69 73 5f 6e 6f 74 5f 76 6d 00}  //weight: 1, accuracy: High
        $x_1_8 = {63 64 6f 25 6c 75 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = {4b 42 25 30 38 6c 75 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_10 = {99 ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad}  //weight: 2, accuracy: High
        $x_1_11 = {8b ce 2b cb 8d 04 1f 8b 1d [0-8] 83 e9 05 c6 00 e9 89 48 01}  //weight: 1, accuracy: Low
        $x_1_12 = {3a 00 25 00 6c 00 75 00 [0-4] 74 00 69 00 64 00 [0-4] 3a 00 25 00 6c 00 75 00 [0-4] 65 00 72 00 72 00 [0-4] 3a 00 25 00 6c 00 75 00 [0-4] 77 00 33 00 32 00 [0-4] 3a 00 25 00 6c 00 75 00}  //weight: 1, accuracy: Low
        $x_1_13 = {3a 25 6c 75 [0-4] 74 69 64 [0-4] 3a 25 6c 75 [0-4] 65 72 72 [0-4] 3a 25 6c 75 [0-4] 77 33 32 [0-4] 3a 25 6c 75}  //weight: 1, accuracy: Low
        $x_2_14 = {3a 00 25 00 6c 00 75 00 [0-4] 62 00 69 00 64 00 [0-4] 3a 00 25 00 6c 00 75 00 [0-4] 6f 00 73 00 [0-4] 3a 00 25 00 6c 00 75 00 [0-4] 6c 00 61 00 [0-4] 3a 00 25 00 6c 00 75 00 [0-4] 72 00 67 00 [0-4] 3a 00 25 00 6c 00 75 00}  //weight: 2, accuracy: Low
        $x_2_15 = {3a 25 6c 75 [0-4] 62 69 64 [0-4] 3a 25 6c 75 [0-4] 6f 73 [0-4] 3a 25 6c 75 [0-4] 6c 61 [0-4] 3a 25 6c 75 [0-4] 72 67 [0-4] 3a 25 6c 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_AU_2147696545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AU!!Gamarue.gen!A"
        threat_id = "2147696545"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 fc 00 68 6e 70}  //weight: 1, accuracy: High
        $x_1_2 = {35 63 72 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "5tixe" ascii //weight: 1
        $x_1_4 = "5cjni" ascii //weight: 1
        $x_1_5 = {81 f9 4b 43 41 50}  //weight: 1, accuracy: High
        $x_1_6 = {69 73 5f 6e 6f 74 5f 76 6d 00}  //weight: 1, accuracy: High
        $x_1_7 = {63 64 6f 25 6c 75 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {4b 42 25 30 38 6c 75 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Gamarue_AV_2147705491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AV"
        threat_id = "2147705491"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 83 e8 02 50 e8 d9 ff ff ff 83 c4 04 8b f0 6a 01 e8 cd ff ff ff 83 c4 04 8d 74 06 01 6a 00 e8 bf ff ff ff 83 c4 04 83 c0 01 2b f0 8b 4d 08 83 e9 01 51 e8 ab ff ff ff 83 c4 04 03 c6}  //weight: 1, accuracy: High
        $x_1_2 = {eb 4e f7 d3 f7 d3 8b d9 0f a5 d3 81 f3 e9 08 ab c2 0f ba ff 21 0f a5 f7 13 dd c1 e3 d1 8b dd 33 d9 0f cb bb c1 80 43 fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_PLA_2147716305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.PLA!!Gamarue.gen!A"
        threat_id = "2147716305"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "USBTHREAD" wide //weight: 1
        $x_1_2 = "Global\\msiff0x1" wide //weight: 1
        $x_1_3 = {25 03 00 00 80 79 05 48 83 c8 fc 40 83 c0 08 39 45 ?? 7d 4b e8 ?? ?? ?? ?? 99 b9 4b 00 00 00 f7 f9 83 c2 30 89 55 ?? 83 7d ?? 30 7c 06 83 7d ?? 39 7e 0c 83 7d ?? 61 7c 1b 83 7d ?? 7a 7f 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_PLB_2147716306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.PLB!!Gamarue.gen!A"
        threat_id = "2147716306"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%tmp%\\tv.dll" wide //weight: 1
        $x_1_2 = ",\"tvid\":%lu,\"tvpw\":%lu" ascii //weight: 1
        $x_1_3 = {68 83 4e 00 00 57 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 40 68 00 01 00 00 8d 85 00 ff ff ff 50 68 82 4e 00 00 57 ff 15 ?? ?? ?? ?? 85 c0 74 24 8d 85 00 ff ff ff 50 e8 ?? ?? ?? ?? 8d 85 00 ff ff ff 50 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_PLC_2147716307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.PLC!!Gamarue.gen!A"
        threat_id = "2147716307"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ",\"s5\":%lu" ascii //weight: 1
        $x_1_2 = {ff 75 08 e8 ?? ?? ?? ?? 0b c0 74 05 83 f8 ff 75 02 eb 4b 80 bd d4 fe ff ff 05 75 42 0f b6 8d d5 fe ff ff 85 c9 74 37 8d bd d6 fe ff ff 33 c0 f2 ae 75 2b c6 85 cf fe ff ff 00 c7 85 d0 fe ff ff 05 00 00 00 6a 00 6a 02 8d 85 d0 fe ff ff 50 ff 75 08 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_PLD_2147716308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.PLD!!Gamarue.gen!A"
        threat_id = "2147716308"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{\"s\":%lu,\"t\":%lu,\"a\":\"%s\",\"u\":\"" ascii //weight: 1
        $x_1_2 = ",\"fg\":\"" ascii //weight: 1
        $x_1_3 = {83 c4 0c 83 e9 05 c6 00 e9 89 48 01 8d 45 14 50 6a 40 57 56 ff d3 85 c0 74 2b 8b 45 0c 2b c6 83 e8 05 89 46 01 8d 45 14 50 ff 75 14 c6 06 e9 57 56 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_PLE_2147716309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.PLE!!Gamarue.gen!A"
        threat_id = "2147716309"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "Gamarue: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"},{\"t\":%lu,\"p\":\"%s\",\"c\":\"%s%s\",\"d\":\"%s" wide //weight: 1
        $x_1_2 = ",\"kl\":\"" ascii //weight: 1
        $x_1_3 = {83 c4 0c 83 e9 05 c6 00 e9 89 48 01 8d 45 14 50 6a 40 57 56 ff d3 85 c0 74 2b 8b 45 0c 2b c6 83 e8 05 89 46 01 8d 45 14 50 ff 75 14 c6 06 e9 57 56 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_BA_2147719658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.BA"
        threat_id = "2147719658"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Desktop\\ShellExec\\out\\" ascii //weight: 3
        $x_3_2 = {62 00 4b 00 52 00 73 00 7a 00 67 00 53 00 4b 00 74 00 66 00 45 00 00 00 5c 00 49 00 6e 00 64 00 65 00 78 00 65 00 72 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 47 00 75 00 69 00 64 00}  //weight: 3, accuracy: High
        $x_2_3 = "oezqenf4mlhxcm4vno5goavqsko8mkur7uynjni1l16q2etx55wfumxk" ascii //weight: 2
        $x_2_4 = "\\pitgnpetvgk.pdb" ascii //weight: 2
        $x_1_5 = "xdxkjeniace" ascii //weight: 1
        $x_1_6 = "qbrexksAMhy" ascii //weight: 1
        $x_1_7 = "obj=%S;%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_BE_2147726561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.BE!bit"
        threat_id = "2147726561"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4e 04 03 c7 8a 04 08 32 06 8b 4c 24 14 32 c3 43 88 04 0f 66 3b 5e 02 72 de}  //weight: 1, accuracy: High
        $x_1_2 = {64 8b 35 30 00 00 00 e8 ?? ?? ?? ff 8b 46 0c 8b 40 0c 8b 30 e8 ?? ?? ?? ff ff 76 18}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 10 8b f2 c1 ee ?? 33 f2 69 f6 ?? ?? ?? ?? 03 f1 89 70 04 83 c0 04 41 3d ?? ?? ?? 00 7c e1}  //weight: 1, accuracy: Low
        $x_1_4 = {be ff ff ff 7f 8b ca 8b 04 8d ?? ?? ?? 00 33 04 8d ?? ?? ?? 00 23 c6 33 04 8d ?? ?? ?? 00 8b f8 d1 e8 83 e7 01 33 04 bd ?? ?? ?? 00 33 04 8d ?? ?? ?? 00 42 89 04 8d ?? ?? ?? 00 81 fa ?? 00 00 00 7c c2}  //weight: 1, accuracy: Low
        $x_1_5 = {50 6a 0e e8 ?? ?? ?? 00 8d 85 ?? ?? ?? ff 50 ff 75 08 ff d3 89 46 ?? 8d 85 ?? ?? ?? ff 50 6a 0f e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Gamarue_AR_2147743442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.AR!MTB"
        threat_id = "2147743442"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 bc 9a 00 00 00 c7 45 ?? ?? 00 00 00 c7 45 ?? ?? 00 00 00 c7 45 ?? ?? 00 00 00 c7 45 ?? ?? 00 00 00 c7 45 ?? ?? 00 00 00 c7 45 ?? ?? 00 00 00 c7 45 ?? ?? 00 00 00 c7 45 ?? ?? 00 00 00 8b 0d ?? ?? ?? ?? 83 c1 ?? 89 4d ?? c7 45 ?? ?? 00 00 00 c7 45 ?? ?? 00 00 00 c7 45 ?? ?? 00 00 00 6a ?? 68 00 00 40 00 8d 95 ?? ?? ?? ?? 52 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "ShellExec\\out\\release\\noubmnza.pdb" ascii //weight: 1
        $x_1_3 = "IndexerVolumeGuid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_OS_2147744667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.OS!MTB"
        threat_id = "2147744667"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 5c 6d 61 72 69 65 ?? 5c 64 65 76 69 6c 6d 61 6e 5c 78 78 78 78 78 5c 63 61 74 66 69 67 68 74 5c 69 79 67 6d 79 67 6a 6b 78 74 79 75 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "iygmygjkxtyu.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Gamarue_G_2147765133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.G!MSR"
        threat_id = "2147765133"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ShellExec\\out\\release\\dlmqsjwy.pdb" ascii //weight: 5
        $x_2_2 = "SOctnMIyCKmWFRRa" ascii //weight: 2
        $x_2_3 = "bimdbexnnvyh" ascii //weight: 2
        $x_2_4 = "gxMQHCWAWSk" ascii //weight: 2
        $x_2_5 = "yojdmfwscmr" ascii //weight: 2
        $x_2_6 = "zWNowiVfKAQdSv" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_G_2147765133_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.G!MSR"
        threat_id = "2147765133"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ShellExec\\out\\release\\vvphpdit.pdb" ascii //weight: 5
        $x_5_2 = "ShellExec\\out\\release\\bpzweru.pdb" ascii //weight: 5
        $x_2_3 = "RBpxAnUDZSeiz" ascii //weight: 2
        $x_2_4 = "cmfvdwztqoytx" ascii //weight: 2
        $x_2_5 = "bniywamosjojwbjk" ascii //weight: 2
        $x_2_6 = "gwaWdFvvocQ" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Gamarue_DK_2147787523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gamarue.DK!MTB"
        threat_id = "2147787523"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "CreateFileW" ascii //weight: 3
        $x_3_2 = "ShellExecuteW" ascii //weight: 3
        $x_3_3 = "sktop.ini" ascii //weight: 3
        $x_3_4 = "0#00080F0K0P0U0" ascii //weight: 3
        $x_3_5 = "0.1J1Q1Z1f1n1u1|" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

