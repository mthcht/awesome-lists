rule VirTool_Win32_Injector_2147565599_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector"
        threat_id = "2147565599"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 59 0d 33 d2 8b c7 f7 f3 8a 59 0c 8a c2 f6 69 0e 8a 16 02 c3 32 d0 88 16 8b 41 04 46 47 3b f8 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_2147565599_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector"
        threat_id = "2147565599"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 6a 12 59 b8 cc cc cc cc f3 ab 59 89 55 f8 89}  //weight: 1, accuracy: High
        $x_1_2 = {4d e0 03 48 04 39 4d d0 73 78 8b 4d d0 e8}  //weight: 1, accuracy: High
        $x_1_3 = {eb 66 83 65 d0 00 6a 2e 5a 8b 4d c0 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_2147565599_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector"
        threat_id = "2147565599"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f bf d0 89 15 68 90 40 00 8b 4d d8 81 c1 aa 38 00 00 a1 64 90 40 00 99 f7 f9 89 55 fc 0f bf 0d 7e 90 40 00 81 c1 a7 00 00 00 8b 45 fc 99}  //weight: 1, accuracy: High
        $x_1_2 = {0f 9d c2 83 e2 01 0b 55 fc 74 2f 8b 0d 64 90 40 00 81 c1 21 0d 00 00 a1 84 90 40 00 99 f7 f9 0f bf 0d 8a 90 40 00 3b d1 7d 10 0f be 05 91 90 40 00 33 05 68 90 40 00 89 45 fc a1 84 90 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_B_2147607830_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!B"
        threat_id = "2147607830"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "vmware" ascii //weight: 2
        $x_2_2 = "sandbox" ascii //weight: 2
        $x_1_3 = "SwapMouseButtons" ascii //weight: 1
        $x_1_4 = "Blind Access" ascii //weight: 1
        $x_1_5 = {43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c (4d 6f 75|41 63 63 65 73 73 69 62 69 6c 69)}  //weight: 1, accuracy: Low
        $x_10_6 = {0f be 00 83 f8 e8 74 0b 8b 45 ?? 0f be 00 83 f8 e9 75 08 6a 01 58 e9}  //weight: 10, accuracy: Low
        $x_10_7 = {0f be 11 83 fa e8 74 0b 8b 45 ?? 0f be 08 83 f9 e9 75 0a b8 01 00 00 00 e9}  //weight: 10, accuracy: Low
        $x_10_8 = {8a 00 3c e8 0f 84 ?? ?? 00 00 3c e9 0f 84 ?? ?? 00 00 a1 ?? ?? ?? ?? 8a 00 3c e8 0f 84 ?? ?? 00 00 3c e9 0f 84}  //weight: 10, accuracy: Low
        $x_10_9 = {8b 45 fc 80 38 e8 74 0a 8b 45 fc 80 38 e9 74 02 eb 0c}  //weight: 10, accuracy: High
        $x_10_10 = {6a 40 68 00 30 00 00 ff 75 ?? 8b 45 ?? ff 70 34 ff b5 ?? ?? ff ff ff}  //weight: 10, accuracy: Low
        $x_10_11 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 4d ?? 8b 51 34 52 8b 85 ?? ?? ff ff 50 ff}  //weight: 10, accuracy: Low
        $x_10_12 = {8b 46 34 8b 4c 24 ?? 6a 40 68 00 30 00 00 57 50 51 ff}  //weight: 10, accuracy: Low
        $x_10_13 = {c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 8b 45 ?? 89 44 24 08 8b 45 ?? 8b 40 34 89 44 24 04 8b 45 ?? 89 04 24}  //weight: 10, accuracy: Low
        $x_10_14 = {03 c2 99 be 00 01 00 00 f7 fe 0f b6 84 15 ?? ?? ff ff 33 c8 8b 85 ?? ?? ff ff 03 85 ?? ?? ff ff 88 08}  //weight: 10, accuracy: Low
        $x_10_15 = {8a 1c 2f 8b 8c 24 ?? ?? 00 00 32 d3 40 88 17 3b c1 7c}  //weight: 10, accuracy: Low
        $x_10_16 = {89 d0 0f b6 84 28 ?? ?? ff ff 8b 8d ?? ?? ff ff 32 01 8b 95 ?? ?? ff ff 88 02 8d 45 ?? ff 00 e9}  //weight: 10, accuracy: Low
        $x_10_17 = {55 8b ec 56 8b 4d 0c 8b 75 08 c1 0c 0e ?? 83 e9 03 e2 f7 c1 0e ?? 5e 5d c3}  //weight: 10, accuracy: Low
        $x_10_18 = {6a 40 68 00 30 00 00 ff 76 50 8d 46 34 ff 30 89 45 ?? ff 35 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_10_19 = {89 d0 0f b6 84 28 ?? ?? ff ff 8b 8d ?? ?? ff ff 32 01 8b 95 ?? ?? ff ff 88 02 8d 85 ?? ?? ff ff ff 00 e9 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_10_20 = {c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 8b 45 ?? 89 44 24 08 8b 45 ?? 8b 40 1c 89 44 24 04 8b 45 ?? 89 04 24 (e8|a1 ?? ?? ?? ??)}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_C_2147607913_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!C"
        threat_id = "2147607913"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {03 cb 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 33 c0 8a 84 0d 00 ff ff ff 33 d0 8b 8d e8 fe ff ff 03 8d f8 fe ff ff 88 11 e9}  //weight: 100, accuracy: High
        $x_1_2 = "CurrentUser" ascii //weight: 1
        $x_1_3 = "vmware" ascii //weight: 1
        $x_1_4 = "sandbox" ascii //weight: 1
        $x_1_5 = "SwapMouseButtons" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_F_2147608604_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!F"
        threat_id = "2147608604"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c9 45 66 8b 4f 06 83 c6 28 3b e9 72 ?? 8b 84 24 ?? ?? 00 00 8b 4c 24 ?? 6a 00 8d 54 24 ?? 6a 04 83 c0 08 52 50 51 ff}  //weight: 10, accuracy: Low
        $x_5_2 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 50 6a 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_3 = {8b 44 24 04 c1 e8 1d 8b 04 85 ?? ?? ?? ?? c3}  //weight: 5, accuracy: Low
        $x_5_4 = {6a 00 68 00 30 00 00 (8b 85 ?? ??|a1 ?? ?? ?? ??) ff 70 50 (8b 85 ?? ??|a1 ?? ?? ?? ??) ff 70 34 ff (35 ?? ?? ?? ??|b5 ?? ??) e8}  //weight: 5, accuracy: Low
        $x_5_5 = {0f b7 51 06 39 15 ?? ?? ?? ?? 73 13 00 a1 ?? ?? ?? ?? 83 c0 01 a3 ?? ?? ?? ?? 8b 8d}  //weight: 5, accuracy: Low
        $x_5_6 = {0f b7 40 06 39 05 ?? ?? ?? ?? 73 11 00 a1 00 40 a3 00 8b 85}  //weight: 5, accuracy: Low
        $x_5_7 = {0f b7 40 06 39 05 ?? ?? ?? ?? 7d 10 00 a1 00 40 a3 00 a1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_I_2147609183_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!I"
        threat_id = "2147609183"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 4c 0c 14 32 0c 2f 88 0f 8b 8c 24 20 01 00 00 40 3b c1 7c}  //weight: 10, accuracy: High
        $x_1_2 = {80 7c 24 1c 01 75 1c 8b 54 24 28 8b 43 1c 6a 40 68 00 30 00 00 52 50 56 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 40 06 85 c0 7e 2d 53 8b 5c 24 ?? 55 83 c3 08 8b e8 8b 0b 85 c9 74 14 33 d2 8b c1 f7 f6 85 d2 75 04 03 f9 eb 06 40 0f af c6 03 f8 83 c3 28}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 47 34 6a 40 68 00 30 00 00 53 50 56 ff}  //weight: 1, accuracy: High
        $x_1_5 = {0f b7 55 06 40 83 c7 28 3b c2 89 44 24 ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_O_2147616022_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!O"
        threat_id = "2147616022"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_2 = "htmlfile\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = {33 c0 8a 0c 03 80 f1 88}  //weight: 1, accuracy: High
        $x_1_5 = {a7 e1 ea e1 e6 a7 fc e3 fb ed fa fe a6 ec e4 e4}  //weight: 1, accuracy: High
        $x_1_6 = {85 c0 74 0e 6a 00 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_Q_2147616964_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!Q"
        threat_id = "2147616964"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 11 88 19 41 ff 4d 0c 75 f5 5b 03 c7 c6 00 e9 40 2b f0 8d 4c 3e fc 89 08}  //weight: 1, accuracy: High
        $x_1_2 = {8d 85 f8 fb ff ff b9 00 01 00 00 89 10 42 83 c0 04 3b d1 7c f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_R_2147616965_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!R"
        threat_id = "2147616965"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b 45 08 03 85 fc fb ff ff 8a 10 32 94 8d 00 fc ff ff 8b 45 08 03 85 fc fb ff ff 88 10}  //weight: 1, accuracy: High
        $x_1_2 = {68 9a 02 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_S_2147617367_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!S"
        threat_id = "2147617367"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 8b 45 08 03 45 fc 8a 10 32 94 8d fc fb ff ff 8b 45 08 03 45 fc 88 10}  //weight: 2, accuracy: High
        $x_1_2 = {68 9a 02 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {68 2b 02 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_T_2147621666_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!T"
        threat_id = "2147621666"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac 8b c8 03 f8 d3 c7 85 c0 75 f5}  //weight: 1, accuracy: High
        $x_2_2 = {8b 47 28 01 05}  //weight: 2, accuracy: High
        $x_1_3 = {32 fb c0 c1 1b fe cf 80 ff 01 75 f6 32 ca 32 ed}  //weight: 1, accuracy: High
        $x_1_4 = {0f 31 2b c6 25 00 f0 ff ff 0c 05 33 c9 0f 00 c1 03 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_V_2147622106_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!V"
        threat_id = "2147622106"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 4c 0c 14 32 0c 2f 88 0f 8b 8c 24 20 01 00 00 40 3b c1 7c 9e}  //weight: 1, accuracy: High
        $x_1_2 = {68 50 4b 00 00 68 ?? ?? ?? ?? 6a 0e 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {02 cb 88 88 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 02 d1 88 90 ?? ?? ?? ?? 83 c0 02 3d e0 00 00 00 72 d4}  //weight: 1, accuracy: Low
        $x_1_4 = {0f af c6 8d 4c 01 01 8d 44 02 01 a3 ?? ?? ?? ?? 0f b7 55 06 43 83 c7 28 3b da 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_W_2147622484_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!W"
        threat_id = "2147622484"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0c 37 40 83 f8 0b 72 f1 8a 04 37 56 f6 d0 88 04 37 47}  //weight: 1, accuracy: High
        $x_1_2 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed}  //weight: 1, accuracy: High
        $x_1_3 = {eb 0b 8b 4f 10 03 c8 89 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_X_2147622974_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!X"
        threat_id = "2147622974"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 4c 0c 14 32 0c 2f 88 0f 8b 8c 24 20 01 00 00 40 3b c1 7c 9e}  //weight: 1, accuracy: High
        $x_1_2 = {02 cb 88 88 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 02 d1 88 90 ?? ?? ?? ?? 83 c0 02 3d e0 00 00 00 72 d4}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 6c 24 14 33 db 66 39 5d 06 76 ?? 57 8b 7c 24 28 83 c7 08 8b 07 85 c0 74 ?? 33 d2 f7 f1 85 d2 8b 15 ?? ?? ?? ?? 75 ?? 8b 07 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AD_2147627354_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AD"
        threat_id = "2147627354"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 08 8b 55 0c 03 55 f4 33 c0 8a 02 8b 55 f8 6b d2 09 03 c2 33 d2 be e8 03 00 00 f7 f6 2b ca 89 4d fc}  //weight: 3, accuracy: High
        $x_1_2 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_4_3 = "do del \"%s\" && if exist \"%s\" ping" ascii //weight: 4
        $x_1_4 = "The Wireshark Network Analyzer" ascii //weight: 1
        $x_1_5 = "- Sysinternals: www.sysinternals.com" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "SetThreadContext" ascii //weight: 1
        $x_1_8 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_AE_2147627680_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AE"
        threat_id = "2147627680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 ?? 33 c9 8a 08 8b 55 0c 03 55 ?? 33 c0 8a 02 8b 55 ?? 6b d2 09 03 c2 33 d2 be e8 03 00 00 f7 f6 2b ca 89 ?? ?? 83 7d 10 64}  //weight: 1, accuracy: Low
        $x_1_2 = {3f e9 d7 21 33 db c7 45 ?? 0e a6 09 b7 64 8b 1d 30 00 00 00 c7 45 ?? 5e 64 c5 e7 8b 5b 0c 8b 5b 14 c7 45 ?? 0b 56 e0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AF_2147627755_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AF"
        threat_id = "2147627755"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 d1 03 c2 25 ff 00 00 80 79 ?? 48 0d 00 ff ff ff 40}  //weight: 2, accuracy: Low
        $x_1_2 = {35 9b 00 00 00 58}  //weight: 1, accuracy: High
        $x_1_3 = {50 83 f0 0d 58}  //weight: 1, accuracy: High
        $x_1_4 = {35 14 13 00 00 35 14 13 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_AG_2147627757_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AG"
        threat_id = "2147627757"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 80 34 10 40 00 4e f2 0f c1 ca b9 e9 08 ab c2 c1 e1 21 08 c2 69 c8 43 fa d5 44 b9 f9 d8 3b 12 b9 31 30 33 2a f2 41 ff c1 c1 e1 d9 40 3d 00 66 00 00 72 cc}  //weight: 1, accuracy: High
        $x_1_2 = {80 80 34 76 40 00 fb 84 e7 d1 e1 4a c7 c1 19 78 5b b2 64 8d 0d 21 60 a3 da 0f c1 ca 69 c8 29 48 eb 02 40 3d 5f 03 00 00 72 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AI_2147628807_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AI"
        threat_id = "2147628807"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 08 89 4d ?? 8d 95 ?? ?? ff ff 52 6a 00 55 9c 51 87 e9 b9 de fa 00 00 81 f9 ee ff c0 00 74 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AL_2147630524_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AL"
        threat_id = "2147630524"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 30 00 00 ff b5 ?? ?? ?? ?? ff 77 34 ff b5}  //weight: 2, accuracy: Low
        $x_2_2 = {66 8b 57 06 83 7e 08 00 74 11 ff 77 38 ff 76 08 e8 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 3b 46 14 76 09 ff 76 14 8f 85 cc fb ff ff 83 c6 28 66 4a 75 ce}  //weight: 2, accuracy: Low
        $x_1_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00 52 65 73 75 6d 65 54 68 72 65 61 64}  //weight: 1, accuracy: High
        $x_1_4 = {43 3a 5c 66 69 6c 65 2e 65 78 65 00 43 3a 5c 73 61 6d 70 6c 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_5 = {56 4d 57 41 52 45 00 51 45 4d 55 00 56 42 4f 58 00 56 49 52 54 55 41 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_AN_2147631023_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AN"
        threat_id = "2147631023"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_2_2 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ff ff 8b 48 50 51 8b 95 ?? ?? ff ff 8b 42 34 50 8b 8d ?? ?? ff ff 51 ff 55}  //weight: 2, accuracy: Low
        $x_1_3 = {66 8b 51 06 39 55 ?? 7d 4b 8b 45 f0 8b 48 3c 8b 55 ?? 6b d2 28}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 10 32 94 8d ?? ?? ff ff 8b 45 08 03 85 ?? ?? ff ff 88 10 e9}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 4d 5a 00 00 74 07 33 c0 e9 ?? ?? ?? ?? 8b 4d f0 8b 55 0c 03 51 3c 89 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 81 38 50 45 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_AP_2147631262_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AP"
        threat_id = "2147631262"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 1d 30 00 00 00 [0-32] 8b 5b 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 08 50 ff (75 ??|b5 ?? ?? ?? ??) ff 15 ?? ?? ?? ?? [0-32] 08 01 01 01 01 01 01 02 05 50 51 52 53 56 57 6a 00 68 00 00 00 00 ff (70|71|72|73|76|77) 50 ff (75 ??|b5 ?? ?? ?? ??) ff (75 ??|b5 ?? ?? ?? ??) ff (75 ??|b5 ?? ?? ?? ??) ff 15 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AR_2147631738_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AR"
        threat_id = "2147631738"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7f 22 8b 45 fc 99 f7 3d ?? ?? ?? ?? 8b 45 08 03 45 fc 8a 08 32 8a ?? ?? ?? ?? 8b 55 08 03 55 fc 88 0a eb cd}  //weight: 1, accuracy: Low
        $x_1_2 = {77 69 6e 00 73 79 73 00 61 70 70 00 6d 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 57 43 52 54 2d 0d 0a 0d 0a f6 45 e8 01 74 06 0f b7 45 ec eb 03}  //weight: 1, accuracy: High
        $x_1_4 = {79 08 49 81 c9 00 ff ff ff 41 8b 45 08 03 45 ?? 8a 10 32 94 8d ?? ?? ?? ?? 8b 45 08 03 45 ?? 88 10 e9}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 40 68 00 30 00 00 8b ?? ?? ?? ?? ?? 8b ?? 50 ?? 8b ?? 01 8b ?? 34}  //weight: 1, accuracy: Low
        $x_1_6 = {66 8b 51 06 39 95 ?? ?? ff ff 7d ?? 8b 85 ?? ?? ff ff 8b 48 3c 8b 95 00 ff ff 6b d2 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_AS_2147632013_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AS"
        threat_id = "2147632013"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 a1 ?? ?? ?? ?? 8b 40 50 50 a1 ?? ?? ?? ?? 8b 40 34}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8a 54 24 04 03 d7 33 d6 88 54 18 ff}  //weight: 1, accuracy: High
        $x_1_3 = {eb 0d 81 fe ff 00 00 00 75 05 be 01 00 00 00 [0-8] 89 ff 43 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AW_2147633552_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AW"
        threat_id = "2147633552"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ESET NOD32 and Sophos are a bunch of faggots!" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "cmd.exe /c del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AX_2147637536_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!AX"
        threat_id = "2147637536"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 02 eb 34 ff b5 f8 fd ff ff 6a 00 ff 95 60 fe ff ff 89 45 e4 8b 85 b4 fd ff ff 03 45 e4 89 85 b4 fd ff ff 68 ?? ?? ?? ?? 8d 85 e4 fe ff ff 50 ff 15 ?? ?? ?? ?? eb aa}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 30 00 00 8b 85 b4 fd ff ff 6b c0 03 50 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {6b c9 28 03 4d 0c 8d 84 01 f8 00 00 00 89 85 f0 fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BA_2147637552_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.BA"
        threat_id = "2147637552"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\test123\\4444\\Release\\4444.pdb" ascii //weight: 1
        $x_1_2 = {40 00 68 c0 27 09 00 04 30 6a 00 a2 ?? ?? 40 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d6 f6 c3 01 6a 00 6a 00 6a 00 74 17 8a 8b ?? ?? 40 00 32 0d ?? ?? 40 00 80 f1 ?? 88 8b ?? ?? 40 00 eb 13 8a 83 ?? ?? 40 00 8a d3 80 c2 ?? 32 c2 88 83 ?? ?? 40 00 ff d6 43 81 fb 27 3a 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_T_2147637748_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.T"
        threat_id = "2147637748"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 00 0c 60 8b 8d ?? ff ff ff 03 c8 89 8d ?? ff ff ff 8b 85 ?? ff ff ff d1 e0 89 85 ?? ff ff ff eb}  //weight: 2, accuracy: Low
        $x_2_2 = {66 9c 72 0a 74 03 75 01 e8 e8 02 00 00 00 72 f4 83 c4 04 66 9d 74 03 75 01}  //weight: 2, accuracy: High
        $x_1_3 = {8b 40 3c 8b 8d ?? ?? ff ff 6b c9 28 03 4d 0c 8d 84 01 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {e8 e8 72 f4 e8 83 c4 04 66 9d eb 01 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_X_2147640820_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.X"
        threat_id = "2147640820"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3a 50 45 00 00 75 05 8b 45 ?? eb 0d 8b 45 08 2d 00 10 00 00 89 45 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 89 45 ?? 8b 4d ?? 8b 55 ?? 03 51 3c 89 55 ?? 8b 45 ?? 8b 48 78 03 4d 08}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 f7 71 3c 8b 55 ?? 0f af 42 3c 50}  //weight: 1, accuracy: Low
        $x_2_4 = {89 10 8b 4d ?? 81 c1 85 47 51 03 8b 15 ?? ?? ?? ?? 03 55 ?? 33 0a}  //weight: 2, accuracy: Low
        $x_1_5 = {8b 45 08 03 05 ?? ?? ?? 00 89 45 dc b9 00 00 00 00 ff 65 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_Z_2147641669_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.Z"
        threat_id = "2147641669"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inject\\release\\Inject.pdb" ascii //weight: 1
        $x_1_2 = {8d 56 0c 89 46 06 c6 06 68 c6 46 05 e8 8b c3 2b d3}  //weight: 1, accuracy: High
        $x_1_3 = {83 c5 0d 89 6f 01 c6 47 0a c2 66 c7 47 0b 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AA_2147641804_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.AA"
        threat_id = "2147641804"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 68 00 00 00 00 68 00 00 00 00 ff 75 ?? 68 00 e1 f5 05 68 00 00 00 00 ff 75 ?? ff 15}  //weight: 3, accuracy: Low
        $x_1_2 = {8b 48 3c 8b 4c 01 50 a3 ?? ?? ?? 00 89 0d ?? ?? ?? 00 03 c8 89 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {68 40 00 00 00 68 00 10 00 00 68 00 87 93 03 68 00 00 00 00 ff 75 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = "document.body.innerHTML='<br/><form NAME=PriForm id=\"PriForm\" method=\"post\" ACTION =" ascii //weight: 1
        $x_1_5 = ":\\SVN\\360tcpview\\Release\\360TcpView.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_BC_2147642655_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BC"
        threat_id = "2147642655"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 39 99 87 e4 ff 35}  //weight: 1, accuracy: High
        $x_1_2 = {ff 76 34 8d 7e 34 ff 75 ?? ff 55 ?? 6a 40 68 00 30 00 00 ff 76 50}  //weight: 1, accuracy: Low
        $x_1_3 = {32 10 32 d1 88 10 8b 45 ?? 40 3b c6 89 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_BD_2147642658_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BD"
        threat_id = "2147642658"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 08 8d 0c 06 8b c6 99 f7 3d ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 30 01 46 3b 74 24 0c 7e e1}  //weight: 2, accuracy: Low
        $x_2_2 = {01 3e 8b 06 c6 00 e9 83 c4 0c ff 06 8b 06 8b cf 2b c8 8d 4c 19 fc 89 08 83 c8 ff 2b c7 01 06}  //weight: 2, accuracy: High
        $x_1_3 = {c7 45 0c f8 00 00 00 a1 ?? ?? ?? ?? 8b ?? 3c [0-16] 8b ?? 0c [0-7] 03 ?? 03 c7}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 40 3c 03 45 0c 53 8d 84 38 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6b c0 28 8b 49 3c 05 f8 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_BE_2147643337_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BE"
        threat_id = "2147643337"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 71 10 8b 51 14 8b 49 0c 03 d6 03 48 34 52 51 ff 73 50}  //weight: 1, accuracy: High
        $x_1_2 = {68 f6 3f 48 90 ff 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BF_2147643351_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BF"
        threat_id = "2147643351"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d fc 68 01 00 00 7d 3f 8b 45 08 33 c9 8a 08 8b 55 0c 33 c0 8a 02 f7 d0 23 c8}  //weight: 1, accuracy: High
        $x_1_2 = {53 56 57 89 65 e8 (c7 45 fc 00 00|83 65) f3 64 f1 (c7 45 fc ff ff|83 4d) eb}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7d fc 00 74 0b 8b 45 fc 83 e8 01 89 45 fc eb ef}  //weight: 1, accuracy: High
        $x_1_4 = {83 45 0c 28 0f b7 40 06 39 45 08 8b 45 0c 03 43 3c 8d ?? 18 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 40 68 00 30 00 00 ff 70 50 ff 70 34 ff}  //weight: 1, accuracy: High
        $x_1_6 = {40 00 ff e2 5a 05 00 52 8d 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_BG_2147644273_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BG"
        threat_id = "2147644273"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ff ff ff 00 eb 05 50 ff 0c 24 58 0b c0 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {68 4c 06 e1 47 e8 ?? ?? ?? ?? 68 6b 59 6f 06 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {77 8d 00 c6 85 ?? ?? ?? ?? 51 8d 00 c6 85 ?? ?? ?? ?? 75 8d 00 c6 85 ?? ?? ?? ?? 65 8d 00 c6 85 ?? ?? ?? ?? 72 8d 00 c6 85 ?? ?? ?? ?? 79 8d 00 c6 85 ?? ?? ?? ?? 53 8d 00 c6 85 ?? ?? ?? ?? 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BH_2147644683_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BH"
        threat_id = "2147644683"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 64 00 00 00 88 d8 f3 aa c6 ?? ?? ?? ?? ff 4d c6 ?? ?? ?? ?? ff 70 c6 ?? ?? ?? ?? ff 64}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 00 ba 0d 00 00 00 89 df 89 d1 f3 aa a0 ?? ?? ?? ?? 48}  //weight: 1, accuracy: Low
        $x_1_3 = {89 d0 c1 e0 02 01 d0 c1 e0 03 8d 04 01 05 f8 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AC_2147645286_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.AC"
        threat_id = "2147645286"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 55 ec ff 55 f8 89 45 e4 8b ?? e4 81 ?? 14 07 40 00 89 ?? cc fd ff ff 8b ?? e4}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 8b 4d f4 8b 51 50 52 8b 45 ec 50 8b 4d 0c 51 ff 95 10 fd ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d f4 03 4d ?? 88 01 8b 55 ?? 83 c2 01 89 55 ?? 83 7d f8 40 7c 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BI_2147645690_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BI"
        threat_id = "2147645690"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {64 a1 18 00 00 00 8b 40 30 8b 40 0c 8b 40 1c 8b 50 08 8b 42 3c 8b 44 10 78 83 65 f0 00}  //weight: 5, accuracy: High
        $x_5_2 = {c1 e9 02 b8 ?? ?? ?? ?? bf 04 00 00 00 50 31 02 d1 c0 03 d7 e2 f8}  //weight: 5, accuracy: Low
        $x_1_3 = {4c 64 72 55 6e 6c 6f 61 64 44 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 64 69 70 44 69 73 70 6f 73 65 49 6d 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {5a 77 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_BZ_2147645935_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.BZ"
        threat_id = "2147645935"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 56 8d 0c 06 e8 ?? ?? ?? ?? 30 01 83 c4 04 46 3b ?? 7c e9}  //weight: 1, accuracy: Low
        $x_2_2 = {f6 d1 32 08 80 f1 74 ?? 88 08}  //weight: 2, accuracy: Low
        $x_1_3 = {c6 00 e9 ff 06 8b 06 2b f8}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 ff 70 54 ff 75 0c ff 70 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_BJ_2147646376_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BJ"
        threat_id = "2147646376"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 6c 57 66 81 3e 4d 5a 0f ?? ?? ?? ?? ?? 8b 4e 3c 8b de 03 d9 81 3b 50 45 00 00 0f ?? ?? ?? ?? ?? b9 11 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 8a 1c 0f 8b ea 81 e5 ff 00 00 00 03 c3 03 c5 25 ff 00 00 80}  //weight: 1, accuracy: High
        $x_1_3 = {8a 1c 06 88 54 24 18 88 1c 01 8b 5c 24 18 88 14 06 33 d2 8a 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BK_2147647243_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BK"
        threat_id = "2147647243"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 b9 ff 44 88 ff f7 f1 8d 94 3a 24 12 00 00 81 fa 24 12 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 47 04 83 c7 04 (35|83) [0-4] 50 56 68 ?? ?? ?? 00 68 00 01 00 00 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BO_2147648026_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BO"
        threat_id = "2147648026"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 74 63 72 79 70 74 5c 52 65 6c 65 61 73 65 5c 73 5f 6c 6f 77 2e 70 64 62 0a 00 3a 5c 70 72 6f 6a 65 63 74 73}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 5c 73 72 63 5c 74 63 72 79 70 74 5c 52 65 6c 65 61 73 65 5c 73 5f (6c|68 69) 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = {3a 5c 70 72 6f 6a 65 63 74 73 5c 74 63 72 79 70 74 5f 63 6c 32 5c 74 63 72 79 70 74 5f 63 6c 32 5c 52 65 6c 65 61 73 65 5c 73 5f (6c|68 69) 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Injector_AD_2147648250_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.AD"
        threat_id = "2147648250"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a 88 10 40 8a 10 84 d2 75 f6 b8 ?? ?? ?? ?? eb 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1c 03 30 19 40 3b 44 24 [0-16] 42 3b 54 24 ?? 72 8b 4c 24 ?? 01 d1 8b 5c 24}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BP_2147648397_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BP"
        threat_id = "2147648397"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 51 0b 32 96 ?? ?? ?? ?? 32 d1 80 f2 ?? 88 96 ?? ?? ?? ?? 83 f9 05 7e 04 33 c9 eb 01 41 46 81 fe ?? ?? ?? ?? 7c d9}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 2e 58 66 89 85 ?? ?? ff ff 6a 6c 58 66 89 85 ?? ?? ff ff 6a 6f 58 66 89 85 ?? ?? ff ff 6a 67}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 40 02 39 85 ?? ?? ff ff 7d 3f 8b 85 ?? ?? ff ff 6b c0 28 8b 4d f0 ff 74 01 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BQ_2147648634_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BQ"
        threat_id = "2147648634"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7e 08 2e 64 6c 6c 75 d8 81 3e 6b 65 72 6e 75 d0 80 7e 0c 00 75 ca 81 7e 04 65 6c 33 32 75 c1}  //weight: 1, accuracy: High
        $x_1_2 = {ad 03 c3 ab e2 fa 8b 74 24 08 33 d2 4a 42 ad 03 c3 6a 00 50 e8 34 00 00 00 2b 44 24 28 75 ee d1 e2 03 54 24 0c 0f b7 02 d1 e0 d1 e0 03 44 24 04 8b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AG_2147648662_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.AG"
        threat_id = "2147648662"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "section0000" ascii //weight: 1
        $x_1_2 = {f8 04 72 0d 8b 4d 08 51 ff 95 04 ff ff ff 83 c4 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AI_2147649310_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.AI"
        threat_id = "2147649310"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7d fc fd 03 01 00 73 42}  //weight: 1, accuracy: High
        $x_1_2 = {68 d3 82 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BS_2147649331_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BS"
        threat_id = "2147649331"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Work\\DPacker64\\Release\\DExeStub32.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AJ_2147649406_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.AJ"
        threat_id = "2147649406"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 08 36 0f be 14 02 38 d6 74 08 c1 cb 0d 03 da 40 eb ec}  //weight: 2, accuracy: High
        $x_2_2 = {81 ff 59 bc 4a 6a}  //weight: 2, accuracy: High
        $x_1_3 = {68 55 9a d0 3b}  //weight: 1, accuracy: High
        $x_1_4 = {68 1b c6 46 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_BT_2147649709_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BT"
        threat_id = "2147649709"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 31 ff 4d fc eb d8 ff 55 f4}  //weight: 1, accuracy: High
        $x_1_2 = {8a 06 46 32 45 f7 50 56 ff 45}  //weight: 1, accuracy: High
        $x_1_3 = {38 47 18 75 f3 80 3f 6b 74 07 80 3f 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_AN_2147650181_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.AN"
        threat_id = "2147650181"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 76 61 72 31 00 00 00 00 76 61 72 32 00 00 00 00 76 61 72 33 00 00 00 00 76 61 72 34 00 00 00 00 76 61 72 35 00 00 00 00 76 61 72 36 00 00 00 00 76 61 72 37 00 00 00 00 76 61 72 38 00 00 00 00 76 61 72 39 00 00 00 00 76 61 72 31 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 45 44 49 4f 4e 2d 38 38 38 42 38 39 43 36 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 56 42 36 2e 4f 4c 42 00 00 56 42}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\deact\\VB6.OLB" ascii //weight: 1
        $x_1_4 = "C:\\Programme\\DUFFY\\loreley\\VB6.OLB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_BU_2147650238_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BU"
        threat_id = "2147650238"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 77 53 65 74 43 6f 6e 74 65 78 74 54 68 72 65 61 64 00 e8 ?? ?? ?? ?? ff e0 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 e8 ?? ?? ?? ?? ff e0 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {5a 77 52 65 73 75 6d 65 54 68 72 65 61 64 00 e8 ?? ?? ?? ?? ff e0 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {83 7d fc 02 74 08 83 7d fc 03 74 14 eb 17 8b 45 0c ff 30 8b 45 0c 8b 48 10 e8 ?? ?? ?? ?? eb 07 33 c0 40 eb 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AQ_2147651486_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.AQ"
        threat_id = "2147651486"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 76 61 73 74 00 50 72 6f 79 65 63 74 6f 31 00 00 50 72 6f 79 65 63 74 6f 31}  //weight: 1, accuracy: High
        $x_1_2 = "[[Dekoder's_Team]]" wide //weight: 1
        $x_1_3 = {4e 65 77 5f 56 61 6c 75 65 00 00 00 50 65 72 63 65 6e 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_AR_2147651517_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.AR"
        threat_id = "2147651517"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 42 24 89 45 06 00 8b 55 ?? 8b 45 08}  //weight: 1, accuracy: Low
        $x_1_2 = {03 51 24 89 55 06 00 8b 4d ?? 8b 55 08}  //weight: 1, accuracy: Low
        $x_1_3 = {03 51 24 89 55 09 00 8b 8d ?? ff ff ff 8b 55 08}  //weight: 1, accuracy: Low
        $x_10_4 = {6a 07 6a 0e 68 07 00 [0-3] 8d 03 05 05 08 4d ?? 51 45 ?? 50 8d ?? ff ff ff 51}  //weight: 10, accuracy: Low
        $n_100_5 = "Core Technologies Consulting, LLC" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_BW_2147653240_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BW"
        threat_id = "2147653240"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 85 d2 7c ?? 42 [0-16] 30 08 40 4a 75 ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {4b 85 db 75 ?? bb ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 b8 02 e8 ?? ?? ?? ?? 50 ff d3 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 cc ba 09 00 00 00 e8 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BD_2147655891_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.BD"
        threat_id = "2147655891"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xylitol knows the answer." ascii //weight: 1
        $x_1_2 = "Btw, THE GAME." ascii //weight: 1
        $x_1_3 = "(You just lost it.)" ascii //weight: 1
        $x_1_4 = {33 c9 b9 06 41 40 00 8a 01 3c 99 75 02 eb 0b 2b 05 04 10 40 00 88 01 41 eb ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BD_2147655891_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.BD"
        threat_id = "2147655891"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_14_1 = {68 00 00 32 40 6a 00 68 00 00 00 40 6a 00 ff 15 ?? ?? ?? ?? dc 8d ?? ?? ?? ?? df e0 a8 0d 0f 85 ?? (03|2d|04) 00 00 dd 9d ?? fe ff ff ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 00 00 28 40 6a 00 68 00 00 00 40 6a 00 ff 15}  //weight: 14, accuracy: Low
        $x_1_2 = {c7 45 fc 22 00 00 00 8b ?? ?? 03 ?? ?? 0f 80 ?? 02 00 00 89 ?? ?? c7 45 fc 23 00 00 00 8b ?? ?? 99 f7 7d ?? 89}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 fc 08 00 00 00 83 bd ?? ff ff ff 1a 0f 8c ?? 00 00 00 83 bd ?? ff ff ff 33 0f 8f ?? 00 00 00 c7 45 fc 09 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 1a 0f 8c ?? 00 00 00 83 bd ?? ff ff ff 33 0f 8f ?? 00 00 00 c7 45 fc ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_14_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_BF_2147656257_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.BF"
        threat_id = "2147656257"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".cn/gate.php" ascii //weight: 1
        $x_1_2 = {50 4f 53 54 00 00 00 00 62 6f 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {be 00 00 f0 05 56 ff 15 ?? ?? f0 05 50 ff 15 ?? ?? f0 05 85 c0 74 df 53 8b 5d 08 68 00 80 00 00 ff 75 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_BY_2147656306_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!BY"
        threat_id = "2147656306"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 30 00 00 ff b5 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? 6a 05 68 ?? ?? ?? ?? 56 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {58 59 59 59 6a 04 03 00 c7 45}  //weight: 2, accuracy: Low
        $x_2_3 = {b8 07 00 01 00}  //weight: 2, accuracy: High
        $x_1_4 = {57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 00 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 75 00 73 00 65 00 72 00 69 00 6e 00 69 00 74 00 2e 00 65 00 78 00 65 00 2c 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 00 52 00 4f 00 43 00 4d 00 4f 00 4e 00 5f 00 57 00 49 00 4e 00 44 00 4f 00 57 00 5f 00 43 00 4c 00 41 00 53 00 53 00 00 00 67 00 64 00 6b 00 57 00 69 00 6e 00 64 00 6f 00 77 00 54 00 65 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {80 7d ff e9 75 05 6a 01 58 eb 02 33 c0}  //weight: 1, accuracy: High
        $x_1_7 = {64 a1 30 00 00 00 83 c0 68 3e 8b 00 83 f8 70 74 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_BY_2147658298_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.BY"
        threat_id = "2147658298"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 83 c0 68 3e 8b 00 83 f8 70 74 09 c7 45 fc 00 00 00 00 eb 07 c7 45 fc 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {58 59 59 59 53 50 8d 85 ?? ff fe ff 50 e8 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_3 = {58 59 59 59 6a 04 5b 53 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_4 = {59 50 00 00 e8 ?? ?? ?? ?? 8b 55 10 83 c4 30 85 d2 6a 06 5e 7e 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_5 = {59 50 00 00 6a 02 8d 45 ?? 50 8d 45 ?? 50 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_6 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74 f2 58 3d 00 02 00 00 72 09 c7 45 fc 01 00 00 00 eb 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Injector_BY_2147658298_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.BY"
        threat_id = "2147658298"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 a1 30 00 00 00 83 ?? 68 3e 8b 00 83 f8 70 74 09 c7 45 fc 00 00 00 00 eb 07 c7 45 fc 01 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74 f2 58 3d 00 02 00 00 72 09 c7 45 fc 01 00 00 00 eb 07}  //weight: 10, accuracy: High
        $x_1_3 = {58 59 59 59 b8 59 50 00 00 66 89 45 ?? 6a 06 58 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 ec 58 59 59 59 e8 ?? ?? 00 00 6a 02 8d 45 ec 50 8d 45 7c 50 c7 45 ?? 59 50 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 45 e4 58 59 59 59 6a 04 8d 45 e4 50 8d 45 78 50 e8 ?? ?? 00 00 c7 45 e4 59 50 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {c7 45 78 58 59 59 59 b8 59 50 00 00 66 11 45 7c 6a 06 58 33 c9 3b fb 7e 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_CB_2147658615_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.CB"
        threat_id = "2147658615"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 44 24 68 58 59 59 59 68 04 00 00 00 8d 44 24 6c 50 ff 74 24 60}  //weight: 10, accuracy: High
        $x_10_2 = {31 c9 8b 74 24 04 8b 7c 24 0c 8b 54 24 08 8b 6c 24 10 01 f5 8a ?? 8a 3f 30 ?? 88 ?? 41 46 47 39 ee 7d 0c 39 d1 7d 02 eb eb 31 c9 29 d7 eb e5 31 c0 c2 10 00}  //weight: 10, accuracy: Low
        $x_1_3 = {07 00 01 00 07 00 c7 84 24}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 00 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_5 = {83 fb 2e 0f 85 ?? ?? ?? ?? ff 44 24 0c 8b 6c 24 0c 0f b6 5d 00 83 fb 64 74 0f 8b 6c 24 0c 0f b6 5d 00 83 fb 65 74 02 eb 07 b8 01 00 00 00 eb 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_CG_2147659044_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.CG"
        threat_id = "2147659044"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 70 20 03 75 fc 8b d9 c1 e3 02 03 f3 8b 7e 0c 03 7d fc 8a 1f}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 ee 50 c6 45 ef 41 c6 45 ed 47}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 c5 75}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 c6 73}  //weight: 1, accuracy: High
        $x_1_5 = {c6 45 c7 65}  //weight: 1, accuracy: High
        $x_1_6 = {c6 45 c8 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CI_2147659222_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.CI"
        threat_id = "2147659222"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {bb 85 3b ae db 8b 95 cc fd ff ff e8 ?? ?? 00 00 89 45 f0}  //weight: 5, accuracy: Low
        $x_5_2 = {bb 93 35 df 85 8b 95 cc fd ff ff e8 ?? ?? 00 00 89 45 ec}  //weight: 5, accuracy: Low
        $x_5_3 = {bb 53 13 c1 78 8b 95 cc fd ff ff e8 ?? ?? 00 00 89 45 e4}  //weight: 5, accuracy: Low
        $x_1_4 = {02 00 01 00 8d 85 ?? ?? ff ff 50 ff b5 ?? ?? ff ff ff 55 ec 64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 40 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CJ_2147659610_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.CJ"
        threat_id = "2147659610"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 65 fc 00 b8 01 00 00 00 0f 3f 07 0b c7 45 fc ff ff ff ff c7 45 fc fe ff ff ff}  //weight: 10, accuracy: High
        $x_10_2 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74 f2 58 3d 00 02 00 00 72 09 c7 45 fc 01 00 00 00 eb 07}  //weight: 10, accuracy: High
        $x_1_3 = {c7 45 e4 58 59 59 59 6a 04 8d 45 e4 50 8d 45 78 50 e8 ?? ?? 00 00 c7 45 e4 59 50 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 78 58 59 59 59 b8 59 50 00 00 66 11 45 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_CL_2147659902_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.CL"
        threat_id = "2147659902"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 fb 2e 0f 85 ?? ?? ?? ?? ff 44 24 0c 8b 6c 24 0c 0f b6 5d 00 83 fb 64 74 0f 8b 6c 24 0c 0f b6 5d 00 83 fb 65 74 02 eb 07 b8 01 00 00 00 eb 02}  //weight: 10, accuracy: Low
        $x_1_2 = {c7 84 24 88 04 00 00 40 00 00 00 c7 84 24 8c 04 00 00 00 30 00 00 [0-64] 68 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_10_3 = {54 d1 40 00 00 00 00 70 00 f0 40 05 00 00 00 00 00 00}  //weight: 10, accuracy: Low
        $x_1_4 = {8b 45 28 89 84 24 ?? ?? ?? ?? 8b 5d 34 03 9c 24 ?? ?? ?? ?? 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CL_2147659902_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.CL"
        threat_id = "2147659902"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 68 58 59 59 59 [0-4] 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 2c 24 c7 45 0c 00 30 00 00 c7 45 10 40 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 d1 40 00 00 00 00 70 00 f0 40 05 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_10_4 = {83 fb 5a 7f 07 b8 01 00 00 00 eb 02 31 c0 21 c0 74 15 8b 6c 24 14 0f b7 5d 00 83 cb 20 53 8b 6c 24 18 58 66 89 45 00}  //weight: 10, accuracy: High
        $x_10_5 = {83 fb 2e 0f 85 ?? ?? ?? ?? ff 44 24 0c 8b 6c 24 0c 0f b6 5d 00 83 fb 64 74 0f 8b 6c 24 0c 0f b6 5d 00 83 fb 65 74 02 eb 07 b8 01 00 00 00 eb 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_CB_2147660079_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!CB"
        threat_id = "2147660079"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff b5 ?? ?? ff ff ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 10 00 00 6a 04 53 ff d0 8b f8 89 bd ?? ff ff ff c7 07 07 00 01 00 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CY_2147661507_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.CY"
        threat_id = "2147661507"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 8b 8c e4 d1 56 8b d8 e8 ?? ?? ?? ?? 68 6b 43 15 20 56 89 45 68 e8 ?? ?? ?? ?? 68 ea 56 5c b8 56 89 45 5c e8 ?? ?? ?? ?? 68 6a 34 4f a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CF_2147661665_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!CF"
        threat_id = "2147661665"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff b5 ?? ?? ff ff ff 55 ?? 89 85 ?? ?? ff ff 6a 00 ff 77 54 ff 75 ?? ff b5 ?? ?? ff ff ff b5 ?? ?? ff ff ff 55}  //weight: 2, accuracy: Low
        $x_1_2 = {66 3b 77 06 72 6b c6 28}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 02 00 01 00 04 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_4 = {e8 06 00 00 00 6e 74 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_CZ_2147661837_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.CZ"
        threat_id = "2147661837"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 cb c6 85 26 ff ff ff 6c c6 85 27 ff ff ff 6c c6 85 21 ff ff ff 74 c6 85 22 ff ff ff 75 c6 85 20 ff ff ff 72}  //weight: 1, accuracy: High
        $x_1_2 = {50 6a 00 ff d6 8b f0 e8 00 00 00 00 58 89 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_DA_2147661841_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.DA"
        threat_id = "2147661841"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 43 58 31 0f 85 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 01 0f 85 06 00 81 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {58 59 59 59 03 00 (00|c7)}  //weight: 1, accuracy: Low
        $x_1_3 = {80 7d ff e9 75 ?? 33 c0 40 eb 02}  //weight: 1, accuracy: Low
        $x_1_4 = {64 a1 30 00 00 00 83 c0 68 3e 8b 00 83 f8 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_CP_2147663155_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!CP"
        threat_id = "2147663155"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 68 bc 02 00 00 6a 08 6a 12 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 35 01 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 00 6a 1c ff 75 c4 e8 ?? ?? ?? ?? 6a 05 ff 75 c4 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 6f 73 74 61 72 74 5f 43 6c 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 65 63 68 6e 69 63 6f 6c 6f 72 20 42 75 74 74 6f 6e 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {8d 45 fc eb eb (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 80 00 00 eb 68 72 14 00 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_DF_2147663191_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.DF"
        threat_id = "2147663191"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 75 14 8b 45 10 0f be 04 10 8b 4d 08 03 0d e0 f3 40 00 0f be 09 33 c8 8b 45 08 03 05 e0 f3 40 00 88 08 eb bf}  //weight: 1, accuracy: High
        $x_1_2 = {03 0d 34 f3 40 00 0f b6 09 33 c8 8b 45 08 03 05 34 f3 40 00 88 08 a1 e4 f3 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {88 08 a1 18 fc 40 00 40 a3 18 fc 40 00 eb c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CQ_2147663669_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!CQ"
        threat_id = "2147663669"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {54 68 65 20 64 61 74 65 20 79 6f 75 20 70 69 63 6b 65 64 20 69 73 3a 00}  //weight: 10, accuracy: High
        $x_1_2 = {64 a1 30 00 00 00 eb 8b 40 0c eb 8b 40 14 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 fc eb 0f 81 ?? ?? ff ff e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_CR_2147663670_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!CR"
        threat_id = "2147663670"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 6e 75 6d 65 72 61 74 65 64 20 57 69 6e 64 6f 77 20 45 78 70 6c 6f 72 65 72 00}  //weight: 10, accuracy: High
        $x_1_2 = {b8 ff ff ff 0f eb eb eb}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 80 00 00 eb eb eb}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 45 fc eb eb e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_DI_2147664065_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.DI"
        threat_id = "2147664065"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 8b 10 c1 e2 ?? 33 10 81 c2 ?? ?? ?? ?? 89 10 8b 00 c1 e8 ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {89 04 24 33 ff 51 6a 00 6a ?? ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 2c 6a 04 68 00 10 00 00 55 6a 00 56 ff 15 ?? ?? ?? ?? 8b d8 85 db 74 15 8d 44 24 04 50 55 8b 44 24 08 50 53 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d8 8d 55 b8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 b8 8b d6 b9 01 00 00 00 e8 ?? ?? ?? ?? 48 75 2a a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CS_2147664272_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!CS"
        threat_id = "2147664272"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 3c ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 fc 6a 2d ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 6f 73 74 61 72 74 5f 43 6c 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 6e 75 6d 65 72 61 74 65 20 52 75 6e 6e 69 6e 67 20 44 65 76 69 63 65 20 44 72 69 76 65 72 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {8d 45 fc eb eb eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CT_2147664553_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!CT"
        threat_id = "2147664553"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 b8 00 10 00 00 0d 00 20 00 00 50 8b 45 ?? 83 c0 50 ff 30 6a 00 8b 45 ?? ff 30 ff 55 ?? 83 f8 00}  //weight: 1, accuracy: Low
        $x_1_2 = {05 b0 00 00 00 89 18 c7 45 ?? 00 00 00 00 c7 45 ?? 74 65 78 74 c7 45 ?? 64 43 6f 6e c7 45 ?? 68 72 65 61 c7 45 ?? 53 65 74 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CU_2147664554_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!CU"
        threat_id = "2147664554"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 40 00 00 00 68 00 30 00 00 ff b4 24 ?? ?? ?? ?? ff 75 34 8d ac 24 ?? ?? ?? ?? ff 75 00 68 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f bf 5d 06 4b 3b 9c 24 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_3 = {0f bf 45 06 39 c3 0f (8d|85) 04 00 8d 6c 24}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 28 89 84 24 ?? ?? ?? ?? 8b 5d 34 03 9c 24 ?? ?? ?? ?? 53}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 30 00 00 ff b4 24 ?? ?? ?? ?? ff 75 34 8d ac 24 ?? ?? ?? ?? ff 75 00 68 04 00 00 00 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 00 00 00 68 00 00 00 00 68 00 00 00 00 8d 6c 24 ?? ff 75 54 ff b4 24 ?? ?? ?? ?? ff 75 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_CV_2147664555_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!CV"
        threat_id = "2147664555"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 cf 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 03 00 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 68 58 02 00 00 ff 75 08 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {47 65 6e 65 72 69 63 5f 43 6c 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 73 73 65 6d 62 6c 65 72 2c 20 50 75 72 65 20 26 20 53 69 6d 70 6c 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {8d 45 fc eb eb (eb|e9)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_DM_2147664921_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.DM"
        threat_id = "2147664921"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 04 0a 8d 55 d4 8d 45 d8 52 50 (6a 02 ff d3 83|e9 c7 77 ff ff)}  //weight: 1, accuracy: Low
        $x_1_2 = {66 3b b5 78 ff ff ff 0f 8f bb 00 00 00 0f bf fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_DP_2147665075_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.DP"
        threat_id = "2147665075"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 85 db 7e 31 be 01 00 00 00 8b 45 fc 8a 44 30 ff 8b 55 f4 8a 54 32 ff 32 c2 88 45 f3 8d 45 ec 8a 55 f3 e8}  //weight: 1, accuracy: High
        $x_1_2 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 e8 fb ff ff 8b 55 e8 30 04 3a 47 4b 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {89 45 f8 8b de 66 81 3b 4d 5a 0f 85 d2 01 00 00 8b c6 33 d2 52 50 8b 43 3c}  //weight: 1, accuracy: High
        $x_1_4 = {8b 47 28 03 45 f0 89 85 7c ff ff ff 8d 85 cc fe ff ff 50 8b 45 e0 50 e8 ?? ?? ?? ?? 8b 45 e0 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_DU_2147678885_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.DU"
        threat_id = "2147678885"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 d4 70 e3 ac ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 eb c1 0e 55 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 3e 45 93 3e}  //weight: 10, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 83 c0 68 3e 8b 00 83 f8 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_DF_2147679127_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DF"
        threat_id = "2147679127"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 3c 2a 74 06 33 f6 eb b3 eb 03 46 eb ae}  //weight: 1, accuracy: High
        $x_1_2 = {c7 00 57 72 69 74 c7 40 04 65 50 72 6f c7 40 08 63 65 73 73 c7 40 0c 4d 65 6d 6f c7 40 10 72 79 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 03 83 c6 04 8b 5d ?? 03 de 8b 85 ?? ?? ?? ?? 89 03 83 c6 04 3b 75 ?? 73 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_DX_2147679169_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.DX"
        threat_id = "2147679169"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 2d 8b 4c 24 04 80 3c 08 64 75 1a 80 7c 08 01 7d 75 13 80 7c 08 02 77 75 0c 80 7c 08 06 61 75 05 05 e4 03 00 00 80 34 08 bb 40 3b c2 7c d7}  //weight: 2, accuracy: High
        $x_1_2 = {0f 84 dd 01 00 00 8b 55 54 8b 44 24 14 6a 00 52 53 56 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4c 24 38 8b 54 24 14 51 52 ff d0 85 c0 74 2a 53 e8}  //weight: 1, accuracy: High
        $x_1_4 = {d5 cf df d7 d7 95 df d7 d7}  //weight: 1, accuracy: High
        $x_1_5 = {f5 cf ee d5 d6 da cb ed d2 de cc f4 dd e8 de d8 cf d2 d4 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_DH_2147679236_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DH"
        threat_id = "2147679236"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 73 18 ff 55 ?? 8b 1b 83 c3 24 8b 5b 04 0f b6 1b 81 cb 00 3a 5c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 a4 b0 e9 aa 8d 46 fc 2b c7 ab}  //weight: 1, accuracy: High
        $x_1_3 = {ff d0 03 45 ?? c7 00 5c 2a 2e 64 c7 40 04 6c 6c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_DZ_2147679569_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.DZ"
        threat_id = "2147679569"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 04 33 c0 eb 29 83 7d 2c 00 74 11 8d 45 e8 6a 10 50 ff 75 2c e8 ?? ?? ?? ?? 83 c4 0c f6 45 1c 04 75 09 ff 75 ec ff 15 ?? ?? ?? ?? 6a 01}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 7c 07 04 eb 03 8b 45 fc 8b 4d 0c 03 c3 ff 31 8b 4d ec 2b cb 51 50 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 0f 8c 39 02 00 00}  //weight: 10, accuracy: Low
        $x_1_3 = {64 65 74 65 63 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 63 74 69 76 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {61 6c 67 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {75 73 65 72 69 6e 69 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_DI_2147679943_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DI"
        threat_id = "2147679943"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6c 6f 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 70 72 6f 6a 65 63 74 2d 37 2e 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 61 74 6e 69 75 6d 20 57 61 72 6e 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {8a 10 88 14 06 40 84 d2 75 f6 83 c7 0c 66 c7 41 0a eb fe 89 79 01 5f b8 01 00 00 00 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_DJ_2147680242_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DJ"
        threat_id = "2147680242"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 6c 24 48 0f bf 45 06 39 c3 0f}  //weight: 1, accuracy: High
        $x_1_2 = {6b db 28 89 9c 24 ?? ?? ?? ?? 8b 9c 24 ?? ?? ?? ?? 03 9c 24}  //weight: 1, accuracy: Low
        $x_1_3 = {40 93 d6 40 00 00 00 00 00 54 d1 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_DL_2147680280_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DL"
        threat_id = "2147680280"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 83 f8 0d 0f 9e c1 f7 d9 8b f1 8d 4d}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 e7 47 50 41 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 83 c1 03}  //weight: 1, accuracy: High
        $x_1_4 = {b8 fc fd fe ff}  //weight: 1, accuracy: High
        $x_1_5 = {2d 04 04 04 04}  //weight: 1, accuracy: High
        $x_1_6 = {0f b7 47 14}  //weight: 1, accuracy: High
        $x_1_7 = {66 3b 77 06}  //weight: 1, accuracy: High
        $x_1_8 = {bb 00 00 40 00}  //weight: 1, accuracy: High
        $x_1_9 = {03 5f 28 eb}  //weight: 1, accuracy: High
        $x_1_10 = {6b c6 28 eb}  //weight: 1, accuracy: High
        $x_1_11 = {64 a1 30 00 00 00 92 8b 52 0c 8b 52 14}  //weight: 1, accuracy: High
        $x_1_12 = {83 f8 10 7f 07 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_13 = {ff 77 54 eb}  //weight: 1, accuracy: High
        $x_1_14 = {8b 50 78 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule VirTool_Win32_Injector_DP_2147681499_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DP"
        threat_id = "2147681499"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b ff 28 01 fb 89 9c 24 a4 04 00 00 ff b4 24 94 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 6c 24 48 0f bf 45 06 39 c3 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_DP_2147681499_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DP"
        threat_id = "2147681499"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 00 00 68 0a 00 00 00 68 1a ?? ?? ?? 68 ff 00 00 00 e8 ?? ?? ?? ?? 68 ?? ?? 40 00 68 00 00 00 00 68 05 00 00 00 68 0a 00 00 00 68 04 00 00 00 e8 ?? ?? 00 00 68 ?? ?? 40 00 68 00 00 00 00 68 05 00 00 00 68 1a 00 00 00 68 04 00 00 00 e8 ?? ?? 00 00 68 ?? ?? 40 00 68 ?? ?? 40 00 68 08 ?? ?? ?? 68 01 00 00 00 68 04 00 00 00 e8 ?? ?? 00 00 e8 ?? ?? 00 00 c7 05 ?? ?? 40 00 01 00 00 00 8b ?? ?? ?? 40 00 c7 45 00 00 00 00 00 68 ?? ?? 40 00 8f 45 04 c7 45 08 ff 00 00 00 ff 35 ?? ?? 40 00 68 02 00 00 00 8b 2d ?? ?? 40 00 8d 95 ee 11 00 00 ff 35 ?? ?? 40 00 68 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 08 00 00 00 68 01 00 00 00 68 04 00 00 00 e8 ?? ?? 00 00 c7 05 ?? ?? ?? 00 00 00 80 3f 68 19 79 24 4e e8 ?? ?? 00 00 d8 0d ?? ?? ?? 00 d8 05 ?? ?? ?? 00 d9 fa 83 ec 04 d9 1c 24 e8 ?? ?? 00 00 dd d8 d9 05 ?? ?? 40 00 d8 05 ?? ?? 40 00 d9 1d ?? ?? 40 00 d9 05 ?? ?? 40 00 d8 1d ?? ?? 40 00 df e0 f6 c4 40 74 b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Injector_DQ_2147681613_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DQ"
        threat_id = "2147681613"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 10 77 07 b8 03 00 00 00 ff e0 fc}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 83 c1 03}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 47 14}  //weight: 1, accuracy: High
        $x_1_5 = {bb 00 00 40 00}  //weight: 1, accuracy: High
        $x_1_6 = {66 3b 77 06}  //weight: 1, accuracy: High
        $x_1_7 = {56 8b 0e fc [0-15] 64 8b 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule VirTool_Win32_Injector_DR_2147681685_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DR"
        threat_id = "2147681685"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 7f 3c 6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff b5 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_1_2 = {46 66 3b 77 06 72 ?? 8b 85 ?? ?? ?? ?? 03 47 28}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 02 00 01 00 04 00 c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_DT_2147681775_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DT"
        threat_id = "2147681775"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 ff ff ff 7f 31 c9 39 c8 75 0a 74 0e bb 00 00 00 00 89 1b c3 48 39 c8 eb ed c3 b9 ff ff ff 7f 90 e2 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_DU_2147681816_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DU"
        threat_id = "2147681816"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 79 20 46 72 61 6e 6b 69 6e 20 42 69 74 63 68 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 27 6d 20 6e 6f 74 20 61 20 6d 61 67 69 63 20 62 75 74 20 74 68 65 20 6e 75 6d 62 65 72 20 79 6f 75 20 63 68 6f 69 63 65 20 77 61 73 3a 0a 0a 20 25 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_DV_2147682212_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!DV"
        threat_id = "2147682212"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 6c 24 44 0f bf 45 06 39 c3 0f}  //weight: 1, accuracy: High
        $x_1_2 = {6b ff 28 01 fb 89 9c 24 ?? ?? ?? ?? 8b 9c 24 ?? ?? ?? ?? 03 9c 24}  //weight: 1, accuracy: Low
        $x_1_3 = {56 56 d6 41 00 00 00 00 40 16 d4 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_EJ_2147682836_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EJ"
        threat_id = "2147682836"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 8d bd ?? ?? ff ff f3 a5 [0-8] c7 45 f8 ?? 00 00 00 c7 45 ?? 00 00 00 00 [0-15] c7 45 ?? 00 00 00 00 eb 09 8b ?? ?? 83 ?? 01 89 ?? ?? 8b ?? ?? 3b [0-8] 0f 8d ?? ?? 00 00 8b ?? ?? 8a ?? ?? ?? ?? ff ff 88 ?? fe 8b ?? ?? 83 ?? 01 89 ?? ?? 0f be ?? fe 8b ?? ?? 33 ?? f8 03}  //weight: 1, accuracy: Low
        $x_1_2 = {40 00 8d bd ?? ?? ff ff f3 a5 [0-4] c7 45 ?? ?? 00 00 00 c7 45 ?? 00 00 00 00 e8 ?? ?? 00 00 89 ?? ?? eb 09 8b ?? ?? 83 ?? 01 89 ?? ?? 83 ?? ?? 00 [0-6] 8b ?? ?? 8a ?? ?? ?? ?? ff ff 88 ?? ?? 8b ?? ?? 83 ?? 01 89 ?? ?? 8a ?? ?? 88 ?? ?? 8b ?? ?? 33 ?? ?? 89 ?? ?? 0f be ?? ff 03}  //weight: 1, accuracy: Low
        $x_1_3 = {40 00 8d bd ?? ?? ff ff f3 a5 a4 c7 85 ?? ff ff ff ?? 00 00 00 c7 85 ?? ff ff ff 00 00 00 00 e8 ?? ?? 00 00 89 ?? ?? ff ff ff eb 0f 8b ?? ?? ff ff ff 83 ?? 01 89 ?? ?? ff ff ff 83 ?? ?? ff ff ff 00 0f ?? ?? 00 00 00 8d ?? ?? ?? ff ff [0-32] 8b ?? ?? ff ff ff 8a ?? ?? ?? ?? ff ff 88 ?? ?? 8b ?? ?? ff ff ff 83 c2 01 89 ?? ?? ?? ff ff 8a ?? ?? 88 ?? ?? 8b 8d ?? ?? ff ff 33 8d ?? ff ff ff 89 8d ?? ff ff ff 0f be ?? ff 03 ?? ?? ff ff ff 88 ?? ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {40 00 8d bd ?? ?? ff ff f3 a5 66 a5 a4 c7 45 ?? ?? 00 00 00 c7 85 ?? ff ff ff 00 00 00 00 c7 85 ?? ff ff ff ?? ?? ?? ?? 8b 85 ?? ff ff ff 8a ?? ?? ?? ?? ff ff 88 ?? ?? 8b ?? ?? ff ff ff 83 c2 01 89 ?? ?? fe ff ff 8a 45 ?? 88 45 ?? 8b ?? ?? fe ff ff 33 4d ?? 89 ?? ?? 0f be}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 55 e8 0f be ?? ?? ?? ?? ff ff 8b 4d e8 83 c1 01 33 4d ?? 03 c1 88 45 ff 8b 55 e8 8a 45 ff 88 82 ?? ?? 40 00 8b 4d e8 83 c1 01 89 4d e8 81 7d e8 8e 0b 00 00 7d 02 eb}  //weight: 1, accuracy: Low
        $x_1_6 = {83 c2 01 33 ?? ?? 03 ?? 88 ?? ff 8b ?? ?? 8a ?? ff 88 88 ?? ?? 40 00 8b ?? ?? 83 c2 01 89 ?? ?? 81 7d ?? ?? ?? 00 00 7d 05 e9 ?? ff ff ff c7 45 b8 ?? ?? 40 00 ff 55 b8 33 c0 5f 5e}  //weight: 1, accuracy: Low
        $x_1_7 = {83 c1 01 33 [0-5] 03 c1 88 ?? ff 8b ?? ?? 8a ?? ff 88 ?? ?? ?? 40 00 8b ?? ?? 83 c1 01 89 ?? ?? 81 7d ?? ?? 10 00 00 7d 05 e9 ?? ff ff ff c7 45 ?? ?? ?? 40 00 ff 55 ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Injector_EC_2147683182_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EC"
        threat_id = "2147683182"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fc fd fe ff b9 40 00 00 00 89 04 8d ?? ?? ?? ?? 2d 04 04 04 04 49 75 f1}  //weight: 1, accuracy: Low
        $x_1_2 = {30 0e 46 4f 75 ce 33 c0 bf ?? ?? ?? ?? b9 40 00 00 00 fc f3 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_ED_2147683789_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!ED"
        threat_id = "2147683789"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 b9 c9 03 00 00 be ?? ?? ?? ?? 8d bd 88 ec ff ff f3 a5 66 a5 a4}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 8c 05 88 ec ff ff 8b 55 f0 83 c2 01 83 f2 ?? 03 ca 88 4d ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_EF_2147684425_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EF"
        threat_id = "2147684425"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 88 45 fe 2a 00 8b 4d ?? 83 c1 01 (81 f1 ?? ?? ?? ??|83 f1 ??) 88 8d ?? ?? ff ff 8b 55 ?? 0f b6 84 15 ?? ?? ff ff 0f be 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {03 ca 88 4d fe 2a 00 8b 55 ?? 83 c2 01 (81 f2 ?? ?? ?? ??|83 f2 ??) 88 95 ?? ?? ff ff 8b 45 ?? 0f b6 8c 05 ?? ?? ff ff 0f be 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {03 ca 88 4d fe 30 00 8b 95 ?? ?? ff ff 83 c2 01 (81 f2 ?? ?? ?? ??|83 f2 ??) 88 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 0f b6 8c 05 ?? ?? ff ff 0f be 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Injector_EK_2147684436_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EK"
        threat_id = "2147684436"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 d8 05 00 30 00 00 89 85 ?? ?? ?? ?? [0-32] f7 d8 83 c0 40 89 85 ?? ?? ?? ?? [0-64] 8b 85 ?? ?? ?? ?? 8b 40 50 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 40 34 89 85}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b7 52 06 0f b7 d2 3b c2 0f 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 03 50 3c 8b 85 ?? ?? ?? ?? 8b 00 0f af 85 ?? ?? ?? ?? 03 d0 89 95}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 28 03 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 89 82 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 00 07 00 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_EG_2147684459_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EG"
        threat_id = "2147684459"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4d f9 30 8c 38 9c f6 ff ff 40 3d 1d 09 00 00 7c ee 8d 85 9c f6 ff ff ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_EL_2147684461_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EL"
        threat_id = "2147684461"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d0 83 ec 08 b8 00 30 00 00 2b 45 ?? 89 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? b8 40 00 00 00 2b 45 ?? 89 85 ?? ?? ?? ?? [0-80] 8b 85 ?? ?? ?? ?? 8b 40 50 89 85 ?? ?? ?? ?? [0-16] 8b 85 ?? ?? ?? ?? 8b 40 34 89 85}  //weight: 2, accuracy: Low
        $x_1_2 = {66 8b 40 06 0f b7 c0 3b 45 ?? 0f 9f c0 84 c0 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 50 3c 8b 85 ?? ?? ?? ?? 01 c2 8b 85 ?? ?? ?? ?? 8b 00 0f af 45 ?? 01 d0 89 85}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 50 28 8b 85 ?? ?? ?? ?? 01 c2 8b 85 ?? ?? ?? ?? 89 90 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 00 07 00 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_EM_2147684498_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EM"
        threat_id = "2147684498"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 56 85 c0 0f 84 8e 00 00 00 8b c8 8d 71 01 8a 19 41 84 db 75 f9 2b ce 83 c1 3a 81 f9 00 04 00 00 77 75 8d 95 fc fb ff ff 33 c9 8a 99 8c 66 01 10 88 9c 0d fc fb ff ff 41 84 db 75 ee 8b f0 8a 08 40 84 c9 75 f9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 3b 45 0c 7d 2c 8b 4d 08 03 4d fc 0f b6 09 8b 45 fc 99 f7 7d 14 8b 45 10 0f be 14 10 33 ca 8b 45 08 03 45 fc 88 08 8b 4d fc 83 c1 01 89 4d fc eb cc 8b e5 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_EN_2147684557_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EN"
        threat_id = "2147684557"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 30 00 00 2b 8d ?? ?? ?? ?? 89 4d f8 8d 55 f8 89 95 ?? ?? ?? ?? b8 40 00 00 00 2b 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? [0-64] 8b 51 50 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 48 34 89 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 51 06 39 95 ?? ?? ?? ?? 0f 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 48 3c 03 8d ?? ?? ?? ?? 8b 55 fc 8b 85 ?? ?? ?? ?? 0f af 02 03 c8}  //weight: 1, accuracy: Low
        $x_1_3 = {03 42 28 8b 8d ?? ?? ?? ?? 89 81 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 01 07 00 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_EE_2147684647_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EE"
        threat_id = "2147684647"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 00 66 c7 45 (f0|f4) 2e 00 8b (41|43) 28 0d 00 66 c7 45 (ee|f2)}  //weight: 10, accuracy: Low
        $x_1_2 = {74 08 8d 85 ?? ?? ff ff ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c0 01 89 45 ?? 81 7d 00 80 0f 00 00 0f 85 ?? ?? ff ff [0-96] ff (55 ??|95 ?? ?? ?? ??) 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_EH_2147684781_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EH"
        threat_id = "2147684781"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 50 8b 50 34 a1 ?? ?? ?? ?? 6a 40 68 00 30 00 00 51 52 50 ff 54 24}  //weight: 1, accuracy: Low
        $x_1_3 = {33 db 66 3b 41 06 73 ?? 33 ed 8b 57 3c 03 d5 8b 8c 3a 08 01 00 00 8d 84 3a f8 00 00 00 8b 50 14 8b 40 0c}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 42 28 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 81 b0 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_EI_2147685093_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EI"
        threat_id = "2147685093"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 52 19 8b 1d ?? ?? ?? ?? 02 53 02 30 14 08 8b 15 ?? ?? ?? ?? 0f b6 52 02 41 03 d6 3b ca 76}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 01 84 c0 74 3a 32 45 77 2a 45 70 fe c8 88 04}  //weight: 1, accuracy: High
        $x_1_3 = {74 09 b8 00 20 00 00 66 09 47 16 8d 45 f8 50 ff 77 54}  //weight: 1, accuracy: High
        $x_1_4 = {8b 00 05 00 10 00 00 8b 48 fc 32 cd 80 f9 10 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_EQ_2147685129_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EQ"
        threat_id = "2147685129"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3b 56 75 16 80 7b 01 4d 75 10 53 8b c3 c6 03 4d c6 43 01 5a}  //weight: 1, accuracy: High
        $x_1_2 = {6a 6e 58 6a 74 66 89 45 e8 58 6a 64 66 89 45 ea}  //weight: 1, accuracy: High
        $x_1_3 = {8d 43 34 50 8b 87 a4 00 00 00 83 c0 08 50 ff 75 dc ff 56 10 8b 43 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_ER_2147685388_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!ER"
        threat_id = "2147685388"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e8 04 0f 6e 07 0f 6e ce 0f ef c1 0f 7e 07 83 c7 04 85 c0 75 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_EP_2147685456_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.EP"
        threat_id = "2147685456"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 8d 85 dd 82 ff ff 8a ?? 88}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 88 00 00 00 36 8b 45 f4 8b 43 28 83 c0 ?? 66 8b 00 66 3b 45 ?? 0f 84 ?? ?? 00 00 36 8b 45 f4}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 43 28 83 c0 ?? 66 8b 00 66 3b 45 ?? 74 ?? eb}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 43 28 83 c0 ?? 66 8b 00 66 3b 45 ?? 0f 84 ?? 00 00 00 e9}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 42 28 83 c0 ?? 66 8b 00 66 3b 45 ?? 0f 84 ?? ?? 00 00 e9}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 85 dd 82 ff ff 33 c9 8a 08 33 4e 04 88 08 40 4a 75 f3 8d 85 dd 82 ff ff ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_EQ_2147685956_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.EQ"
        threat_id = "2147685956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 5a e4 3e c0 e8 ?? ?? ?? ?? (ff d0|e9)}  //weight: 1, accuracy: Low
        $x_1_2 = {68 5a e4 3e c0 (e9|60 e9)}  //weight: 1, accuracy: Low
        $x_1_3 = {68 0a ed dc e7 e8 ?? ?? ?? ?? (ff d0|e9)}  //weight: 1, accuracy: Low
        $x_1_4 = {68 0a ed dc e7 e9}  //weight: 1, accuracy: High
        $x_1_5 = {32 04 13 aa 42 (e9|3b)}  //weight: 1, accuracy: Low
        $x_1_6 = {32 04 13 e9 ?? ?? (00 00|ff ff)}  //weight: 1, accuracy: Low
        $x_1_7 = {32 04 13 aa e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_ES_2147686275_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!ES"
        threat_id = "2147686275"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 00 72 00 23 00 68 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 6e 74 65 72 20 61 20 6e 75 6d 62 65 72 20 74 6f 20 72 65 76 65 72 73 65 0a 00 00 52 00 65 00 76 00 65 00 72 00 73 00 65 00 20 00 6f 00 66 00 20 00 65 00 6e 00 74 00 65 00 72 00 65 00 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {35 36 73 67 6a 73 66 67 6a 35 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_ET_2147687128_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!ET"
        threat_id = "2147687128"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 96 bc 08 00 00 3b d0 76 4c 0f b6 8c 06 c0 08 00 00 0f b6 bc 06 c8 08 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {6a 02 6a 00 53 ff 15 ?? ?? ?? ?? 53 8d be bc 08 00 00 ff 15 ?? ?? ?? ?? 53 89 07 ff 15 ?? ?? ?? ?? 8b 07 53 40 50 8d 86 c0 08 00 00 6a 01 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_EU_2147687129_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EU"
        threat_id = "2147687129"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c9 9b cf 62 00 2b c1 2d dc 25 d7 02 89 45 ?? 8b 55 ?? 33 c0 (8b 4d ?? 8a|8a 42 10)}  //weight: 2, accuracy: Low
        $x_1_2 = {b9 30 00 00 00 33 c0 8d bd ?? ?? ?? ?? f3 ab 66 ab c7 45 fc ?? ?? ?? ?? 8b 55 fc 52 0e 00 66 8b 0d ?? ?? ?? ?? 66 89 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {00 59 41 70 70 2e 45 58 45 [0-2] 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_EV_2147687132_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EV"
        threat_id = "2147687132"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 8a 51 06 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 33 c9 8a 08 83 c1 03 3b d1 0f 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 33 c0 8a 42 04}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 03 6a 00 6a 01 68 00 00 00 80 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 6a 00 8b 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 45 ?? 6a 01 8b 4d ?? 81 c1 00 04 00 00 51 ff 15 ?? ?? ?? ?? 83 c4 08 89 85 ?? ?? ?? ?? 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_EX_2147687855_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!EX"
        threat_id = "2147687855"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 89 8d ?? ?? ff ff c6 85 ?? ?? ff ff 6d c6 85 ?? ?? ff ff 79 c6 85 ?? ?? ff ff 61 c6 85 ?? ?? ff ff 70 c6 85 ?? ?? ff ff 70 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 78 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 00 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 83 c4 08 89 45 ?? 83 7d ?? 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_EU_2147688111_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.EU"
        threat_id = "2147688111"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 d0 00 00 00 00 eb ?? 0f be 4d ff 83 e9 3d 89 4d d0 8a 55 d0 88 55 ff e9 ?? ?? ?? ?? 0f be 45 ff 85 c0 74 ?? 8b 4d e0 83 c1 01 89 4d e0 0f be 55 ff 83 ea 01}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 55 fd 0f b6 45 ff 33 c2 88 45 ff 8b 4d f8 8a 55 ff 88 91 04 00 ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_3 = {55 89 e5 8b 45 08 8b 4d 0c 83 ec 01 c6 45 ff ff 8a 10 8a 31 38 f2 75 ?? c6 45 ff 00 84 d2 74 ?? 40 41 eb ?? 80 7d ff 00 89 ec 5d c2 08 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 e4 03 45 e8 0f be 08 33 ca 8b 55 e4 03 55 e8 88 0a e9 ?? ?? ?? ?? 8b 45 e4 eb ?? 33 c0 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_EX_2147689085_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.EX"
        threat_id = "2147689085"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 36 8b 3b 03 fd 52 33 d2 c1 c2 03 32 17 47 80 3f 00 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = {ac 32 c3 aa 43 86 df e2 f7 8b 9d ?? ?? ?? ?? 03 5b 3c}  //weight: 1, accuracy: Low
        $x_1_3 = {97 33 c0 2d ?? ?? ?? ?? ab 35 ?? ?? ?? ?? ab 05 ?? ?? ?? ?? ab 35 ?? ?? ?? ?? ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FC_2147689427_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!FC"
        threat_id = "2147689427"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 48 50 8b 85 ?? ?? ?? ?? 8b 40 34 89 c2 8b 85 ?? ?? ?? ?? c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 89 4c 24 08 89 54 24 04 89 04 24 8b 85 ?? ?? ?? ?? ff d0}  //weight: 2, accuracy: Low
        $x_2_2 = {66 8b 40 06 0f b7 c0 3b 85 ?? ?? ?? ?? 0f 9f c0 84 c0 8b 85 ?? ?? ?? ?? 8b 40 3c 89 c2 8b 85 ?? ?? ?? ?? 8d 0c 02 8b 95 ?? ?? ?? ?? 89 d0 c1 e0 02 01 d0 c1 e0 03 01 c8 05 f8 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 50 28 8b 85 ?? ?? ?? ?? 01 c2 8b 85 ?? ?? ?? ?? 89 90 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 00 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_5 = {f3 aa c6 85 ?? ?? ?? ?? 69 c6 85 ?? ?? ?? ?? 72 c6 85 ?? ?? ?? ?? 74 c6 85 ?? ?? ?? ?? 75 c6 85 ?? ?? ?? ?? 61 c6 85 ?? ?? ?? ?? 6c c6 85 ?? ?? ?? ?? 41 c6 85 ?? ?? ?? ?? 6c c6 85 ?? ?? ?? ?? 6c c6 85 ?? ?? ?? ?? 6f c6 85 ?? ?? ?? ?? 63 c6 85 ?? ?? ?? ?? 45 c6 85 ?? ?? ?? ?? 78 c6 85 ?? ?? ?? ?? 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_FD_2147690189_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!FD"
        threat_id = "2147690189"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 64 fd ff ff 83 c0 01 33 85 74 fd ff ff 03 d0 88 55 ff dd 05 ?? ?? ?? ?? dd 9d}  //weight: 1, accuracy: Low
        $x_1_2 = {83 bd 34 fe ff ff 28 7d 20 e8 ?? ?? ?? ?? 25 01 00 00 80 79 05 48 83 c8 fe 40 8b 8d 34 fe ff ff 89 84 8d a8 fe ff ff eb c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_EY_2147690219_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.EY"
        threat_id = "2147690219"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 d8 8b f1 83 c2 02 83 c2 14 8b c2 8b 16 85 d2 7c 10}  //weight: 1, accuracy: High
        $x_1_2 = {75 dc 8b f1 03 07 83 c0 02 83 c0 14 8b 16 85 d2 7c 10}  //weight: 1, accuracy: High
        $x_1_3 = {e8 00 00 00 00 58 89 45 f4 c6 45 87 42 c6 45 88 21 c6 45 89 33}  //weight: 1, accuracy: High
        $x_1_4 = {8b 40 18 89 45 fc c6 45 ?? 47 c6 45 ?? 50 c6 45 ?? 41 33 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 0f 3a 4d ?? 75 ?? 8a 4f 03 3a 4d ?? 75 ?? 8a 4f 07 3a 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 06 50 c6 46 01 24 c6 46 02 78 e8 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_FC_2147690804_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FC"
        threat_id = "2147690804"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 04 00 00 00 6a 0b ff 15 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 8b d0 8d 4d ?? ff 15 ?? ?? 40 00 c7 45 fc 05 00 00 00 6a 0b 8d 55 ?? 52 6a 00 ff 15 ?? ?? 40 00 c7 45 fc 06 00 00 00 6a 0b ff 15 ?? ?? 40 00 c7 45 fc 07 00 00 00 c7 45 ?? ?? ?? 40 00 c7 45 ?? 08 00 00 00 8d 55 ?? 8d 4d ?? ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {66 c7 40 12 c9 3b 66 c7 40 16 08 74 66 c7 40 18 02 8b 66 c7 40 1a 00 c3 66 c7 40 0a 24 04 66 c7 40 08 8b 44 66 c7 40 0c 83 c0 66 c7 40 0e 08 8b 66 c7 40 10 00 31 66 c7 40 14 4c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Injector_FE_2147690917_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!FE"
        threat_id = "2147690917"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 68 00 10 00 00 57 ff 53}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 07 00 01 00 ff 75 ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = {51 51 89 45 f8 33 c0 50 68 00 00 00 08 6a 40 8d 4d f8}  //weight: 1, accuracy: High
        $x_1_4 = {68 1f 00 0f 00 ff 75 0c 89 45 fc 8b 45 08 ff 50}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 d8 03 4d cc 50 89 88 b0 00 00 00 ff 75 e4}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 46 34 8b 7e 50 57}  //weight: 1, accuracy: High
        $x_1_7 = {0f b7 46 06 ff 45 fc 59 83 c7 28 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule VirTool_Win32_Injector_FF_2147690995_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!FF"
        threat_id = "2147690995"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = {8b 4a 28 03 8d ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 89 8e b0 00 00 00}  //weight: 16, accuracy: Low
        $x_16_2 = {8b 73 28 03 b5 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 89 b1 b0 00 00 00}  //weight: 16, accuracy: Low
        $x_16_3 = {00 30 00 00 8d 45 ?? 89 45 ?? c7 45 ?? 40 00 00 00 03 00 c7 45 00}  //weight: 16, accuracy: Low
        $x_16_4 = {8b 71 50 89 75 ?? 8b 41 34 89 45 ?? ff 32 8b 5d ?? ff 33 56 50 ff b5 ?? ?? ?? ?? ff 95}  //weight: 16, accuracy: Low
        $x_16_5 = {8b 72 50 89 75 ?? 8b 4a 34 89 4d ?? ff 33 ff 30 56 51 ff b5 ?? ?? ?? ?? ff 95}  //weight: 16, accuracy: Low
        $x_16_6 = {c7 00 07 00 01 00 ff b5 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? ff 95 ?? ?? ?? ?? 50 ff 95}  //weight: 16, accuracy: Low
        $x_16_7 = {c7 06 07 00 01 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? ff b5 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? ff 95 ?? ?? ?? ?? 50 ff 95}  //weight: 16, accuracy: Low
        $x_1_8 = {4e 74 55 6e 6d 61 70 56 69 65 01 02 77 57 4f 66 53 65 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_9 = {56 69 72 74 75 61 ?? 41 6c 6c 01 02 6f 4f 63}  //weight: 1, accuracy: Low
        $x_1_10 = {57 72 69 74 65 50 72 6f 63 ?? 73 73 01 02 4d 6d 65 6d 6f 72 79}  //weight: 1, accuracy: Low
        $x_1_11 = {47 65 74 54 68 72 65 61 01 02 64 44 43 6f 6e 74 65 78 74}  //weight: 1, accuracy: Low
        $x_1_12 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 01 02 65 45 78 74}  //weight: 1, accuracy: Low
        $x_1_13 = {52 65 73 75 6d 65 01 02 54 74 68 72 ?? 61 64}  //weight: 1, accuracy: Low
        $x_1_14 = {52 65 61 64 50 01 02 72 52 6f 63 65 73 73 4d 65 6d 6f 72 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_16_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_FH_2147691811_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!FH"
        threat_id = "2147691811"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 ec 5f fa e9}  //weight: 1, accuracy: High
        $x_1_2 = {68 2b ed 9b 51}  //weight: 1, accuracy: High
        $x_1_3 = {68 17 ee b4 cf}  //weight: 1, accuracy: High
        $x_1_4 = {68 02 eb d4 97}  //weight: 1, accuracy: High
        $x_1_5 = {68 cb 6a a7 a0}  //weight: 1, accuracy: High
        $x_1_6 = {68 23 f9 35 9d}  //weight: 1, accuracy: High
        $x_6_7 = {8b 48 74 ff d1 85 c0 75 09 8b 55 f8 83 c2 01 89 55 f8 8b 45 f0 50 e8 ?? ?? ?? ?? 8b 08 ff d1 e9}  //weight: 6, accuracy: Low
        $x_4_8 = {8b 48 74 ff d1 83 7d 18 00 74 0a 8b 55 18 8b 45 fc 89 02 eb 0d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_FK_2147693635_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FK"
        threat_id = "2147693635"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 13 8e c0 09 50 e8 ?? ?? 00 00 8b 4d ?? 68 ee 38 83 0c 51 a3 ?? ?? 40 00 e8 ?? ?? 00 00 68 f2 5d d3 0b}  //weight: 3, accuracy: Low
        $x_1_2 = {68 99 b0 48 06}  //weight: 1, accuracy: High
        $x_1_3 = {68 44 27 23 0f}  //weight: 1, accuracy: High
        $x_1_4 = {68 57 64 e1 01}  //weight: 1, accuracy: High
        $x_1_5 = {68 ac 6f bc 06}  //weight: 1, accuracy: High
        $x_1_6 = {68 e3 ca d8 03}  //weight: 1, accuracy: High
        $x_1_7 = {68 05 d1 3d 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_FL_2147693692_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FL"
        threat_id = "2147693692"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f6 21 20 21 20 81 c6 11 10 11 10 89 30 83 c0 04 83 ea 01 75 e7}  //weight: 1, accuracy: High
        $x_1_2 = {67 42 79 44 c7 ?? ?? 75 60 40 7f c7 ?? ?? 73 75 43 43 c7 ?? ?? 1d 75 7d 7f c7 ?? ?? 40 49 ce cf c7 ?? ?? ce cf cf cf e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FI_2147694057_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!FI"
        threat_id = "2147694057"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 83 ec 08 c7 84 24 ?? ?? ?? ?? 00 30 00 00 [0-48] 8b 76 34 [0-48] 8b 7f 50 8b 9c 24 00 89 44 24 ?? 89 e0 89 58 0c 89 78 08 89 70 04 89 10 c7 40 10 40 00 00 00 ff d1}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d0 83 ec 14 8b 8c 24 d4 01 00 00 8b 94 24 ?? ?? ?? ?? 03 4a 28 8b 94 24 dc 01 00 00 89 8a b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 00 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 49 06 39 c8 0f 8d 35 01 00 00 8b 84 24 ?? ?? ?? ?? 8b 40 3c 03 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 0f af 8c 24 ?? ?? ?? ?? 01 c8 89 84 24 f8 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_FN_2147694687_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FN"
        threat_id = "2147694687"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 95 04 ff ff ff c7 45 fc 6d 00 00 00 8b 85 e8 fd ff ff 0f b7 48 06 39 8d ec fd ff ff 0f 8d 8e 00 00 00}  //weight: 4, accuracy: High
        $x_2_2 = {ff ff 68 00 00 00 b9 ba 00 00 00 2b 8d ?? ?? ff ff 89 8d}  //weight: 2, accuracy: Low
        $x_2_3 = {ec 01 00 00 8b 8d ?? ff ff ff 51 8b 95 ?? ff ff ff 52 ff 95 ?? ff ff ff b8 00 30 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {89 02 b9 07 00 00 00 be ?? ?? 00 10 8d bd ?? ?? ff ff f3 a5 66 a5 a4 33 c9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_FQ_2147694862_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FQ"
        threat_id = "2147694862"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {36 00 36 00 30 00 46 00 44 00 42 00 (43|2d|46) ?? ?? ?? 36 00 36 00 30 00 46 00}  //weight: 5, accuracy: Low
        $x_1_2 = {ff 75 c0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0 8d 4d c0 e8 ?? ?? ?? ?? ff 75 c0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0 8d 4d c0 e8 ?? ?? ?? ?? ff 75 c0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0 8d 4d c0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FQ_2147694862_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FQ"
        threat_id = "2147694862"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 00 31 00 46 00 39 00 32 00 31 00 46 00 46 00 32 00 31 00 46 00 46 00 37 00 35 00 [0-24] 36 00 36 00 30 00 46 00 [0-24] 36 00 36 00 30 00 46 00}  //weight: 1, accuracy: Low
        $x_1_2 = "817C1DFC9090909075" wide //weight: 1
        $x_1_3 = {36 00 36 00 74 00 30 00 46 00 74 00 [0-16] 36 00 36 00 74 00 30 00 46 00 74 00 [0-16] 36 00 36 00 74 00 30 00 46 00 74 00 [0-16] 36 00 36 00 74 00 30 00 46 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {38 00 31 00 74 00 37 00 43 00 74 00 31 00 44 00 74 00 46 00 43 00 74 00 [0-64] 36 00 36 00 74 00 30 00 46 00 74 00}  //weight: 1, accuracy: Low
        $x_2_5 = {34 00 30 00 33 00 31 00 43 00 31 00 38 00 31 00 46 00 39 00 38 00 35 00 [0-127] 43 00 30 00 38 00 35 00 43 00 30 00 37 00 35 00 [0-32] 36 00 36 00 30 00 46 00 [0-128] 36 00 36 00 30 00 46 00}  //weight: 2, accuracy: Low
        $x_2_6 = {64 a1 30 00 00 00 0f [0-24] 8b 40 0c [0-1] 0f [0-72] 8b 40 14 [0-1] 0f [0-72] 8b 40 28 [0-1] 0f [0-104] 8a 3c 08 [0-1] 0f [0-104] 8a 1c 0e [0-1] 0f}  //weight: 2, accuracy: Low
        $x_2_7 = {64 8b 15 30 00 00 00 0f [0-24] 8b 52 0c [0-1] 0f [0-72] 8b 52 14 [0-1] 0f [0-72] 8b 52 28 [0-1] 0f [0-104] 8a 3c 0a [0-1] 0f [0-104] 8a 1c 0e [0-1] 0f}  //weight: 2, accuracy: Low
        $x_2_8 = {bb 30 00 00 00 0f [0-32] 64 8b 1b [0-6] 0f [0-72] 8b 5b 14 [0-6] 0f [0-72] 8b 53 28 [0-6] 0f [0-104] 8a 3c (02|0a) [0-6] 0f [0-104] 8a (1c 0e|0c 06) [0-6] 0f}  //weight: 2, accuracy: Low
        $x_2_9 = {ba 30 00 00 00 66 0f [0-32] 64 8b 1a [0-6] 0f [0-72] 8b 5b 14 [0-6] 0f [0-72] 8b (43|53) 28 [0-6] 0f [0-104] 8a 3c (02|0a|10) [0-6] 0f [0-104] 8a 03 02 02 02 1c 0e 0c 06 0c 16 [0-6] 0f}  //weight: 2, accuracy: Low
        $x_2_10 = {ba 30 00 00 00 0f [0-32] 64 8b 1a [0-6] 0f [0-72] 8b 5b 14 [0-6] 0f [0-72] 8b (43|53) 28 [0-6] 0f [0-104] 8a 3c (02|0a|10) [0-104] 8a 03 02 02 02 1c 0e 0c 06 0c 16 [0-6] 0f}  //weight: 2, accuracy: Low
        $x_2_11 = {b9 30 00 00 00 0f [0-32] 64 8b 09 [0-1] 0f [0-72] 8b 49 14 [0-1] 0f [0-72] 8b 51 28 [0-1] 0f [0-104] 8a 3c 0a [0-1] 0f [0-104] 8a (04|1c) 0e [0-1] 0f}  //weight: 2, accuracy: Low
        $x_2_12 = {8b b4 24 00 03 00 00 [0-24] ad [0-6] 0f [0-24] 8b 8c 24 04 03 00 00 [0-6] 0f [0-24] 39 08 75 (d0|2d|f0) [0-24] 8b 8c 24 08 03 00 00 [0-6] 0f}  //weight: 2, accuracy: Low
        $x_2_13 = {81 ec 00 03 00 00 [0-6] 0f [0-24] b8 00 03 00 00 [0-24] 8b 34 04 [0-24] ad [0-24] 8b 8c 24 04 03 00 00 [0-6] 0f [0-24] 39 08 75 (d0|2d|f0) [0-24] 8b 8c 24 08 03 00 00 [0-6] 0f}  //weight: 2, accuracy: Low
        $x_2_14 = {81 dc 00 03 00 00 [0-6] 0f [0-24] b8 00 03 00 00 [0-24] 8b 34 04 [0-24] ad [0-24] 8b 8c 24 04 03 00 00 [0-6] 0f [0-24] 39 08 75 (d0|2d|f0) [0-24] 8b 8c 24 08 03 00 00}  //weight: 2, accuracy: Low
        $x_2_15 = {81 dc fc 02 00 00 [0-6] 0f [0-24] b8 fc 02 00 00 [0-24] 8b 34 04 [0-24] ad [0-24] 8b 8c 24 00 03 00 00 [0-24] 39 08 75 (d0|2d|f0) [0-24] 8b 8c 24 04 03 00 00}  //weight: 2, accuracy: Low
        $x_2_16 = {81 ec fc 02 00 00 [0-6] 0f [0-24] b8 fc 02 00 00 [0-24] 8b 34 04 [0-24] ad [0-24] 8b 8c 24 00 03 00 00 [0-6] 0f [0-24] 39 08 75 (d0|2d|f0) [0-104] 08 03 00 00}  //weight: 2, accuracy: Low
        $x_2_17 = {81 ec fc 02 00 00 [0-6] 0f [0-24] 8b b4 24 00 03 00 00 [0-24] ad [0-24] 8b 9c 24 04 03 00 00 [0-6] 0f [0-24] 39 18 [0-24] 75 (d0|2d|f0)}  //weight: 2, accuracy: Low
        $x_2_18 = {b8 fc 02 00 00 0f [0-24] 8b 34 04 [0-6] 0f [0-24] ad [0-24] 8b 8c 24 00 03 00 00 [0-6] 0f [0-24] 39 08 75 (d0|2d|f0) [0-104] 08 03 00 00}  //weight: 2, accuracy: Low
        $x_2_19 = {81 ec 09 01 00 00 [0-6] 0f [0-16] 44 [0-6] 0f [0-56] ad [0-6] 0f [0-24] 8b 9c 24 10 01 00 00 [0-24] 39 18 [0-24] 75 (d0|2d|f0)}  //weight: 2, accuracy: Low
        $x_2_20 = {81 ec 0a 01 00 00 [0-6] 0f [0-16] 44 [0-6] 0f [0-56] ad [0-6] 0f [0-24] 8b 9c 24 10 01 00 00 [0-24] 39 18 [0-24] 75 (d0|2d|f0)}  //weight: 2, accuracy: Low
        $x_2_21 = {81 ec 0b 01 00 00 [0-6] 0f [0-16] 44 [0-6] 0f [0-56] ad [0-6] 0f [0-24] 8b 9c 24 10 01 00 00 [0-24] 39 18 [0-24] 75 (d0|2d|f0)}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_FO_2147694958_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FO"
        threat_id = "2147694958"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "127.0.0.1:8080" ascii //weight: 1
        $x_1_2 = "NOKIAN95/WEB" ascii //weight: 1
        $x_1_3 = "http\\shell\\open\\command" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = {fb f0 bf 5f 97 0f 2c 38}  //weight: 1, accuracy: High
        $x_1_6 = {6a 40 68 00 10 00 00 68 00 28 00 00 6a 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FR_2147695048_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FR"
        threat_id = "2147695048"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6090\\E890\\4E90\\0090\\0090\\0090\\6B90\\0090\\6590\\0090\\7290\\0090\\6E90\\0090\\6590\\0090\\6C90\\0090\\3390\\0090\\3290" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FL_2147695053_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FL!!GenInjectorFL"
        threat_id = "2147695053"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "GenInjectorFL: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f6 21 20 21 20 81 c6 11 10 11 10 89 30 83 c0 04 83 ea 01 75 e7}  //weight: 1, accuracy: High
        $x_1_2 = {67 42 79 44 c7 ?? ?? 75 60 40 7f c7 ?? ?? 73 75 43 43 c7 ?? ?? 1d 75 7d 7f c7 ?? ?? 40 49 ce cf c7 ?? ?? ce cf cf cf e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FS_2147695084_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FS"
        threat_id = "2147695084"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 56 8b 4d ?? 03 4d ?? 88 01 eb 12 8b 55 ?? 03 55 ?? 8a 02 2c 98}  //weight: 1, accuracy: Low
        $x_1_2 = "launch" ascii //weight: 1
        $x_1_3 = "prompt.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FS_2147695084_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FS"
        threat_id = "2147695084"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 4d 50 72 6f 74 65 63 74 [0-16] 00 b0 04 00}  //weight: 10, accuracy: Low
        $x_5_2 = "SeDebugPrivilege" ascii //weight: 5
        $x_1_3 = {6c 61 75 6e 63 68 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 6f 6e 66 69 67 2e 69 6e 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_FS_2147695084_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FS"
        threat_id = "2147695084"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 c4 2f c6 45 c5 63 c6 45 c6 20 c6 45 c7 70 c6 45 c8 69 c6 45 c9 6e c6 45 ca 67 c6 45 cb 20 c6 45 cc 31 c6 45 cd 32 c6 45 ce 37 c6 45 cf 2e [0-128] c6 45 e1 33 c6 45 e2 32 c6 45 e3 2e c6 45 e4 65 c6 45 e5 78 c6 45 e6 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FP_2147695168_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FP"
        threat_id = "2147695168"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 ad fb ff ff e8 c6 85 ae fb ff ff f1 c6 85 af fb ff ff b9}  //weight: 1, accuracy: High
        $x_1_2 = {83 f0 8b 8d 8d ad fb ff ff 8b 55 bc 01 ca 88 02 ff 45 bc 83 7d bc 1d}  //weight: 1, accuracy: High
        $x_1_3 = {c7 00 07 00 01 00 8d 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FU_2147695694_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FU"
        threat_id = "2147695694"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 99 f7 7d 0c 8b 45 08 0f be 0c 10 8b 55 10 03 55 fc 0f be 02 33 c1 8b 4d 10 03 4d fc 88 01}  //weight: 1, accuracy: High
        $n_100_2 = "\\xmcrypto.pdb" ascii //weight: -100
        $n_100_3 = "hr_decryptor\\bin\\HRDecrypter.pdb" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FT_2147696233_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FT"
        threat_id = "2147696233"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 07 07 00 01 00 ff d6 8b 4c 24 ?? 57 51 ff d0}  //weight: 2, accuracy: Low
        $x_2_2 = {83 c0 34 50 8b 44 24 ?? 83 c2 08 52 50 ff 54 24 ?? 8b 4c 24 ?? 8b 51 28 03 54 24}  //weight: 2, accuracy: Low
        $x_1_3 = "RevdFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FT_2147696233_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FT"
        threat_id = "2147696233"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 00 07 00 01 00 8d 85 ?? ?? ff ff 83 c0 7d}  //weight: 2, accuracy: Low
        $x_2_2 = {ff d0 83 ec 14 8b 85 ?? ?? ff ff 8b 50 28 8b 85 ?? ?? ff ff 01 c2 8b 85 ?? ?? ff ff 89 90 b0 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = "CreaOeFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FT_2147696233_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FT"
        threat_id = "2147696233"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 02 07 00 01 00 8d 8d ?? ?? ff ff 51 ff b5 ?? ?? ff ff ff 55 ?? 89 45}  //weight: 2, accuracy: Low
        $x_2_2 = {83 c0 34 50 ff b5 ?? ?? ff ff ff b5 ?? ?? ff ff ff 55 ?? 8b 95 ?? ?? ff ff 8b 4a 28 03 8d ?? ?? ff ff 8b 85 ?? ?? ff ff 89 88 b0 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = "kernel32.dVl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FW_2147696421_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FW"
        threat_id = "2147696421"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "codeblox\\___stubz\\Gccalaxy\\main.cpp" ascii //weight: 2
        $x_1_2 = {b0 00 00 00 8d 85 ?? ?? ff ff 05 96 00 00 00 89 44 24 04 8b 85 ?? ?? ff ff 89 04 24 8b 85 ?? ?? ff ff ff d0 02 00 89 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FZ_2147696594_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FZ"
        threat_id = "2147696594"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 08 83 45 ?? 01 83 45 ?? 01 81 7d ?? ?? ?? 01 00 7e ef}  //weight: 1, accuracy: Low
        $x_1_2 = {00 53 63 75 6c 6b 73 00 53 63 75 6c 6b 73 40 32 38 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Injector_FZ_2147696594_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FZ"
        threat_id = "2147696594"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 45 f8 ff 45 f8 81 7d f8 ?? ?? 00 00 7c f1 0e 00 c7 45 f8}  //weight: 2, accuracy: Low
        $x_1_2 = {b9 82 00 00 00 f3 a5 a4}  //weight: 1, accuracy: High
        $x_1_3 = {b9 51 00 00 00 f3 a5 a4}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 74 65 72 6e 75 6d 00 5f 5f 5f 43 50 50 64 65 62 75 67 48 6f 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FZ_2147696594_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FZ"
        threat_id = "2147696594"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 44 7d 0c 8a 4d ?? 88 0c 02 40 83 f8 44 7c f4 8d 95 ?? ?? ff ff 8b 45 ?? 83 f8 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 83 c0 ff 85 c9 75 f1 33 c0 89 45 ?? c7 45 ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {be 84 a0 40 00 8d bd ?? ?? ff ff b9 ?? 00 00 00 f3 a5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_GA_2147696614_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GA"
        threat_id = "2147696614"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 cc fd ff ff 72 c6 85 cd fd ff ff 7a c6 85 ce fd ff ff 7a c7 85 3c ff ff ff d0 01 00 00 c6 85 c3 fd ff ff 7d c7 45 d8 00 00 00 00 c7 45 d8 00 00 00 00 eb 34 c7 85 38 ff ff ff 57 01 00 00 8d 95 c3 fd ff ff 8b 45 d8 01 d0 8a 00 83 f0 16 8d 8d c3 fd ff ff 8b 55 d8 01 ca 88 02 c7 85 34 ff ff ff 12 00 00 00 ff 45 d8 83 7d d8 0b 0f 9e c0 84 c0 75 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_GB_2147696646_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GB"
        threat_id = "2147696646"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f b6 0c 19 03 ca 66 81 e1 ff 00 79 09 66 49 66 81 c9 00 ff 66 41 0f bf d1 8b 8d 34 ff ff ff 8a 14 1a 8a 19 32 da 88 19 8b 8d 44 ff ff ff 03 c1 e9 57 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "TMPNETLOAD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_GC_2147696830_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GC"
        threat_id = "2147696830"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8d 8c 3d ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 05 ?? ?? ?? ?? 3c f3 88 01 73 04 fe c8}  //weight: 1, accuracy: Low
        $x_1_2 = {51 51 83 c0 28 dd 1c 24 ff d0 59 59 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_GE_2147696959_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GE"
        threat_id = "2147696959"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f6 90 c6 45 f7 8b c6 45 f8 ff c6 45 f9 55 6a 06 8d 45 f4}  //weight: 1, accuracy: High
        $x_1_2 = {b6 08 66 d1 eb 66 d1 d8 73 09 66 35 20 83 66 81 f3 b8 ed fe ce 75 eb}  //weight: 1, accuracy: High
        $x_1_3 = {ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 dc 6e c6 45 dd 74 c6 45 de 64 c6 45 df 6c c6 45 e0 6c c6 45 e1 00 8d 45 dc 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_GF_2147697056_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GF"
        threat_id = "2147697056"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 78 fc 80 80 80 80 75 00 00 81 78 fc 80 80 80 80 31 30 [0-32] 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fd 21 ff 21 ff 75 00 00 81 fd 21 ff 21 ff 8b 2f [0-32] 46 [0-32] 31 f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_GG_2147697232_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GG"
        threat_id = "2147697232"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 4b 0a 0f 51 8a 0d 34 30 40 00 f7 ef c1 fa 0a 8b c2 c1 e8 1f 8a 94 02 20 30 40 00 32 d1 80 fa f2 88 94 35 04 e2 ff ff 77 09 fe ca 88 94 35 04 e2 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {75 b3 68 10 65 f5 40 6a 00 8d 8d 2c e2 ff ff ff d1 83 c4 08 eb 9f}  //weight: 1, accuracy: High
        $x_1_3 = {9b 1a 85 30 9b 1a 86 3a 9b 1a 87 2f 9b 1a 80 33 9b 1a 81 3a 9b 1a 82 31 9b 1a 83 68 9b 1a bc 6f 9b 1a bd 73 9b 1a be 39 9b 1a bf 31 9b 1a b8 31 d5 02 b9 9b}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 d8 6b c6 45 d9 65 c6 45 da 72 c6 45 db 6e c6 45 dc 65 c6 45 dd 6c c6 45 de 33 c6 45 df 32 c6 45 e0 2e c6 45 e1 64 c6 45 e2 6c c6 45 e3 6c 88 5d e4}  //weight: 1, accuracy: High
        $x_1_5 = {3b 94 da 55 a3 a3 a3 73 5d 3b 94 da 57 a3 a3 a3 09 5d 3b 94 da 51 a3 a3 a3 12 5d 3b 94 da 53 a3 a3 a3 0d 5d 3b d6 c2 4d a3 a3 a3 a3 0a b5 d2}  //weight: 1, accuracy: High
        $x_1_6 = {66 c7 85 08 ff ff ff 2e 00 66 c7 85 0a ff ff ff 54 00 66 c7 85 0c ff ff ff 4d 00 66 c7 85 0e ff ff ff 50 00 66 89 9d 10 ff ff ff ff 55 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_GK_2147697792_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GK"
        threat_id = "2147697792"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 c4 01 00 00 83 ec 04 50 6a 00 52 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8a 00 31 c8 88 84 1d ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {89 d0 c1 e0 02 01 d0 8d 14 85 00 00 00 00 01 d0 8d 55 ?? 01 d0 01 c8 2d ?? ?? 00 00 88 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FM_2147705497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!FM"
        threat_id = "2147705497"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac 51 8b 0f 33 c1 aa 59 4b 75 04 5b 2b f3 53 49 75 ee}  //weight: 1, accuracy: High
        $x_1_2 = {8b f1 33 c0 66 ad 85 c0 74 05 03 c1 50 eb f3 89 45 0c 89 45 10 6a 01 59 ff 55 e8}  //weight: 1, accuracy: High
        $x_1_3 = {e8 22 00 00 00 b0 0d 49 00 ea 00 0a 01 24 01 88 01 07 02 fa 02 3f 03 fb 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_GL_2147705510_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GL"
        threat_id = "2147705510"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d0 0f b6 08 8b 45 ?? 99 f7 7d ?? 89 d0 89 c2 8b 45 10 01 d0 0f b6 00 31 c8 8d 8d ?? ?? ff ff 8b 55 ?? 01 ca 88 02 83 45 ?? 01 8b 45 ?? 99 f7 7d ?? 89 d0 85 c0 75 07 c7 45 ?? 00 00 00 00 83 45 ?? 01 8b 45 ?? 3b 45 ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FO_2147705960_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!FO"
        threat_id = "2147705960"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RernQl32.dll" ascii //weight: 1
        $x_1_2 = "SreatdFileANU" ascii //weight: 1
        $x_1_3 = "RfadFileAfk" ascii //weight: 1
        $x_3_4 = {0f b6 8c 04 20 06 00 00 8b 94 24 40 05 00 00 8b b4 24 78 08 00 00 89 84 24 10 01 00 00 89 d0 99 f7 fe 8b 84 24 84 08 00 00 0f b6 04 10 31 c1 88 cb 8b 84 24 10 01 00 00 88 9c 04 20 06 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FQ_2147705962_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.gen!FQ"
        threat_id = "2147705962"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wernelu2.dllJXOrvOI" ascii //weight: 1
        $x_1_2 = "CIeaHGFileA" ascii //weight: 1
        $x_1_3 = "ReadMileljDOBp" ascii //weight: 1
        $x_3_4 = {89 d0 03 45 14 8a 00 31 c8 88 03 8b 85 5c ff ff ff 89 c3 03 9d e4 fe ff ff 8b 85 5c ff ff ff 03 85 e4 fe ff ff 8a 08 8b 85 5c ff ff ff 99 f7 bd 3c ff ff ff 89 d0 03 45 14 8a 00 31 c8 88 03}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_GS_2147705966_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GS"
        threat_id = "2147705966"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 79 43 6e 65 6c 33 32 76 64 6c 6c 53 58 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 72 65 42 66 65 46 69 6c 65 41 72 46 57 53 71 6e 6f 72 46 5a 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 65 61 4f 6d 69 6c 65 45 52 00}  //weight: 1, accuracy: High
        $x_2_4 = {66 a1 f0 e1 00 10 0f bf c8 66 a1 08 e2 00 10 88 c2 66 a1 20 e1 00 10 88 d3 28 c3 88 d8 88 84 0d a1 fc ff ff c7 85 78 fd ff ff 06 01 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_GY_2147706310_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GY"
        threat_id = "2147706310"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 8d 8d 34 ff ff ff 51 53 68 1f 00 0f 00 8d ?? ?? ?? ff ff 51 ff 55 cc 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 53 51 8b 0f ac 33 c1 aa 59 4b 75 04 5b 2b f3 53 e2 ef}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 14 8b 4a 04 ff 55 e8 55 59 ff d0 50 8b 45 10 ff 4d 10 ba 1c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {3b fa 72 04 41 5a eb f3 5e 8b 55 14 89 4a 0c 67 e3 03 ff 55 e8}  //weight: 1, accuracy: High
        $x_2_5 = {74 05 03 c2 50 eb f3 89 45 0c 89 45 10 b9 01 00 00 00 ff 55 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_AEK_2147706400_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.AEK"
        threat_id = "2147706400"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d0 40 40 8b c8 33 c0 41 66 ad 66 2b c2 74 04 2b f1 eb f5}  //weight: 1, accuracy: High
        $x_1_2 = {8b 07 8b 16 33 d0 46 88 17 8b c3 48 74 0a 47 8b d8 e2 ed}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 f8 ff 45 f8 47 47 40 47 47 8b 4d f4 3b c1 72}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 00 8b 4e 1b 4e 4e 4e 8d 04 81 8b 4d fc 03 c1 8b 00 03 c1 eb d1}  //weight: 1, accuracy: High
        $x_1_5 = {40 48 74 12 47 47 8b 45 f8 ff 45 f8 47 8b 4d f4 47 40 3b c1 72 c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_HB_2147706694_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HB"
        threat_id = "2147706694"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 2f 0f d8 f0 [0-16] 46 [0-32] 31 f5 66 0f 73 d3 5c [0-16] 3b ac 24 10 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {31 32 66 0f fd d2 [0-32] 83 c2 04 0f d5 c1 [0-21] 39 5a fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_HD_2147706952_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HD"
        threat_id = "2147706952"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 48 74 12 47 47 8b 45 f8 ff 45 f8 47 8b 4d f4 47 40 3b c1 72 c5}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 00 8b 4e 1a 4e 4e 4e 8d 04 81 4e 8b 4d fc 03 c1 8b 00 03 c1 eb}  //weight: 1, accuracy: High
        $x_1_3 = {03 c1 03 c2 4e 4e 4e 0f b7 00 8b 4e 1e 8d 04 81 4e 8b 4d fc 03 c1 8b 00 03 c1 eb c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_HE_2147707118_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HE"
        threat_id = "2147707118"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {db 45 dc dc 1d ?? ?? ?? ?? df e0 f6 c4 41 75 ?? 68 ?? ?? ?? ?? 6a 00 8d 95 ?? ?? ?? ?? ff d2}  //weight: 1, accuracy: Low
        $x_1_2 = {32 d8 88 9c 3d [0-34] f7 6d d8 c1 fa 08 8b c2 c1 e8 1f 03 d0 02 84 15 ?? ?? ?? ?? 3c 05 8d 8c 15 ?? ?? ?? ?? 77 [0-24] f7 6d e0 c1 fa 03 8b c2 c1 e8 1f 03 d0 8a 94 15 ?? ?? ?? ?? fe ca 88 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Injector_HF_2147707125_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HF"
        threat_id = "2147707125"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c9 2c 8b 3d ?? ?? ?? ?? 2b d1 89 15 ?? ?? ?? ?? 8b 8c 06 ?? ?? ?? ?? 0f b6 d2 2b fa 81 c1 ?? ?? ?? ?? 83 ef 04 89 3d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 89 8c 06 ?? ?? ?? ?? 83 c0 04 3d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d6 83 ea 3b 8b cf 2b ce 83 e9 3b 0f b6 f2 8b e9 2b ee 83 ed 04 85 c0 a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 0f b6 d3 2b ca 68 ?? ?? ?? ?? 83 e9 04 50 89 0d ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_HG_2147707165_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HG"
        threat_id = "2147707165"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b de 8b b4 02 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 b4 02 ?? ?? ?? ?? 0f b7 c3 99 2b c7 1b 15 ?? ?? ?? ?? 33 ff 03 44 24 10 89 1d ?? ?? ?? ?? 13 d7 8b 7c 24 14 83 c7 04 81 ff ?? ?? ?? ?? 89 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 7c 24 14 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {66 03 d1 66 83 c2 08 66 89 15 ?? ?? ?? ?? 0f b7 d2 8b f2 2b f1 83 ee 3a 85 c0 89 35 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 8b 4c 24 0c 8d 54 0a 0c 8d 4c 24 14 51 50 89 15 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 4c 02 08 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 c2 3b 0f b7 05 88 a4 42 00 2b d0 89 55 e8 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 8b 7d ec 46 be ?? ?? ?? ?? 57 03 f3 81 ee ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_HH_2147707188_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HH"
        threat_id = "2147707188"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d ff 8a 65 ff 8a 4d f7 32 e1 88 65 ff 8b 45 ec 03 45 e0 8a 4d ff 88 08 8b 55 e0 83 c2 01 89 55 e0 e9}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 18 ff ff ff 56 c6 85 19 ff ff ff 69 c6 85 1a ff ff ff 72 c6 85 1b ff ff ff 74 c6 85 1c ff ff ff 75 c6 85 1d ff ff ff 61 c6 85 1e ff ff ff 6c c6 85 1f ff ff ff 41 c6 85 20 ff ff ff 6c c6 85 21 ff ff ff 6c c6 85 22 ff ff ff 6f c6 85 23 ff ff ff 63}  //weight: 1, accuracy: High
        $x_1_3 = {51 8b 55 f8 52 ff 55 fc 89 85 98 fe ff ff 8d 45 98 50 8b 4d f8 51 ff 55 fc 89 85 c8 fe ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {eb dd 8b 8d a8 fe ff ff 8b 55 f4 03 51 28 89 55 cc ff 55 cc 6a 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_HI_2147707304_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HI"
        threat_id = "2147707304"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6a 01 6a ff 6a 20 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {3c 14 52 73 45 b3 52 73 36 b1 51 73 f7 71 4f 73 5e 47 44 73 68 91 44 73 ea}  //weight: 1, accuracy: High
        $x_1_3 = {8b d0 8d 8d 0c fd ff ff ff d6 50 ff d7 8b d0 8d 8d 08 fd ff ff ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_HJ_2147707383_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HJ"
        threat_id = "2147707383"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d2 85 c0 0f 84 86 0d 00 00 6a 04 68 00 10 00 00 6a 04 6a 00 a1 ?? ?? ?? ?? ff d0 89 45 fc 33 c9 75 3f}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d0 85 c0 0f 84 b0 0b 00 00 6a 00 6a 04 8d 4d ec 51 8b 55 fc 8b 82 a4 00 00 00 83 c0 08 50 8b 4d dc 51 8b 15 d4 14 42 00 ff d2}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 8b 4d f4 8b 51 54 52 8b 45 0c 50 8b 4d d8 51 8b 55 dc 52 a1 ec 14 42 00 ff d0 33 c9 75}  //weight: 1, accuracy: High
        $x_1_4 = {8b 55 fc 52 8b 45 e0 50 8b 0d d0 14 42 00 ff d1 33 d2 75}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 e0 50 8b 0d f4 14 42 00 ff d1 33 d2 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_HK_2147707384_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HK"
        threat_id = "2147707384"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 19 8b 45 fc 8b 4d 8c 8b 14 81 8b 45 94 03 45 fc 8b 4d 80 8a 00 88 04 11 eb d6}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 80 00 00 6a 00 8b 4d 94 51 ff 55 b0 68 00 80 00 00 6a 00 8b 55 8c 52 ff 55 b0 6a 04 68 00 10 00 00 68 00 10 03 00 6a 00 ff 55 bc 89 45 c0}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 d8 8b 42 04 8b 4d c0 8d 94 01 00 f0 ff ff 52 ff 55 d4 83 c4 0c eb 28}  //weight: 1, accuracy: High
        $x_1_4 = {83 c0 03 89 85 1c ff ff ff 58 8b 85 1c ff ff ff 50 ff 95 14 ff ff ff 8b 85 0c ff ff ff c9 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_HL_2147707385_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HL"
        threat_id = "2147707385"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 07 0f 81 8d fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {72 78 0f 81 3e ff ff ff eb}  //weight: 1, accuracy: High
        $x_1_3 = {39 f1 0f 81 aa 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_HM_2147707386_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HM"
        threat_id = "2147707386"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8d 4d e0 51 ff 75 d0 35 ?? ?? ?? ?? 50 ff 75 d4 e8 ?? ?? ?? ?? 53 89 45 64 81 ce ?? ?? ?? ?? ff 55 0c 03 f8 39 5d 64 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 4c ff 75 64 ff 75 58 ff 55 b8 69 ff ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 83 c4 0c 81 fe ?? ?? ?? ?? 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 58 8b 4d 4c 8d 1c 08 6a f6 c6 03 e9 ff}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 64 2b 45 58 6a f6 83 e8 05 89 43 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_HO_2147707507_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HO"
        threat_id = "2147707507"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 10 4e 75 1a 51 8b ce 8b 01 8b c8 58 33 ca}  //weight: 1, accuracy: High
        $x_1_2 = {8a d5 40 88 10 8b f8 59 46 59 5a 4a 85 d2 74 db e2 bd}  //weight: 1, accuracy: High
        $x_1_3 = {58 5e 8b f8 8d 0d ?? ?? ?? ?? ff 36 57 ff d1 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {80 79 44 00 75 0c 80 b9 88 00 00 00 00 75 03 33 c0 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_HP_2147707510_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HP"
        threat_id = "2147707510"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 58 ff d3 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {51 8b ce ff 37 8b 01 33 04 24 aa 58 59 46 8b c3 48 74 09 8b d8 e2 e9}  //weight: 1, accuracy: High
        $x_1_3 = {5b 2b f3 8b c3 50 eb ef}  //weight: 1, accuracy: High
        $x_1_4 = {8b d8 58 5a 51 50 52 68 ?? ?? ?? ?? ff d3 a1 ?? ?? ?? ?? b9 80 00 00 00 bf}  //weight: 1, accuracy: Low
        $x_1_5 = {5b 8b 7d fc 8b 73 18 8b 43 1c 8b 4b 0c 8b 53 08 ff d2 8b 4b 20 8b 45 fc 03 45 f4 51 ff d0}  //weight: 1, accuracy: High
        $x_1_6 = {eb d3 47 d9 18 e6 e6 90 90 ee 70 8a 58 b0 d4 99 4c 0b 1a b2 fd 87 f1 17 ab 28 95 65 52 6e 33 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_HQ_2147707512_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HQ"
        threat_id = "2147707512"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d0 5a 89 45 fc 33 c0 8a 03 43 85 c0 75 f9 53 8b 42 10 50 8b 42 08 ff d0 89}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 04 8b 7d fc 57 51 8b 75 f8 03 f1 4e c1 e9 03 8b d1 b3 66 56 51 b9 08 00 00 00 8a 07 32 c3 88 06 47}  //weight: 1, accuracy: High
        $x_1_3 = {eb 06 8a 06 88 07 47 46 8b 45 f0 3b f0 72 c7}  //weight: 1, accuracy: High
        $x_1_4 = {74 16 48 8b f0 51 57 fc f3 a4 5f 59 03 f9 42 42 42 42 43 43 43 43 eb df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_HY_2147708054_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.HY"
        threat_id = "2147708054"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 5d d4 8b 5d f8 8b 5b 08 83 c3 50 89 5d d0 89 65 cc b8 00 00 00 00 89 45 c8 8d 45 c8 50 8b 5d d0 ff 33 ff 75 d4 ff 75 e8 8b 5d d8 ff 33 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {5b 83 c3 04 5b 83 c3 04 ff 15 ?? ?? ?? ?? 90 90 90 90 39 65 c0 74 0d 68 06 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 75 b8 68 00 00 00 00 ff 15 ?? ?? ?? ?? 90 90 90 90 39 65 b4 74 0d 68 06 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c7 04 8b 03 83 c3 04 89 07 83 c7 04 8b 5d d8 ff 33 ff 15 ?? ?? ?? ?? 90 90 90 90 39 65 d4 74 0d 68 06 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_IA_2147708501_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.IA"
        threat_id = "2147708501"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 50 c6 45 ?? 6d c6 45 ?? 79 c6 45 ?? 61 c6 45 ?? 70 c6 45 ?? 70 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_IB_2147708502_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.IB"
        threat_id = "2147708502"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 ce 00 6a 2e 68 ?? ?? ?? ?? 6a 0b 8d 8d 38 ff ff ff 51 e8 ?? ?? ?? ?? 83 c4 10 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 99 b9 b9 41 c7 00 f7 f9 83 f8 01}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 09 8b 45 e0 83 c0 01 89 45 e0 81 7d e0 e8 03 00 00 7f ?? c7 45 d8 00 00 00 00 8d 4d d8 51 8d 4d e4 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 fe 30 c6 45 fc 78 c6 45 fd 41 c6 45 ff 61 0f be 45 fe 8b 4d 08 0f b6 11 3b c2 0f 85 ?? ?? ?? ?? 0f be 45 fc 8b 4d 08 0f b6 51 01 3b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_BG_2147708691_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.BG!bit"
        threat_id = "2147708691"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 1a ff 33 d7 88 54 18 ff 8d 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 43 4e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_IC_2147708699_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.IC"
        threat_id = "2147708699"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 08 2b 4d fc 8b 55 08 03 55 f8 88 0a}  //weight: 1, accuracy: High
        $x_1_2 = {6b c9 28 03 4d 0c 8d 94 01 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 e1 ff ff 00 00 81 f9 d0 07 00 00 7d 04 b0 01 eb 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_ID_2147708752_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.ID!bit"
        threat_id = "2147708752"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 5c 24 ?? 0f be 7c 24 ?? 31 fb 8b 7c 24 ?? 31 fb 33 5c 24 ?? 8b 7c 24 ?? 31 fb 89 d8 88 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_IE_2147708753_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.IE!bit"
        threat_id = "2147708753"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 03 c8 8a 09 88 0c 02 8d 48 01 33 4b 04 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 8d 48 01 33 0b 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 40 ?? ?? ?? ?? ?? ?? 75 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_IF_2147708964_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.IF"
        threat_id = "2147708964"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 0b b9 8e 00 00 00 58 ba 80 00 00 00 6a 04}  //weight: 1, accuracy: High
        $x_1_2 = {81 7d ec 13 7b 83 12 7f 41 8b 45 ec 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_IG_2147709603_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.IG"
        threat_id = "2147709603"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 33 f0 33 fa 89 75 f0 eb}  //weight: 1, accuracy: High
        $x_1_2 = {33 32 35 38 38 37 38 39 24 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_IH_2147709651_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.IH!bit"
        threat_id = "2147709651"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 68 00 10 00 00 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {88 10 8b 45 f8 83 c0 01 89 45 f8 8b 4d 08 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {03 45 f0 8b 4d f4 03 4d f8 8a 11 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {33 94 8d 00 fc ff ff e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 55 08 8b 82 c4 03 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_6 = {8b 45 08 8b 88 94 03 00 00 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_MRG_2147712010_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.MRG!bit"
        threat_id = "2147712010"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8a 08 32 4d ec 8b 55 08 88 0a 8b 45 08 8a 08 02 4d ec 8b 55 08 88 0a 8b 45 08 83 c0 01 89 45 08 b8 ?? ?? 40 00 c3 c7 45 fc 01 00 00 00 eb 99}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 4d f4 33 d2 66 8b 11 81 fa 4d 5a 00 00 74 07 33 c0 e9 ?? ?? 00 00 8b 45 f4 8b 48 3c 81 c1 f8 00 00 00 39 4d 0c 7d 07 33 c0 e9 ?? ?? 00 00 8b 55 f4 8b 45 f4 03 42 3c 89 45 f8 8b 4d f8 81 39 50 45 00 00 74 07}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 30 00 00 8b 45 1c 50 6a 00 8b 8d ?? ?? ff ff 51 ff 15 ?? ?? 40 00 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff 00 74 1a 8b 95 ?? ?? ff ff 52 8b 45 18 50 8b 4d 10 51 8b 8d ?? ?? ff ff e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_MRH_2147712300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.MRH!bit"
        threat_id = "2147712300"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ResetsEvnt" ascii //weight: 1
        $x_1_2 = "PowerShellThe StartElement" ascii //weight: 1
        $x_1_3 = {ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a}  //weight: 1, accuracy: High
        $x_1_4 = {b6 08 66 d1 eb 66 d1 d8 73 09 66 35 20 83 66 81 f3 b8 ed fe ce 75 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_IM_2147714800_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.IM"
        threat_id = "2147714800"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 0c 03 48 3c 6b 55 f0 28 8d 84 11 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 e8 0f be 14 10 03 ca 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 89 4d f8 eb}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 ec 03 45 f4 0f be 08 33 4d f0 8b 55 ec 03 55 f4 88 0a eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Injector_IV_2147717747_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.IV"
        threat_id = "2147717747"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e2 8d b4 24 ?? 00 00 00 89 72 04 89 0a 8b 0d ?? ?? ?? ?? 89 44 24 ?? ff d1}  //weight: 1, accuracy: Low
        $x_1_2 = {89 e6 89 4e 0c [0-6] c7 46 08 00 10 00 00 [0-8] c7 06 00 00 00 00 ff d0 83 ec 10 89 [0-4] 8b [0-4] 89 [0-4] 89 [0-4] 89 [0-4] e8 ?? 01 00 00 83 ec 08 8b [0-4] 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {89 e1 89 41 04 8d [0-6] 89 01 e8 ?? ?? ff ff 83 ec 08 89 [0-8] 89 e0 c7 00 4e 7d 40 00 e8 ?? ?? ff ff 83 ec 04 83 f8 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_GF_2147718798_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.GF!bit"
        threat_id = "2147718798"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7d 40 eb 04 8b ?? ?? ?? 8a 0c 38 8b ?? ?? ?? 99 f7 ?? ?? ?? 8b ?? ?? ?? 8a 04 02 f6 d0 8a d0 22 d1 f6 d0 f6 d1 22 c1 8b ?? ?? ?? 0a c2 8b ?? ?? ?? 88 04 39 8b ?? ?? ?? 42 47 3b f8 89 ?? ?? ?? 7c c2}  //weight: 2, accuracy: Low
        $x_2_2 = {85 c0 74 47 89 ?? ?? ?? 8b ?? ?? ?? 8b ?? ?? ?? 8a 0c 08 8b c7 99 f7 ?? ?? ?? 8b ?? ?? ?? 8a 04 02 f6 d0 8a d0 22 d1 f6 d0 f6 d1 22 c1 8b ?? ?? ?? 0a c2 8b ?? ?? ?? 47 88 04 0a 8b ?? ?? ?? 41 48 89 ?? ?? ?? 89 ?? ?? ?? 75 bd}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 42 50 51 8b 8c ?? ?? ?? 00 00 89 ?? ?? ?? 8b 42 34 51 89 84 ?? ?? ?? 00 00 8b 52 28}  //weight: 1, accuracy: Low
        $x_1_4 = {66 8b 51 06 0f ?? ?? ?? ?? 89 ?? ?? ?? 8b 49 54 8b ?? ?? ?? 51 8b ?? ?? ?? 52 8b ?? ?? ?? 51 52 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Injector_JG_2147718993_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.JG"
        threat_id = "2147718993"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 f4 75 73 65 72 66 c7 45 f8 33 32 c6 45 fa 00 ff 56 48}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 b8 4d 4d 58 65 c7 45 bc 6e 56 4d 4d}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 f4 73 62 69 65 c7 45 f8 64 6c 6c 2e c7 45 fc 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Injector_JK_2147719228_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.JK"
        threat_id = "2147719228"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nsstrawstdllsstraws::NtsstrawsClosstrawssesstraws(i sstrawsr0)sstraws" wide //weight: 1
        $x_1_2 = "kernetbreakdownl32::tbreakdownVitbreakdownrttbreakdownualAtbreakdownltbreakdownloc(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Injector_JR_2147720156_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.JR"
        threat_id = "2147720156"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 73 15 00 00 68 84 05 00 00 e8 ?? ?? ?? ?? 83 c4 08 [0-6] 81}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 50 75 ?? 8b c0 8d 15 ?? ?? ?? ?? 89 55 f8 81 6d f8 05 14 00 00 81 45 f8 8a 10 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {50 8b ff 8b c9 8b ff c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_KP_2147732288_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.KP"
        threat_id = "2147732288"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 32 0d ?? ?? ?? ?? 88 08 87 f6 89 f6 89 f6 ff 06 81 3e ?? ?? ?? ?? 75 ae}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c9 89 ff ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {ff 06 81 3e ?? ?? ?? ?? 75 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CQ_2147733008_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.CQ!bit"
        threat_id = "2147733008"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 68 00 60 00 00 68 80 68 41 00 ff 15 ?? ?? ?? 00 51 53 8d 05 ?? ?? ?? 00 33 c9 8a 1c 08 80 f3 bb f6 d3 80 f3 84 88 1c 08 41 81 f9 51 5f 00 00 75 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_CP_2147733086_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.CP!bit"
        threat_id = "2147733086"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 03 85 ?? ?? ff ff 8b cf c1 e1 04 03 8d ?? ?? ff ff 33 c1 8b 8d ?? ?? ff ff 03 cf 33 c1 2b f0 8b c6 c1 e8 05 03 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ce c1 e1 04 03 8d ?? ?? ff ff 33 c1 8b 8d ?? ?? ff ff 81 85 ?? ?? ff ff 47 86 c8 61 03 ce 33 c1 2b f8 ff 85 ?? ?? ff ff 83 bd ?? ?? ff ff 20 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_KP_2147733103_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.KP!bit"
        threat_id = "2147733103"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 9c 24 25 02 00 00 c6 84 24 28 02 00 00 5c c6 84 24 29 02 00 00 76 c6 84 24 2a 02 00 00 62 c6 84 24 2b 02 00 00 63 c6 84 24 2c 02 00 00 2e c6 84 24 2d 02 00 00 65 c6 84 24 2e 02 00 00 78 c6 84 24 2f 02 00 00 65}  //weight: 1, accuracy: High
        $x_1_2 = {88 54 24 23 c6 44 24 25 76 c6 44 24 26 63 c6 44 24 27 68 c6 44 24 28 6f c6 44 24 2a 74 c6 44 24 2b 2e}  //weight: 1, accuracy: High
        $x_1_3 = {88 9c 24 1e 02 00 00 c6 84 24 1f 02 00 00 61 c6 84 24 20 02 00 00 64 c6 84 24 21 02 00 00 43 c6 84 24 22 02 00 00 6f c6 84 24 23 02 00 00 6e c6 84 24 24 02 00 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_KQ_2147734586_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.KQ!bit"
        threat_id = "2147734586"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "( $FILE , $REGKEY , $ATTRIB , $HIDDEN )" wide //weight: 1
        $x_1_2 = "( $URL , $FILENAME , $DIR )" wide //weight: 1
        $x_1_3 = "( $RESNAME , $RESTYPE )" wide //weight: 1
        $x_1_4 = "( $VDATA , $VCRYPTKEY )" wide //weight: 1
        $x_1_5 = " , $FILENAME , $RUN , $RUNONCE , $DIR )" wide //weight: 1
        $x_1_6 = "( $PROTECT )" wide //weight: 1
        $x_1_7 = "( $WPATH , $WARGUMENTS , $LPFILE , $PROTECT )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_KR_2147734613_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.KR!bit"
        threat_id = "2147734613"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 89 45 fc ff 75 fc 81 04 24 1c 0d 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 6a 40 68 e2 59 00 00 57 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f7 03 f2 [0-32] 8a 08 [0-32] 80 f1 79 [0-32] 88 0e [0-32] 42}  //weight: 1, accuracy: Low
        $x_1_4 = {81 3c 24 e3 59 00 00 75 [0-32] 8b c7 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Injector_KL_2147750266_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.KL!MTB"
        threat_id = "2147750266"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 03 45 f0 73 ?? e8 ?? ?? ?? ?? 8a 00 88 45 f7 8b 45 f0 89 45 f8 ?? ?? 80 75 f7 ?? ?? ?? 8b 45 fc 03 45 f8 73 ?? e8 ?? ?? ?? ?? 8a 55 f7 88 10 ?? ff 45 f0 81 7d f0 ?? ?? ?? ?? 75 ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_SBR_2147753986_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.SBR!MSR"
        threat_id = "2147753986"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exec bypass" ascii //weight: 1
        $x_1_2 = "gitee.com" ascii //weight: 1
        $x_1_3 = "APPLICATION DATA\\SECURITY.DLL" wide //weight: 1
        $x_1_4 = "acquire credentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Injector_FGT_2147807572_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injector.FGT!MTB"
        threat_id = "2147807572"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d0 59 b4 38 4d 87 31 5f 9c f1 0a c5 6b c9 72 38 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

