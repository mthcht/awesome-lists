rule VirTool_Win32_CeeInject_C_2147598387_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!C"
        threat_id = "2147598387"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 81 c9 00 ff ff ff 41 8a 4c 0c 14 32 0c 2f 88 0f 8b 8c 24 20 01 00 00 40 3b c1 7c 9e 8b 44 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 0c 50 6a 09 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 50 ff d7 50 ff d5 8b 4c 24 2c 8b 54 24 28 51 8b 4c 24 24 52 51 53 56 6a 02 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_D_2147602876_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!D"
        threat_id = "2147602876"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 00 00 00 72 62 00 00 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00 00 00 00 6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = {00 8c 04 40 01 00 00 00 94 04 41 01 00 00 83 c0 02 83 f8 40 72 ea 56 57 b9 10 00 00 00 8d b4 24 48 01 00 00 8d 7c 24 28 f3 a5 66 81 7c 24 28 4d 5a}  //weight: 1, accuracy: High
        $x_1_3 = "Expl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_B_2147604698_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!B"
        threat_id = "2147604698"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FindResourceA" ascii //weight: 1
        $x_1_2 = "LoadResource" ascii //weight: 1
        $x_1_3 = "CreateProcessA" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = {ff 74 24 0c 8d 56 fc e8 ?? ?? ?? ?? 8b 46 f4 31 02 8b 46 f8 31 06 83 ee 08 4b 59 75 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_H_2147608423_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!H"
        threat_id = "2147608423"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 40 00 00 00 b8 00 30 00 00 89 4c 24 10 89 44 24 0c 8b 55 ?? 89 54 24 08 8b 5e 34 89 5c 24 04 8b 8d ?? ?? ff ff 89 0c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {29 d0 0f b6 84 28 ?? ?? ff ff 32 04 0b 88 04 33 43 39 5d 10 0f 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_J_2147611223_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!J"
        threat_id = "2147611223"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "109"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateProcessA" ascii //weight: 1
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
        $x_1_3 = "LoadResource" ascii //weight: 1
        $x_1_4 = "FindResourceA" ascii //weight: 1
        $x_1_5 = "SizeofResource" ascii //weight: 1
        $x_1_6 = "GetThreadContext" ascii //weight: 1
        $x_1_7 = "SetThreadContext" ascii //weight: 1
        $x_1_8 = "ResumeThread" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_10_10 = {6d 5f 53 74 75 62 00}  //weight: 10, accuracy: High
        $x_10_11 = {8a 10 32 91 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 88 10 eb}  //weight: 10, accuracy: Low
        $x_10_12 = {81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8a 5c 9c 14 30 1c 2a 42 3b d0 72}  //weight: 10, accuracy: High
        $x_10_13 = {8b 45 08 03 85 ?? ?? ff ff 8a 10 32 94 8d ?? ?? ff ff 8b 45 08 03 85 ?? ?? ff ff 88 10 e9}  //weight: 10, accuracy: Low
        $x_10_14 = {8a 04 1f 8a 54 94 ?? 32 c2 88 04 1f 8b 84 24 ?? ?? 00 00 47 3b f8 72}  //weight: 10, accuracy: Low
        $x_10_15 = {99 f7 f9 8a 84 95 ?? ?? ff ff 30 07 ff 45 ?? 8b 45 ?? 3b 45 ?? 72}  //weight: 10, accuracy: Low
        $x_10_16 = {66 b9 ff ff eb 06 66 b8 00 4c cd 21 e2 f6}  //weight: 10, accuracy: High
        $x_10_17 = {8a 14 31 8a 0c 07 32 ca 88 0c 07 ff d5 50 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 44 24 20 47 3b f8 0f 8c 2f ff ff ff}  //weight: 10, accuracy: Low
        $x_100_18 = {6a 04 68 00 30 00 00 ff 73 50 ff 73 34 ff 75 e4 ff 15}  //weight: 100, accuracy: High
        $x_100_19 = {6a 40 68 00 30 00 00 8b 48 50 8b 50 34 8b 44 24 ?? 51 52 50 ff}  //weight: 100, accuracy: Low
        $x_100_20 = {6a 40 68 00 30 00 00 (8b 0d|a1) ?? ?? ?? ?? 8b (51|48) 50 (52|51) (a1|8b 15) ?? ?? ?? ?? 8b (48|42) 34 (51|50) 8b (95|8d) ?? ?? ff ff (52|51) ff}  //weight: 100, accuracy: Low
        $x_100_21 = {8b 48 50 51 8b 15 ?? ?? ?? ?? 8b 42 34 50 8b 4d ?? 51 ff 15}  //weight: 100, accuracy: Low
        $x_100_22 = {6a 40 68 00 30 00 00 8b 50 50 8b 40 34 52 50 51 ff}  //weight: 100, accuracy: High
        $x_100_23 = {6a 40 68 00 30 00 00 a1 ?? ?? ?? ?? 8b 4c 24 ?? 8b 50 50 8b 40 34 52 50 51 ff}  //weight: 100, accuracy: Low
        $x_100_24 = {6a 40 68 00 30 00 00 8b 0d ?? ?? ?? ?? 8b 51 50 52 a1 ?? ?? ?? ?? 8b 48 34 51 8b 55 ?? 52 ff}  //weight: 100, accuracy: Low
        $x_100_25 = {8b 50 50 8b 40 34 8b 4c 24 ?? 6a 40 68 00 30 00 00 52 50 51 ff}  //weight: 100, accuracy: Low
        $x_100_26 = {6a 40 c1 e9 1f 03 d1 8b 4c 24 ?? 89 15 ?? ?? ?? ?? 8b 50 50 8b 40 34 68 00 30 00 00 52 50 51 ff 15}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 9 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_L_2147618901_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!L"
        threat_id = "2147618901"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lulhelloworldcppftw" ascii //weight: 1
        $x_1_2 = "lalala....$$$$$$" ascii //weight: 1
        $x_1_3 = "mvua2n43ga1313131" ascii //weight: 1
        $x_1_4 = "muvan2h4gnnj2vnvnjav2nja4vnja4v" ascii //weight: 1
        $x_1_5 = "laulgulhuah1231" ascii //weight: 1
        $x_1_6 = "lulzbar" ascii //weight: 1
        $x_1_7 = "njvjnarjgahjnrvajrvn2jone" ascii //weight: 1
        $x_20_8 = {64 62 67 68 65 6c 70 2e 64 6c 6c 00 53 62 69 65 44 6c 6c 2e 64 6c 6c}  //weight: 20, accuracy: High
        $x_20_9 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed 89 5d e4 5b 83 4d fc ff eb 14}  //weight: 20, accuracy: High
        $x_20_10 = {b8 01 00 00 00 0f 3f 07 0b c7 45 fc ff ff ff ff 83 4d fc ff eb 14}  //weight: 20, accuracy: High
        $x_20_11 = {8b 95 f0 fe ff ff 03 d0 03 ca 8b c1 99 b9 00 01 00 00 f7 f9 89 95 f0 fe ff ff}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_N_2147622885_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!N"
        threat_id = "2147622885"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 88 ?? ?? ?? ?? 30 0c 37 40 83 f8 ?? 72 f1 8a 04 37 56 f6 d0 88 04 37 47 e8 ?? ?? ?? ?? 3b f8 59 72 db}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 40 06 85 c0 7e ?? 8b 55 ?? 53 57 8b d8 8d 7a 08 8b 37 85 f6 74 ?? 8b c6 33 d2 f7 75 ?? 85 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_O_2147622887_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!O"
        threat_id = "2147622887"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 f8 00 00 00 00 eb 09 8b 55 f8 83 c2 01 89 55 f8 83 7d f8 06 73 1b 8b 45 f4 03 45 fc 8b 4d f8 8a 10 32 91 ?? ?? ?? ?? 8b 45 f4 03 45 fc 88 10 eb d6}  //weight: 5, accuracy: Low
        $x_5_2 = {50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8b 4d 08 51 6a 00 ff 15 ?? ?? 40 00 8b 15 ?? ?? 40 00 8b 42 34 50 8b 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? 6a 40 68 00 30 00 00}  //weight: 5, accuracy: Low
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "SetThreadContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_P_2147622935_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!P"
        threat_id = "2147622935"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 6d 77 61 72 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 61 6e 64 62 6f 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_2_4 = {83 7d f8 07 73 1b 8b 45 f4 03 45 fc 8b 4d f8 8a 00 32 81 ?? ?? 40 00 8b 4d f4 03 4d fc 88 01 eb d8}  //weight: 2, accuracy: Low
        $x_2_5 = {6a 40 68 00 30 00 00 a1 ?? ?? 40 00 ff 70 50 a1 ?? ?? 40 00 ff 70 34 ff 75 f0 ff 15}  //weight: 2, accuracy: Low
        $x_2_6 = {0f b7 49 06 49 6b c9 28 03 0d ?? ?? 40 00 8d 84 01 f8 00 00 00 a3 ?? ?? 40 00 6a 32}  //weight: 2, accuracy: Low
        $x_2_7 = {99 b9 00 01 00 00 f7 f9 8b 45 08 03 85 ?? ?? ff ff 8a 00 32 84 ?? ?? fb ff ff 8b 4d 08 03 8d ?? ?? ff ff 88 01 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_Q_2147624244_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!Q"
        threat_id = "2147624244"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d e4 68 58 4d 56 0f 94 c0 eb}  //weight: 1, accuracy: High
        $x_1_2 = {0f 68 48 43}  //weight: 1, accuracy: High
        $x_2_3 = {8a 84 95 f8 fb ff ff 30 06 ff 45 14 8b 45 14 3b 45 10 72}  //weight: 2, accuracy: High
        $x_3_4 = {75 06 8b 85 d4 fe ff ff 8b 8d c8 fe ff ff 03 c8}  //weight: 3, accuracy: High
        $x_3_5 = {ff 70 50 ff 70 34 ff 75 ?? ff 15}  //weight: 3, accuracy: Low
        $x_1_6 = {81 38 50 45 00 00 0f 85}  //weight: 1, accuracy: High
        $x_2_7 = {99 f7 f9 8b 4d ?? 8a 84 15 ?? ?? ff ff 32 04 31 47 3b 7d ?? 88 06 7c}  //weight: 2, accuracy: Low
        $x_2_8 = {83 45 08 28 0f b7 41 06 39 45 ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_R_2147624458_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!R"
        threat_id = "2147624458"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 56 28 03 56 34 8b 4c 24 14 8d 44 24 68 50 51 89 94 24 20 01 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b d1 83 e2 0f 8a 14 3a 30 14 29 83 c1 01 3b c8 72 ee}  //weight: 1, accuracy: High
        $x_1_3 = {8a c2 b4 3e 66 f7 f1}  //weight: 1, accuracy: High
        $x_1_4 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 62 6c 61 0a 64 65 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_S_2147624569_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!S"
        threat_id = "2147624569"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 06 8b 85 ?? fe ff ff 8b 8d ?? fe ff ff 03 c8}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_2_3 = {8a 84 95 f8 fb ff ff 30 06 ff 45 14 8b 45 14 3b 45 10 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_T_2147624794_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!T"
        threat_id = "2147624794"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 53 28 8b 7b 34 03 d7 89 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {02 c2 8a 14 31 32 d0 88 14 31}  //weight: 1, accuracy: High
        $x_1_3 = {8b 03 6a 00 81 c2 00 01 00 00 6a 00 52 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_U_2147624832_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!U"
        threat_id = "2147624832"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 61 6e 64 62 6f 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {76 6d 77 61 72 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_3_4 = {89 45 f0 89 45 ec 8d 45 f4 50 68 40 40 40 00 68 01 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 3, accuracy: Low
        $x_2_5 = {50 58 35 aa aa aa aa 35 aa aa aa aa}  //weight: 2, accuracy: High
        $x_2_6 = {50 58 83 f0 ff 83 f0 ff}  //weight: 2, accuracy: High
        $x_2_7 = {99 b9 0f 27 00 00 f7 f9 (8b|89)}  //weight: 2, accuracy: Low
        $x_1_8 = {66 81 38 4d 5a 0f 85 ?? ?? 00 00 8b 40 3c 03 c7 a3 ?? ?? ?? ?? 81 38 50 45 00 00 0f 85 ?? ?? 00 00 8d 45 f0 33 f6 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_B_2147625506_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.B"
        threat_id = "2147625506"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 3f 4d 5a c7 44 24 20 44 00 00 00 c7 44 24 68 07 00 01 00 0f 85 ?? ?? 00 00 8b 77 3c 03 f7 81 3e 50 45 00 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 51 01 8a 59 ff 8a 01 88 54 24 0a 0f b6 51 02 88 54 24 0b 8b d6 81 e2 03 00 00 80 79 05 4a 83 ca fc 42 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_W_2147625719_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!W"
        threat_id = "2147625719"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3b 45 e4 75 0e 8b 47 10 03 47 1c 89 85 c8 fd ff ff eb 0b}  //weight: 2, accuracy: High
        $x_1_2 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_3 = {68 58 4d 56 0f 94 c0}  //weight: 1, accuracy: High
        $x_2_4 = {8a 84 95 b4 fb ff ff 30 03 ff 45 14 8b 45 14 3b 45 10 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_X_2147626139_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!X"
        threat_id = "2147626139"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 8b f7 68 00 10 00 00 03 77 3c 89 74 24 18 ff 76 50 55 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 89 5c 24 58 68 00 10 00 00 f3 ab ff 76 50 53 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 04 01 03 c7 f7 f3 8b 5d 08 0f b6 04 1e 2b c2 79 05 05 00 01 00 00 88 04 1e}  //weight: 1, accuracy: High
        $x_1_5 = {bb e8 03 00 00 89 4d f4 0f b6 04 02 03 45 10 33 d2 f7 f3 0f b6 19 2b da 79 06 81 c3 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {01 44 24 24 ff 44 24 14 0f b7 46 06 83 44 24 1c 28 39 44 24 14 0f 8c}  //weight: 1, accuracy: High
        $x_1_7 = {42 55 54 54 4f 4e 00 [0-4] 49 63 6f 6e 2e 69 63 6f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_Y_2147626178_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!Y"
        threat_id = "2147626178"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 0c ff 45 f8 83 c6 28 39 5d f8 7c c7}  //weight: 1, accuracy: High
        $x_1_2 = {bb e8 03 00 00 0f b6 04 01 03 c7 f7 f3 8b 5d 08 0f b6 04 1e 2b c2 79 05 05 00 01 00 00 88 04 1e 41 46 83 c7 09 3b 75 10 72 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_Z_2147626179_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!Z"
        threat_id = "2147626179"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 bd 70 fb ff ff 00 00 01 00 75 02 eb 14 8b ?? 38 fc ff ff 03 ?? 6c fb ff ff 89 ?? 38 fc ff ff eb bd}  //weight: 1, accuracy: Low
        $x_1_2 = {be e8 03 00 00 f7 f6 2b ca 89 4d fc 83 7d ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_E_2147626491_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.E"
        threat_id = "2147626491"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sbiedll.dll" ascii //weight: 1
        $x_1_2 = "api_log.dll" ascii //weight: 1
        $x_1_3 = {e9 00 00 00 00 6a 0e 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 a3 ?? ?? ?? ?? 59 c3 e9 00 00 00 00 6a ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 a3 ?? ?? ?? ?? 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AA_2147626743_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AA"
        threat_id = "2147626743"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 6d 77 61 72 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 61 6e 64 62 6f 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_3_4 = {6a 40 68 00 30 00 00 [0-5] ff ?? 50 ff ?? 34 ff [0-3] ff (15|d0)}  //weight: 3, accuracy: Low
        $x_3_5 = {8b 4e 50 8b 56 34 6a 40 68 00 30 00 00}  //weight: 3, accuracy: High
        $x_1_6 = {83 45 0c 28 43 0f b7 41 06 3b d8 7c}  //weight: 1, accuracy: High
        $x_1_7 = {66 8b 4e 06 40 83 c7 28 3b c1}  //weight: 1, accuracy: High
        $x_1_8 = {ff 44 24 14 83 44 24 10 28 0f b7 48 06 39 4c 24 14 7c}  //weight: 1, accuracy: High
        $x_1_9 = {ff 44 24 1c 0f b7 46 06 83 44 24 ?? 28 39 44 24 1c 0f 8c}  //weight: 1, accuracy: Low
        $x_1_10 = {0f b7 46 06 ff 45 ?? 83 c7 28 39 45 ?? 72}  //weight: 1, accuracy: Low
        $x_1_11 = {6a 0a 5e 8b ce 90 90 90 50 58 35 ?? ?? ?? ?? 35 ?? ?? ?? ?? 90 90 49 75 ec}  //weight: 1, accuracy: Low
        $x_1_12 = {4d 5a 0f 85 ?? ?? ?? ?? 8b ?? 3c 03 ?? a3 ?? ?? ?? ?? 81 38 50 45 00 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_13 = {81 e2 ff 00 00 00 03 c2 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 44 04 ?? 8a 1c 2f 32 c3 41 88 07}  //weight: 1, accuracy: Low
        $x_1_14 = {0f b6 04 01 03 44 24 ?? b9 e8 03 00 00 f7 f1 8b 44 24 ?? 0f b6 00 2b c2 81 7c 24}  //weight: 1, accuracy: Low
        $x_1_15 = {8a 19 88 18 88 11 8a 00 8b 4d 10 03 c2 23 c6 8a 84 05 ?? ?? ff ff 32 04 39 88 07 47 ff 4d 0c 75}  //weight: 1, accuracy: Low
        $x_1_16 = {50 58 35 aa aa aa aa 35 aa aa aa aa}  //weight: 1, accuracy: High
        $x_1_17 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AB_2147626786_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AB"
        threat_id = "2147626786"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 24 8b 4c 24 14 8b 54 24 10 03 c8 8b 44 24 28 bb e8 03 00 00 89 4c 24 1c 0f b6 04 02 03 44 24 18 33 d2 f7 f3 0f b6 19}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4e 54 8b 76 38 8b c1 33 d2 f7 f6 83 c4 18 8b c1 85 d2 74 08 33 d2 f7 f6 40 0f af c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AC_2147626906_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AC"
        threat_id = "2147626906"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 32 db ff 15 ?? ?? ?? ?? 8b 48 3c [0-8] 8d ?? ?? 04 [0-8] 8d [0-2] 14 [0-8] 02 [0-4] 89 [0-16] e8 [0-8] 8b 51 ec [0-8] 03 f2 ff 15 [0-16] 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 ?? ff 15 [0-48] 8b 7c 24 10 3b fe 76 3c}  //weight: 1, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "GetUserNameA" ascii //weight: 1
        $x_1_6 = "sandbox" ascii //weight: 1
        $x_1_7 = "vmware" ascii //weight: 1
        $x_1_8 = "GetModuleHandleA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AD_2147627161_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AD"
        threat_id = "2147627161"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 28 03 48 34 eb 09 8b 4c 24 ?? 8b 49 28 03 c8}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f3 0f b6 19 2b da 79 06 81 c3 00 01 00 00 8b 44 24}  //weight: 1, accuracy: High
        $x_1_3 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AE_2147627193_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AE"
        threat_id = "2147627193"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 46 28 75 05 03 46 34 eb 03 03 45 fc 89 85}  //weight: 1, accuracy: High
        $x_1_2 = {f7 f1 8b 4d 08 0f b6 04 0b 2b c2 79 0f ba ff 00 00 00 2b d0 c1 ea 08}  //weight: 1, accuracy: High
        $x_1_3 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AF_2147627330_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AF"
        threat_id = "2147627330"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 1a 8b 8d ?? ?? ff ff 8b 51 34 8b 85 ?? ?? ff ff 03 50 28 89 95 ?? ?? ff ff eb 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 46 28 75 05 03 46 34 eb 03 03 45 fc 89 85}  //weight: 1, accuracy: High
        $x_1_3 = {be e8 03 00 00 f7 f6 2b ca 89 4d fc 83 7d fc 00 7d 0d 8b 45 fc 05 00 01 00 00 89 45 fc eb ed}  //weight: 1, accuracy: High
        $x_1_4 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_AG_2147627516_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AG"
        threat_id = "2147627516"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 8b 4e 50 8b 56 34 68 00 30 00 00 51 52 50 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_3 = {8a 04 0e b9 e8 03 00 00 03 c2 33 d2 f7 f1 8a 1c 2f 2b da 81 fe}  //weight: 1, accuracy: High
        $x_1_4 = {83 c2 28 03 c8 8b 44 24 ?? 89 54 24 ?? 33 d2 40 66 8b 57 06 89 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AH_2147627605_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AH"
        threat_id = "2147627605"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 04 68 00 20 00 00 8b 45 f0 8b 48 50 51 8b 55 f0 8b 42 34 50 ff 15}  //weight: 3, accuracy: High
        $x_2_2 = {83 c0 01 89 45 ?? 8b 4d ?? 83 c1 28 89 4d ?? 8b 55 ?? 8b 02 33 c9 66 8b 48 06 39 4d}  //weight: 2, accuracy: Low
        $x_2_3 = {49 4e 4a 45 43 54 5f 44 4c 4c 00}  //weight: 2, accuracy: High
        $x_1_4 = {4d 41 49 4e 5f 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_5 = {4d 41 49 4e 5f 4b 45 59 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AI_2147627728_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AI"
        threat_id = "2147627728"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 84 24 94 00 00 00 07 00 01 00 75 16 c6 05 d7 68 40 00 00 8b 4d 28 03 4d 34 89 8c 24 44 01 00 00 eb 0c 8b 55 28 03 d0}  //weight: 1, accuracy: High
        $x_1_2 = {b9 e8 03 00 00 03 c2 33 d2 f7 f1 33 c0 8a 04 1f 2b c2}  //weight: 1, accuracy: High
        $x_1_3 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AJ_2147627754_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AJ"
        threat_id = "2147627754"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b d2 09 03 c2 33 d2 be e8 03 00 00 f7 f6 2b ca}  //weight: 1, accuracy: High
        $x_1_2 = {8b 51 34 8b 85 ?? ?? ff ff 03 50 28 89 95 ?? ?? ff ff eb}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_4 = {81 bd 50 fc ff ff 81 57 03 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_AK_2147627898_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AK"
        threat_id = "2147627898"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4f 28 03 4f 34 39 05 ?? ?? ?? ?? 89 8d ?? ?? ff ff 74 22 a3 ?? ?? ?? ?? eb 1b 8b 4f 28 03 c8}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_3 = {b9 e8 03 00 00 f7 f1 8b 4c 24 14 0f b6 04 0e 2b c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AL_2147627902_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AL"
        threat_id = "2147627902"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_2 = {46 81 fe 81 57 03 00 7c}  //weight: 1, accuracy: High
        $x_1_3 = {b9 e8 03 00 00 03 c2 33 d2 f7 f1 8a 1c 2e 2b da}  //weight: 1, accuracy: High
        $x_1_4 = {8b 55 28 8b 45 34 03 d0 89 94 24 ?? ?? 00 00 eb ?? 8b 55 28 03 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_AM_2147628066_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AM"
        threat_id = "2147628066"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 78 76 63 6a 76 68 64 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 61 67 77 6d 70 00 00 6e 6a 77 6f 69 75 69 00 6c 77 72 77 6c 6a 6b 6d 6a 00}  //weight: 1, accuracy: High
        $x_10_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 00 53 62 69 65 44 6c 6c 2e 64 6c 6c}  //weight: 10, accuracy: High
        $x_10_4 = {8d 84 9d fc fb ff ff 89 0f 0f b6 ca 83 c7 04 39 75 fc 89 08 7c bc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AN_2147628096_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AN"
        threat_id = "2147628096"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff 74 24 34 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 47 06 ff 44 24 ?? 83 44 24 20 28 39 44 24 ?? 7d}  //weight: 1, accuracy: Low
        $x_1_4 = {b9 e8 03 00 00 0f b6 04 07 03 45 ?? f7 f1 8b 45 ?? 0f b6 1c 06 33 c0 2b da 39 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AO_2147628305_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AO"
        threat_id = "2147628305"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {e9 00 00 00 00 6a 0e 68 ?? ?? 40 00 e8 ?? ?? ?? ?? 59 a3 ?? ?? 40 00 59 c3 e9 00 00 00 00 6a 14 68 ?? ?? 40 00 e8 ?? ?? ?? ?? 59 a3 ?? ?? 40 00 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AP_2147628916_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AP"
        threat_id = "2147628916"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 48 85 c0 75 f9 0f 31}  //weight: 1, accuracy: High
        $x_1_2 = {8d 04 95 04 00 00 00 39 85 ?? ?? ?? ?? 73 2d 8b 8d ?? ?? ?? ?? 8b 54 0d 0c 89 55 fc 8b 45 fc 33 45 08 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {81 39 50 45 00 00 74 07 33 c0 e9}  //weight: 1, accuracy: High
        $x_1_4 = {8d 94 01 f8 00 00 00 89 95}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AR_2147629370_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AR"
        threat_id = "2147629370"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 34 8b 95 ?? ?? ff ff 03 4a 28 89 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {73 2d 8b 8d ?? ?? ff ff 8b 54 0d 0c 89 55 fc 8b 45 fc 33 45 08 89 45 fc 6a 04}  //weight: 1, accuracy: Low
        $x_1_3 = {66 8b 51 06 39 95 ?? ?? ff ff 0f 83 ?? ?? 00 00 8b 85 ?? ?? ff ff 8b 48 3c 8b 95 ?? ?? ff ff 6b d2 28 03 55 08}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c1 01 89 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 0f b7 42 06 39 85 ?? ?? ff ff 7d 51 8b 8d ?? ?? ff ff 8b 51 3c 8b 85 ?? ?? ff ff 6b c0 28 03 45}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 40 68 00 30 00 00 8b 95 ?? ?? ff ff 8b 42 50 50 8b 8d ?? ?? ff ff 8b 51 34 52 8b 85 ?? ?? ff ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_AS_2147629371_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AS"
        threat_id = "2147629371"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f1 40 0f af c1 01 44 24 ?? ff 44 24 ?? 0f b7 ?? 06 83 44 24 ?? 28 39 44 24 ?? 0f 8c}  //weight: 2, accuracy: Low
        $x_1_2 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_3 = {bb e8 03 00 00 0f b6 04 06 03 45 f8}  //weight: 1, accuracy: High
        $x_1_4 = {83 45 f8 09 46 ff 45 fc 88 18 8b 45 fc 3b 45 10 0f 82}  //weight: 1, accuracy: High
        $x_1_5 = {54 68 65 20 57 69 72 65 73 68 61 72 6b 20 4e 65 74 77 6f 72 6b 20 41 6e 61 6c 79 7a 65 72 00}  //weight: 1, accuracy: High
        $x_2_6 = {6a 40 68 00 30 00 00 [0-10] ff ?? 50 ff ?? 34 ff 74 24 ?? ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AT_2147629546_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AT"
        threat_id = "2147629546"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 8b 56 50 52 8b 46 34 50}  //weight: 1, accuracy: High
        $x_1_2 = {81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8b 54 8c ?? 8a 04 37 32 d0 8b 44 24 ?? 88 16 46 48 89 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AU_2147629722_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AU"
        threat_id = "2147629722"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4f 3c 03 cd 8b 94 39 08 01 00 00 8d 84 39 f8 00 00 00 8b 48 14 6a 00 52 8b 50 0c 03 56 34 8b 44 24 ?? 03 cf 51 52 50 ff 15 ?? ?? ?? ?? 0f b7 4e 06 43 83 c5 28 3b d9 7c c6}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 0a 6a 03 6a 00 ff ?? 8b f0 85 f6 74 33 56 6a 00 ff d5 56 6a 00 8b f8 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AV_2147629878_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AV"
        threat_id = "2147629878"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 28 8b 56 34 03 c2}  //weight: 1, accuracy: High
        $x_1_2 = {66 8b 4e 06 40 83 c7 28 3b c1 89 44 24 ?? 72 bc eb 08}  //weight: 1, accuracy: Low
        $x_1_3 = {32 c1 8a 4c 24 ?? 32 c1 8b 4c 24 ?? 88 04 11 42 3b d6 72 ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AW_2147629935_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AW"
        threat_id = "2147629935"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 08 8b c6 32 d3 83 e0 ?? b9 08 00 00 00 8a da 2b c8 d2 e3 8a c8 d2 ea 0a da 88 1c 3e 46 3b f5 72 d1}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 48 34 03 48 28 8d 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {83 45 0c 28 43 0f b7 41 06 3b d8 7c bc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_J_2147630009_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.J"
        threat_id = "2147630009"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 64 a1 30 00 00 00 0f b6 40 02 0b c0 74 02 c9 c3 58 0f 31 83 c2 01 89 55 f0 0f 31 39 55 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AY_2147630212_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AY"
        threat_id = "2147630212"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f8 01 8a 04 0a 75 05 02 04 1f eb 03 2a 04 1f 88 01 41 4e 75}  //weight: 2, accuracy: High
        $x_2_2 = {8b 42 3c 03 c3 8d 84 30 f8 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {8a 14 08 8b c6 32 d3 83 e0 07 b9 08 00 00 00 8a da 2b c8 d2 e3 8a c8 d2 ea 0a da 88 1c 3e 46 3b f5 72}  //weight: 2, accuracy: High
        $x_1_4 = "SbieDll.dll" ascii //weight: 1
        $x_1_5 = "SyntheticUser.FGVS" ascii //weight: 1
        $x_1_6 = "SANDBOX" ascii //weight: 1
        $x_1_7 = "Exit Silently" ascii //weight: 1
        $x_1_8 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_1_9 = "NtResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AZ_2147630657_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!AZ"
        threat_id = "2147630657"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 00 01 00 75 0e 8b 43 10 03 43 1c 89 85}  //weight: 1, accuracy: High
        $x_1_2 = {75 04 c6 45 ff 01 8a 45 ff 32 c1 fe 45 ff 88 02 42 4f 75 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BB_2147631196_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!BB"
        threat_id = "2147631196"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ff ff 8b 48 50 51 8b 95 ?? ?? ff ff 8b 42 34 50 8b 8d ?? ?? ff ff 51 ff 15}  //weight: 3, accuracy: Low
        $x_2_2 = {0f b7 48 06 39 8d ?? ?? ff ff 7d 51 8b 95 ?? ?? ff ff 8b 42 3c 8b 8d ?? ?? ff ff 6b c9 28}  //weight: 2, accuracy: Low
        $x_2_3 = {81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8b 45 08 03 85 ?? ?? ff ff 0f b6 10 33 94 8d ?? ?? ff ff 8b 45 08 03 85 ?? ?? ff ff 88 10 e9}  //weight: 2, accuracy: Low
        $x_1_4 = {ff ff 07 00 01 00 8b 45 0c 89 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_BC_2147631251_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!BC"
        threat_id = "2147631251"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_2_2 = {8b 47 50 8b 4f 34 8b 95 ?? ?? ff ff 6a 04 68 00 30 00 00 50 51 52 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {0f b7 57 06 43 83 c6 28 3b da}  //weight: 1, accuracy: High
        $x_1_4 = {8b 47 28 03 85 ?? ?? ff ff 8b 95 ?? ?? ff ff 8d 8d ?? ?? ff ff 51 52 89 85 ?? ?? ff ff ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 7c 24 10 e8 ?? ?? ?? ?? 30 04 3e 46 3b f3 72 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_BD_2147631440_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!BD"
        threat_id = "2147631440"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 10 8d 54 24 ?? 88 44 24 ?? 52 8d 44 24 ?? 50 c6 44 24 ?? 30 c6 44 24 ?? 78 88 4c 24 ?? c6 44 24 ?? 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_3 = {00 64 62 67 68 65 6c 70 2e 64 6c 6c 00 53 62 69 65 44 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 25 73 25 73 25 73 25 73 5b 25 73 5d 7b 7d 25 73 7b 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_BF_2147631985_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!BF"
        threat_id = "2147631985"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 28 43 66 8b 41 02 3b d8 7e c6 8b 44 24 ?? 68 ?? ?? ?? ?? 8b 48 10 03 cf}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 7d 00 4d 5a 0f 85 ?? ?? ?? ?? 8b 75 3c 03 f5 81 3e 50 45 00 00 74 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BG_2147632046_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!BG"
        threat_id = "2147632046"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 28 45 66 8b 4a 02 3b e9 7e c6 8b 4c 24 ?? 68 ?? ?? ?? ?? 8b 51 10 03 d7}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 3b 4d 5a 0f 85 ?? ?? ?? ?? 8b 73 3c 03 f3 81 3e 50 45 00 00 74 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BH_2147632159_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!BH"
        threat_id = "2147632159"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 58 4d 56 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_2 = {00 64 62 67 68 65 6c 70 2e 64 6c 6c 00 53 62 69 65 44 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_3 = {6a 40 68 00 30 00 00 8b 45 ?? ff 70 50 8b 45 00 ff 70 34 ff 75 ?? ff 15}  //weight: 2, accuracy: Low
        $x_1_4 = {0f b7 40 06 39 85 ?? ?? ?? ?? 7d 58 [0-64] 8b 45 ?? 8b 40 3c 8b 8d 00 6b c9 28}  //weight: 1, accuracy: Low
        $x_1_5 = {33 d2 f7 75 ?? 8b 45 ?? 0f b6 04 10 03 c8 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_DL_2147632453_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DL"
        threat_id = "2147632453"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 8b 42 34 8b 4d fc 03 41 28 89 85}  //weight: 1, accuracy: High
        $x_1_2 = {79 07 48 0d 00 ff ff ff 40 33 8c 85 ?? ?? ff ff 8b 45 08 03 85 ?? ?? ff ff 88 08 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {66 8b 51 06 39 95 ?? ?? ff ff 7d 4b 8b 85 ?? ?? ff ff 8b 48 3c 8b 95 ?? ?? ff ff 6b d2 28 03 55 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CM_2147632695_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CM"
        threat_id = "2147632695"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7c 37 01 46 75 ?? 80 7c 37 02 75 75 ?? 80 7c 37 03 4a 75 ?? 80 7c 37 04 30 75 ?? 80 7c 37 05 78 75 ?? 80 7c 37 06 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CN_2147632766_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CN"
        threat_id = "2147632766"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fe 0f b6 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8b 54 24 ?? 8d 84 ?? ?? ?? ?? ?? 99 f7 fe 83 c1 05 0f b6 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 83 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 b4 10 8b 54 bc 10 89 54 b4 10 0f b6 c0 89 44 bc 10 33 d2 8d 41 ff f7 f3 0f b6 92 ?? ?? ?? ?? 03 d7 03 54 b4 14 8b fa 81 e7 ff 00 00 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CP_2147633072_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CP"
        threat_id = "2147633072"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 38 7b 0f 85 6a 03 00 00 8b 45 f8 03 45 0c 40 80 38 61 0f 85 5a 03 00 00 8b 45 f8 03 45 0c 83 c0 02 80 38 64 0f 85 48 03 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {80 7e f9 7b 75 f0 80 7e fa 61 75 ea 80 7e fb 64 75 e4 80 7e fc 69 75 de 80 7e fd 66 75 d8 80 7e fe 7d 75 d2}  //weight: 1, accuracy: High
        $x_1_3 = {80 3e 7b 75 f1 80 7e 01 61 75 eb 80 7e 02 64 75 e5 80 7e 03 69 75 df 80 7e 04 66 75 d9 80 7e 05 7d 75 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_DM_2147633091_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DM"
        threat_id = "2147633091"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ed 01 0f 85 ?? ?? ff ff 0f 11 ?? 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 54 8c 14 8b 84 24 18 04 00 00 30 14 28}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4c 24 14 8b c1 99 f7 fe 8b 84 24 2c 02 00 00 8a 14 02 88 94 0c 20 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_DN_2147633117_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DN"
        threat_id = "2147633117"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ea 01 0f 85 ?? ?? ff ff 0f 11 ?? 24}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 4c 8c 14 8b 84 24 18 04 00 00 30 0c 02}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 18 99 f7 7c 24 10 8b 8c 24 28 02 00 00 8a 04 0a 8b 54 24 18 88 84 14 1c 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_CQ_2147633124_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CQ"
        threat_id = "2147633124"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 38 7b 75 3f 8b 45 f0 03 45 0c 40 80 38 7d 75 33 c7 04 24 04 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 0c 03 45 f8 80 38 7b 0f 85 ?? ?? ?? ?? 8b 45 f8 03 45 0c 40 80 38 61 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CS_2147633326_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CS"
        threat_id = "2147633326"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 00 52 65 73 75 6d 65 54 68 72 65 61 64 00 00 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00 00 00 00 57 72 69 74 65 50 72 6f 63 65 73 73 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {81 c9 00 ff ff ff 41 8b 45 08 03 85 fc fb ff ff 0f b6 10 33 94 8d 00 fc ff ff 8b 45 08 03 85 fc fb ff ff 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CT_2147633327_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CT"
        threat_id = "2147633327"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 00 00 00 2e 2e 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "LoadResource" ascii //weight: 1
        $x_1_3 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_4 = "NtWriteVirtualMemory" ascii //weight: 1
        $x_1_5 = {2a 04 1f 88 01 41 83 ee 01 75 ?? 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CR_2147633332_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CR"
        threat_id = "2147633332"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 51 10 03 d7 89 94 24}  //weight: 1, accuracy: High
        $x_1_2 = {83 c6 28 45 66 8b 4a 02 3b e9 7e ca}  //weight: 1, accuracy: High
        $x_1_3 = {83 c6 02 83 f0 30 47 89 44 24 ?? 88 47 ff 3b f5 7c 9a}  //weight: 1, accuracy: Low
        $x_1_4 = {02 00 01 00 ff 15 ?? ?? ?? ?? 85 c0 75 0b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 81 3b 4d 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_CV_2147633384_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CV"
        threat_id = "2147633384"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 55 ?? 52 8b 45 ?? 50 8b 0d ?? ?? ?? ?? 51 ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 0f 8b 85 ?? ?? ff ff 83 c0 01 89 85 00 ff ff 8b 8d ?? ?? ff ff 0f b7 51 06 39 95 00 ff ff 0f 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 8b 48 34 8b 95 ?? ?? ff ff 03 4a 28 89 8d ?? ?? ff ff 04 00 8b 85 00}  //weight: 1, accuracy: Low
        $x_1_4 = {81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8b 45 08 03 85 ?? ?? 0f b6 10 33 94 8d ?? ?? ff ff 8b 45 08 03 85 ?? ?? ff ff 88 10}  //weight: 1, accuracy: Low
        $x_1_5 = {ff ff 07 00 01 00 8b 45 0c 89 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_CeeInject_CW_2147633385_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CW"
        threat_id = "2147633385"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 7d 08 b9 00 30 00 00 8b 77 3c 83 ec 08 01 f7 8b 47 54 89 4c 24 0c 89 5c 24 10 a3 ?? ?? ?? ?? 8b 47 50 89 44 24 08 8b 47 34 89 44 24 04 a1 ?? ?? ?? ?? 89 04 24 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b7 47 14 83 ec 14 8d 74 38 18 31 c0 66 83 7f 06 00 a3 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 5f 28 b9 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 ec 14 01 d8 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 4c 24 04 89 04 24 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_DO_2147633919_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DO"
        threat_id = "2147633919"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 19 88 18 88 11 8a 00 8b 4d 10 03 c2 23 c6 8a 84 05 f0 fe ff ff 32 04 39 88 07 47 ff 4d 0c 75 bc}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 46 14 83 65 0c 00 66 83 7e 06 00 c7 45 fc 01 00 00 00 8d 7c 30 18 76 41}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 b5 d8 80 38 00 74 ?? 50 8d 85 d4 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CX_2147633925_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CX"
        threat_id = "2147633925"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 51 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 52 ff d7 8b 4c 24 ?? 8d 84 24}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 52 51 8b 4c 24 ?? 50 51 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_4 = "AltDefaultUserName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CY_2147636359_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CY"
        threat_id = "2147636359"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 d4 56 69 72 74 c7 45 d8 75 61 6c 50 c7 45 dc 72 6f 74 65 c7 45 e0 63 74 45 78 c6 45 e4 00 c6 45 e5 4b}  //weight: 1, accuracy: High
        $x_1_2 = {25 00 f0 ff ff 3b c8 72 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CZ_2147636501_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!CZ"
        threat_id = "2147636501"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 7e 34 57 83 c2 08 52 ?? ff 15 ?? ?? ?? ?? 8b 4e 28 03 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 48 06 43 83 c6 28 3b d9 7c d8 eb 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DA_2147637254_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DA"
        threat_id = "2147637254"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 47 50 89 44 24 08 8b 47 34 89 44 24 04}  //weight: 2, accuracy: High
        $x_1_2 = {73 10 8d 76 00 e8 ?? ?? ?? ?? 30 04 33 43 39 fb 72 f3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 5f 28 a1 ?? ?? ?? ?? 83 ec 14 01 d8 89 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_DB_2147637416_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DB"
        threat_id = "2147637416"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 33 43 39 fb 72 f3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 47 28 03 05 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 89 44 24 04 a1 ?? ?? ?? ?? 89 04 24 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "net stop MsMpSvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DD_2147637962_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DD"
        threat_id = "2147637962"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d0 c0 32 c8 d0 c0 32 c8 d0 c0 32 c8 d0 c0 c1 ea 02 32 82 ?? ?? ?? ?? 32 c1 34 ?? 88 45 ff 84 db 74 ?? b0 01 32 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {f6 eb 88 45 f4 8a 46 02 c0 e8 05 88 45 fb 24 04 f6 eb 88 45 f5 8a 46 02 c0 e8 06 88 45 e9 24 02 f6 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DE_2147638028_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DE"
        threat_id = "2147638028"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 73 50 ff 73 34}  //weight: 1, accuracy: High
        $x_1_2 = {74 11 0f b7 47 06 ff 45 0c 83 c3 28 39 45 0c 72 ?? eb 03}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 43 28 03 43 34 89 85 74 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_DF_2147638153_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DF"
        threat_id = "2147638153"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 01 b9 04 00 00 00 b9 ?? ?? ?? ?? 39 31 74 ?? 8b f0 83 eb 06 8b d8 83 eb 02 83 c0 04 c1 ce 0c 2b d9}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 c8 09 83 f8 0b 74 14 bb 0e 00 00 00 21 d8 83 eb 08 09 d9 83 c1 01 be 07 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DG_2147638397_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DG"
        threat_id = "2147638397"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 19 88 18 88 11 8a 00 8b 4d 10 03 c2 23 c6 8a 84 05 ?? ?? ff ff 32 04 39 88 07 47 ff 4d 0c 75}  //weight: 1, accuracy: Low
        $x_1_2 = {53 0f be 04 37 0f be 5c 37 01 8a 80 ?? ?? ?? ?? 83 c6 04 8a 9b ?? ?? ?? ?? c0 e0 02 c0 eb 04 0a c3 88 01 41}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 09 09 4d 4e 4f 4a 39 4e 2f 2f 2f 50 31 37 2f 2f 2f 4e 51 0c 02 21 0b}  //weight: 1, accuracy: High
        $x_1_4 = {6a 40 68 00 30 00 00 ff ?? 50 ff ?? 34 ff 75 ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_DI_2147639350_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DI"
        threat_id = "2147639350"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 34 8b 8d ?? ?? ff ff 03 41 28 89 85}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 00 0c 60 8b 8d ?? ff ff ff 03 c8 89 8d 00 ff ff ff 8b 85 00 ff ff ff d1 e0 89 85 00 ff ff ff eb bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DR_2147640291_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DR"
        threat_id = "2147640291"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 8c 05 ?? ?? ff ff 40 3d ?? ?? 00 00 72 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 49 3c 03 4d 0c 8d 8c 31 f8 00 00 00 89 0d ?? ?? ?? ?? 8b 40 34 8b 51 14 ff 71 10 03 41 0c 03 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DR_2147640291_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DR"
        threat_id = "2147640291"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_2 = {42 0f b6 94 15 ec fe ff ff 33 c2 8b 8d e0 fe ff ff 03 4d f8 88 01}  //weight: 1, accuracy: High
        $x_2_3 = {89 4d f0 8b 55 f0 0f b6 84 15 ec fe ff ff 03 45 f4 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 2, accuracy: High
        $x_1_4 = {bb de c0 00 00 53 90 3b c3 58 5b 58 6a 0b 6a 01 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DT_2147640841_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DT"
        threat_id = "2147640841"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 51 f0 30 10 fe cb 0f b6 14 0e 88 11 75 e8}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 0e 8b c1 25 ff 0f 00 00 03 02 81 e1 00 f0 00 00 81 f9 00 30 00 00 75 06}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 01 8d 4d ff 51 50 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 80 7d ff e9 75 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DU_2147641317_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DU"
        threat_id = "2147641317"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {8a 04 32 30 01 ff 45 fc 8b 45 fc 3b 45 10 7c ad}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DS_2147641330_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DS"
        threat_id = "2147641330"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 34 03 48 28 [0-3] 89 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 8c 8d fc fb ff ff 80 f1 ?? f6 d1 30 0a 40 3b 45 10 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DV_2147641816_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DV"
        threat_id = "2147641816"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 (ff 70 50 ff|8b 48 50 8b)}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 34 03 48 28}  //weight: 1, accuracy: High
        $x_1_3 = {8b 41 28 a3 ?? ?? ?? ?? (03|8b 51 34)}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 41 28 a3 ?? ?? ?? ?? 03 41 34 a3 00 ff 56 3c}  //weight: 1, accuracy: Low
        $x_1_5 = {32 0a 80 f1 ?? 40 88 0a}  //weight: 1, accuracy: Low
        $x_1_6 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_DX_2147642148_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DX"
        threat_id = "2147642148"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 39 07 0f 85 ?? ?? ?? ?? 8b 47 3c 03 c7 a3 ?? ?? ?? ?? 81 38 50 45 00 00 0f 85 8f 01 00 00 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {39 74 24 0c 7c 1f 8b 44 24 08 8d 0c 06 8b c6 99 f7 3d ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 30 01 46 3b 74 24 0c 7e e1 5e c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 4d 08 51 6a 40 53 50 89 06 ff 15 ?? ?? ?? ?? 8b 5d 0c 57 53 ff 36 e8 ?? ?? ?? ?? 01 3e 8b 06 c6 00 e9 83 c4 0c ff 06 8b 06 8b cf 2b c8 8d 4c 19 fc 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DY_2147642564_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DY"
        threat_id = "2147642564"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 08 01 75 0a b8 ?? ?? ?? ?? e9 e7 00 00 00 83 7d 08 02 75 0a b8 ?? ?? ?? ?? e9 d7 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d f0 8a 94 0d ?? ?? ?? ?? 88 94 05 ?? ?? ?? ?? 8b 45 f0 8a 8d ?? ?? ?? ?? 88 8c 05 ?? ?? ?? ?? e9 79 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 09 6a 01 e8 ?? ?? ?? ?? 83 c4 08 a3 ?? ?? ?? ?? 6a 44 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DZ_2147644180_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DZ"
        threat_id = "2147644180"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 73 50 ff 73 34 ff 75 e0 ff ?? ?? 57}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 0c 03 43 34 50 ff ?? ?? ff ?? ?? 0f b7 43 06 ff ?? ?? 83 45 f8 28 39 45 fc 7c c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DZ_2147644180_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!DZ"
        threat_id = "2147644180"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 46 28 03 46 34}  //weight: 2, accuracy: High
        $x_2_2 = {ff 76 50 ff 76 34}  //weight: 2, accuracy: High
        $x_1_3 = {07 00 01 00 (0b 00 c7|0a 00)}  //weight: 1, accuracy: Low
        $x_1_4 = {07 00 01 00 03 00 c7 45}  //weight: 1, accuracy: Low
        $n_10_5 = "VeryPDF" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_EA_2147644782_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EA"
        threat_id = "2147644782"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 02 6a 01 8b 4d d4 51 ff 55 fc}  //weight: 1, accuracy: High
        $x_1_2 = {52 6a 00 6a 00 6a 24 6a 00 6a 00 6a 00 8b 45 0c 50 6a 00 ff 55 a0 83 7d 0c 00 74 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EB_2147644849_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EB"
        threat_id = "2147644849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f0 8b 46 04 6a 2e 50}  //weight: 1, accuracy: High
        $x_1_2 = {33 ff 33 c0 89 44 84 14 40 3d 00 01 00 00 7c f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EC_2147644906_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EC"
        threat_id = "2147644906"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 28 03 46 34 ?? 89 87 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 3b 47 65 74 50 74 06 83 c7 04 41 eb ed 81 7b 04 72 6f 63 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_V_2147644918_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.V"
        threat_id = "2147644918"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 70 50 ff 70 34}  //weight: 1, accuracy: High
        $x_2_2 = {8d 0c 06 e8 ?? ?? ?? ?? 30 01 83 c4 04 46 3b ?? 7c e9}  //weight: 2, accuracy: Low
        $x_1_3 = {c6 00 e9 ff 06 8b 06 2b f8}  //weight: 1, accuracy: High
        $x_1_4 = {f7 75 14 8b 45 0c 8b ?? 89 bc bd ?? ?? ff ff 0f b6 04 ?? 03 ?? 03 ?? 99 f7 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_ED_2147645422_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!ED"
        threat_id = "2147645422"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec f0 02 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 6a 0f e8 ?? ?? ff ff 83 c4 40 50 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 68 ?? 00 00 00 6a 0a e8 ?? ?? ff ff 83 c4 2c 50 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 01 00 00 00 85 c0 74 18 8b 4d fc 3b 4d f4 75 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EE_2147645461_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EE"
        threat_id = "2147645461"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 83 c2 01 89 55 f8 81 7d f8 2e e6 0a 00 0f 8f ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EF_2147645462_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EF"
        threat_id = "2147645462"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 42 0f 00 75 ?? 8b 95 ?? ?? ff ff 8b 02 05 00 dd d8 ?? 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EG_2147645534_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EG"
        threat_id = "2147645534"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 f8 8b 4d f4 51 8b 55 0c 52 ff 55 f8 6a 40 68 00 30 00 00 8b 45 fc 8b 48 50 51 8b 55 f4 52 8b 45 0c 50 ff 15 ?? ?? ?? ?? 6a 00 8b 4d fc 8b 51 54 52 8b 45 08 50 8b 4d f4 51 8b 55 0c 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EH_2147645548_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EH"
        threat_id = "2147645548"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 f8 00 00 00 8b 45 ec 50 8b c3 03 46 3c 50 ff 15 ?? ?? ?? ?? 8d 45 e0 50 8b 45 ec 8b 40 50 50 53 8b 45 e4 50 8b 45 d0 50 ff 15 ?? ?? ?? ?? 8d 45 e0 50 6a 04 8d 45 e4 50 8b 87 a4 00 00 00 83 c0 08 50 8b 45 d0 50 ff 15 ?? ?? ?? ?? 8b 45 ec 8b 40 28 03 45 e4 89 87 b0 00 00 00 57 8b 45 d4 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EI_2147645695_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EI"
        threat_id = "2147645695"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 75 14 8b 7d 0c 0f b6 04 17 8b bd f0 fb ff ff 01 c7 81 e7 ff 00 00 80 79 b7 4f 81 cf 00 ff ff ff 47 eb ad}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 04 00 00 00 00 c7 04 24 01 00 1f 00 e8 ?? ?? ?? ?? 83 ec 0c 85 c0 74 0c 31 c0 8d 65 f4 5b 5e 5f c9 c2 10 00 c7 44 24 08 ?? ?? ?? ?? c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8 ?? ?? ?? ?? 83 ec 0c c7 44 24 08 04 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EJ_2147645728_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EJ"
        threat_id = "2147645728"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 50 8d 04 49 50 57 68 02 01 00 00 ff 56 44 68 ff 00 00 00 68 ?? ?? ?? ?? 53 ff 56 28}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 56 38 8b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 42 34 50 51 ff 56 40 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 6a 40 68 00 30 00 00 8b 50 50 8b 40 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EL_2147645765_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EL"
        threat_id = "2147645765"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 50 50 8b 40 34}  //weight: 1, accuracy: High
        $x_1_2 = {8b 51 34 8b 0d ?? ?? ?? ?? 03 c2 08 00 [0-5] 8b 41 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EM_2147645820_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EM"
        threat_id = "2147645820"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 51 06 39 95 ?? ?? ff ff 7d ?? 8b 85 ?? ?? ff ff 8b 48 3c 8b 55 ?? 8d 84 0a f8 00 00 00 8b 8d ?? ?? ff ff 6b c9 28 03 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 04 8d (45|5d|4d|55|75|7d) ?? (50|53|51|52|56|57) 8b (85|9d|8d|95|b5|bd) ?? ?? ff ff 83 (c0|c3|c1|c2|c6|c7) 08 (50|53|51|52|56|57) 8b (45|5d|4d|55|75|7d) ?? (50|53|51|52|56|57) ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EN_2147645966_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EN"
        threat_id = "2147645966"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 41 03 b9 00 01 00 00 99 f7 f9 89 d1 8b bc 95 ?? ?? ff ff 8d 04 1f bb 00 01 00 00 99 f7 fb 89 d3 8b 84 95 ?? ?? ff ff 89 84 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 3b 4d 5a 0f 85 ?? ?? 00 00 8b 43 3c 01 d8 a3 ?? ?? ?? ?? 81 38 50 45 00 00 0f 85 ?? ?? 00 00 8b 3d ?? ?? ?? ?? c7 85 ?? ?? ff ff 07 00 01 00 c7 45 ?? 44 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EO_2147645985_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EO"
        threat_id = "2147645985"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d 10 56 57 8d 7b 05 8b f1 57 e8 ?? ?? ?? ?? 59 89 06 8d 4d fc 51 6a 40 57 50 ff 15 ?? ?? ?? ?? ff 75 08 ff 75 0c ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 53 50 ff 36 89 45 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 3c 03 45 fc 8d 84 30 f8 00 00 00 a3 ?? ?? ?? ?? 8b 49 34 8b 50 14 ff 70 10 03 48 0c 03 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EQ_2147646050_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EQ"
        threat_id = "2147646050"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d3 6a 00 ff 76 54 89 45 f0 57 ff 75 08 ff 75 0c ff d0 83 65 fc 00 33 c0 66 3b 46 06 73}  //weight: 1, accuracy: High
        $x_1_2 = {8d 84 38 f8 00 00 00 ff 70 10 8b 48 14 8b 40 0c 03 45 08 03 cf 51 50 ff 75 0c ff 55 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ER_2147646058_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!ER"
        threat_id = "2147646058"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 50 68 ?? ?? ?? ?? 6a 0c e8 ?? ?? ?? ?? 83 c4 08 50 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 50 ff 55 ?? 8b e5}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? ff 55 ?? ff 55 ?? 89 45 ?? 81 7d ?? 14 07 00 00 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ES_2147646339_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!ES"
        threat_id = "2147646339"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 d8 8d 47 5c 50 53 ff d6 83 c7 2e}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 46 06 ff 45 fc 83 45 08 28 39 45 fc 7c}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 75 ?? ff 55 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ET_2147646368_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!ET"
        threat_id = "2147646368"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b cf 80 f3 ?? e8 ?? ?? ?? ?? 46 88 18 83 fe 14 72 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 b5 a4 00 00 00 8b 45 84 0f b6 04 02 0f b6 55 8b 03 c3 03 d0 23 d1 8b da}  //weight: 1, accuracy: Low
        $x_1_3 = {40 3d 00 01 00 00 72 f2 33 c9 be ff 00 00 00 33 d2 8b c1 f7 75 14}  //weight: 1, accuracy: High
        $x_1_4 = {8b 77 3c 68 4d 5a 00 00 50 c7 ?? ?? 07 00 01 00 03 f7 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 45 e4 89 50 f8 0f b7 54 4f 08 89 50 fc c6 00 04 88 58 01 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_EU_2147646651_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EU"
        threat_id = "2147646651"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 11 81 e2 00 00 00 80 74 ?? 8b 45 ?? 8b 08 81 e1 ff ff 00 00 51 8b 55 ?? 52 ff 15 ?? ?? ?? ?? 8b 4d ?? 89 01}  //weight: 1, accuracy: Low
        $x_1_2 = {03 48 3c 89 4d ?? 8b 55 ?? 8b 42 50 89 45 ?? 6a 00 8b 4d ?? 51 8b 55 ?? 52 8b 45 08 50 8b 4d ?? 51 ff 15 ?? ?? ?? ?? 8b 55 ?? 8b 45 08 03 42 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EV_2147646652_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EV"
        threat_id = "2147646652"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 57 ff 55 ?? 50 ff 55 ?? 8b 4e 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7b 3c 8b 54 1f 50 8b 45 fc 83 c4 14 6a 00 03 fb 52 53 8b 5d 08 53 50 ff 15 ?? ?? ?? ?? 8b 4f 28 03 cb ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EW_2147646676_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EW"
        threat_id = "2147646676"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7e 3c 8b 54 37 50 6a 40 03 fe 68 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 c6 04 3b f0 75 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_Y_2147647046_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.Y"
        threat_id = "2147647046"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 06 83 4d fc ff eb 10 81 7d 08 50 4b 01 02 74 07 c7 45 fc 99 ff ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {74 05 83 cb ff eb 0c 81 7d 08 50 4b 03 04 74 03 6a 99 5b}  //weight: 5, accuracy: High
        $x_5_3 = {83 f8 01 75 3e 8d 47 fd eb 1c 48 80 3c 18 50 75 15 80 7c 18 01 4b 75 0e 80 7c 18 02 05 75 07 80 7c 18 03 06 74 06}  //weight: 5, accuracy: High
        $x_10_4 = {40 3b c7 7c 0b 00 [0-1] 83 ?? 04 8a ?? [0-3] 88 14}  //weight: 10, accuracy: Low
        $x_1_5 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 00 00 64 00 70 00 6c 00 61 00 79 00 73 00 76 00 72 00 2e 00 6c 00 6e 00 6b 00 00 00 00 00 64 00 70 00 6c 00 61 00 79 00 78 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 64 00 70 00 6c 00 61 00 79 00 73 00 76 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 00 00 26 00 72 00 73 00 3d 00 31 00 00 00 26 00 73 00 63 00 3d 00 31 00 00 00 26 00 73 00 72 00 3d 00 31 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_EX_2147647050_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EX"
        threat_id = "2147647050"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 81 fe 80 f0 fa 02 74 0f e8 ?? ?? 00 00 83 f8 63 75 ed 83 fe 63 75 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ec 3c 01 00 00 c7 44 24 08 ?? ?? ?? 00 c7 44 24 04 00 00 00 00 c7 04 24 01 00 1f 00 e8 ?? ?? 00 00 83 ec 0c 85 c0 74 0d 31 c0 8d 65 f4}  //weight: 1, accuracy: Low
        $x_1_3 = {81 ec 7c 03 00 00 8b 5d 0c 8d 75 94 b9 44 00 00 00 31 c0 89 f7 f3 aa 89 1d ?? ?? 40 00 66 81 3b 4d 5a 74 0a 8d 65 f4}  //weight: 1, accuracy: Low
        $x_1_4 = {cc cc cc cc 75 f2 c7 06 90 eb 01 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_EY_2147647104_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EY"
        threat_id = "2147647104"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 95 9c fd ff ff 03 95 c4 fa ff ff 89 95 78 fb ff ff 8d 85 c8 fa ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 85 6c fb ff ff 83 c0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_EZ_2147647219_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!EZ"
        threat_id = "2147647219"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 44 0a ff eb 8b 45 ?? 40 89 45 01 8b 45 01 3b}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 70 34 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 65 ?? 00 eb 07 8b 45 02 40 89 45 02 8b 45 ?? 0f b7 40 06 39 45 02 0f 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FA_2147647380_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FA"
        threat_id = "2147647380"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 f8 09 c0 75 04 83 c8}  //weight: 1, accuracy: High
        $x_1_2 = {c1 c6 02 81 ee}  //weight: 1, accuracy: High
        $x_1_3 = {d1 ce 81 ee}  //weight: 1, accuracy: High
        $x_1_4 = {c1 ee 06 03}  //weight: 1, accuracy: High
        $x_1_5 = {32 c4 fe c8 02 c4 32 c4 2a c4 fe c8 04 a9 d0 c8 aa d0 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FB_2147647501_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FB"
        threat_id = "2147647501"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 84 0a f8 00 00 00 8b 8d ?? ?? ff ff 6b c9 28}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 10 8b d4 8b 45 f0 89 02 8b 4d f4 89 4a 04 8b 45 f8 89 42 08 8b 4d fc 89 4a 0c 8b 55 ec 52 e8}  //weight: 1, accuracy: High
        $x_1_3 = {b8 01 00 00 00 85 c0 74 1f 8b 4d fc 3b 4d f8 75 05 8b 45 f8 eb 15 8b 55 08 8b 45 f8 8d 4c 10 04 2b 4d 08 89 4d f8 eb d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_FC_2147647669_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FC"
        threat_id = "2147647669"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 47 3c 03 c3 50 ff 15 ?? ?? ?? ?? 8d 45 ?? 50 8b 45 ?? 8b 40 50 50 53 8b 45 ?? 50 8b 45 ?? 50 ff 15 ?? ?? ?? ?? 8d 45 ?? 50 6a 04 8d 45 ?? 50 8b 45 f0 8b 80 a4 00 00 00 83 c0 08 50 8b 45 ?? 50 ff 15 ?? ?? ?? ?? 8b c6 2b c6 03 45 ?? 8b 55 e8 03 42 28 8b 55 f0 89 82 b0 00 00 00 8b 45 f0 50 8b 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 89 45 f4 68 00 80 00 00 6a 00 8b 45 ec 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FD_2147647674_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FD"
        threat_id = "2147647674"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "54A3818F-28A7-4525-B2DE-96E78174AB65" ascii //weight: 1
        $x_1_2 = {33 8b f7 8a 8b 0f 03 0f 03 23 8b 89 03 8a 88 47 88}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 f0 01 00 00 00 66 8b 04 75 ?? ?? ?? ?? 66 33 04 75 ?? ?? ?? ?? 56 8b cb 0f b7 f8 e8 ?? ?? ?? ff 46 66 89 38 83 fe 0c 72}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 f0 01 00 00 00 8a 9e ?? ?? ?? ?? 32 9e ?? ?? ?? ?? 56 8b cf e8 ?? ?? ?? ff 46 88 18 83 fe 14 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_FE_2147648189_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FE"
        threat_id = "2147648189"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 50 34 8b 68 50}  //weight: 1, accuracy: High
        $x_1_2 = {8b 50 34 03 50 28}  //weight: 1, accuracy: High
        $x_1_3 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FF_2147648356_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FF"
        threat_id = "2147648356"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 fb 5a 0f 94 c2 33 db 80 3f 4d 0f 94 c3}  //weight: 1, accuracy: High
        $x_1_2 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c1 08 51 52 ff 15 ?? ?? ?? ?? 85 c0 a0 ?? ?? ?? ?? 74 0c 3c 01 75 08 07 00 6a 04 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FG_2147648389_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FG"
        threat_id = "2147648389"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 28 03 46 34}  //weight: 1, accuracy: High
        $x_1_2 = {8b 56 50 8b 46 34}  //weight: 1, accuracy: High
        $x_1_3 = {07 00 01 00 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $n_10_4 = "D:\\BuildScript.NET\\c2patchdx11\\pc\\Build\\Bin32\\Crysis2.pdb" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_Z_2147648403_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.Z"
        threat_id = "2147648403"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\ValhallaCrypter\\ValhallaStub\\Debug\\ValhallaStub.pdb" ascii //weight: 1
        $x_1_2 = {79 08 49 81 c9 00 ff ff ff 41 8b 45 08 03 85 ?? ?? ?? ?? 0f b6 10 33 94 8d ?? ?? ?? ?? 8b 45 08 03 85 ?? ?? ?? ?? 88 10 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 fc 0b 8d 85 ?? ?? ?? ?? 50 8d 8d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 83 c4 08 c6 45 fc 0d 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = {8b f4 50 6a 00 6a 00 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 3d b7 00 00 00 75 66 68 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_FH_2147648424_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FH"
        threat_id = "2147648424"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 51 50 8b 4e 3c 6a 40 68 00 30 00 00 52 8b 54 31 34}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff 02 00 01 00 04 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_3 = {68 d8 cb 88 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FI_2147648530_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FI"
        threat_id = "2147648530"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 2e 68 ff 11 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {8d 46 fe f7 75 14 0f b6 04 13 03 41 fc 03 f8 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_FJ_2147648541_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FJ"
        threat_id = "2147648541"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 04 56 8b 74 24 0c 33 c9 85 f6 74 0c 8a 54 24 10 30 14 01 41 3b ce 72 f8}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FK_2147648618_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FK"
        threat_id = "2147648618"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f3 34 66 81 e9 a9 00 66 0b c3 c0 e3 03 02 c8 f6 d8 d0 e3 f7 d3 c0 e0 1a}  //weight: 1, accuracy: High
        $x_1_2 = {30 0c 2f 83 c7 01 3b fa 89 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {66 4b 66 81 f1 b0 00 f6 d3 fe c8 fe c1 8b 44 24 14 8b 4c 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AO_2147648630_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AO"
        threat_id = "2147648630"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 31 04 83 c0 ?? 88 44 17 fb 83 c1 05 3b 8d 9c fd ff ff 76 b6}  //weight: 1, accuracy: Low
        $x_1_2 = {52 6a 24 52 52 52 50 52 ff 15 ?? ?? ?? ?? 8b 45 cc ff 74 38 34 ff 35 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {f7 84 d1 1c 01 00 00 00 00 00 80 0f 44 f0 f7 84 d1 1c 01 00 00 00 00 00 20 89 75 c8 8b 75 d0 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FN_2147648697_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FN"
        threat_id = "2147648697"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {07 00 01 00 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 58 50 8b ?? 34 [0-32] 6a 40 68 00 30 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 50 34 03 50 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AP_2147648703_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AP"
        threat_id = "2147648703"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 1c 8d 41 15 32 04 32 32 c1 34 15 88 04 32 83 f9 05 7e 04 33 c9 eb 01 41 42 3b d7 7c e4}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 fc af be ba ba 89 55 f8 eb 06 8d 9b 00 00 00 00 8d 4d fc 8b c7 be 03 00 00 00 8d 9b 00 00 00 00 8a 18 3a 19 75 05 40 41 4e 75 f5}  //weight: 1, accuracy: High
        $x_1_3 = {89 07 8b 7d 08 c7 45 f8 dd cc bb aa 89 55 fc eb 06 8d 9b 00 00 00 00 8d 4d f8 8b c7 be 03 00 00 00 8d 9b 00 00 00 00 8a 18 3a 19 75}  //weight: 1, accuracy: High
        $x_1_4 = {8d 49 00 8d 50 0b 32 91 ?? ?? ?? 00 32 d0 80 f2 0b 88 91 ?? ?? ?? 00 83 f8 05 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_FO_2147648907_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FO"
        threat_id = "2147648907"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 78 50 8b 58 34}  //weight: 1, accuracy: High
        $x_1_3 = {8b 48 34 03 48 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FP_2147648950_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FP"
        threat_id = "2147648950"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 50 51 8b 15 ?? ?? ?? ?? 8b 42 34}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 48 34 8b 15 ?? ?? ?? ?? 03 4a 28 89 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FQ_2147649698_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FQ"
        threat_id = "2147649698"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 28 03 46 34}  //weight: 1, accuracy: High
        $x_1_2 = {ff 76 50 ff 76 34}  //weight: 1, accuracy: High
        $x_1_3 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FQ_2147649698_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FQ"
        threat_id = "2147649698"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 55 ?? 85 c0 0f 84 ?? ?? ?? ?? 50 6a 00 ff 55 ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 c1 01 00 00 00 74 09 60 6a ?? e8 ?? ?? ?? ?? 61 e2 ?? ff 75 ?? ff 75 ?? b8 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FR_2147649988_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FR"
        threat_id = "2147649988"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 41 28 89 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {07 00 01 00 06 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 30 00 00 8b 8d ?? ?? ff ff 8b 51 50 52 8b 85 ?? ?? ff ff 8b 48 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BY_2147650495_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BY"
        threat_id = "2147650495"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 48 3c 8b 55 fc 0f b7 04 0a 3d 50 45 00 00 2f 00 83 e9 02 8b 95 ?? fe ff ff 39 4a 3c}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 64 72 50 72 6f 63 00 39 00 6c 64 72 2e 65 78 65 00}  //weight: 2, accuracy: Low
        $x_1_3 = {c1 e0 07 8b 4d f8 c1 e9 19 0b c1 89 45 f8}  //weight: 1, accuracy: High
        $x_2_4 = {68 dd 47 43 de 6a 01 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_FU_2147650951_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FU"
        threat_id = "2147650951"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4e 54 8b 56 34}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4e 34 8b 46 28 [0-8] 03 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FV_2147651007_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FV"
        threat_id = "2147651007"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ws\\%ws.exe" wide //weight: 1
        $x_1_2 = {80 24 31 00 8d 5c 31 01 89 1a 47 83 c2 04}  //weight: 1, accuracy: High
        $x_1_3 = {53 ff 76 54 ff 75 08 ff 76 34 ff 75 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CD_2147651309_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CD"
        threat_id = "2147651309"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 28 8b 54 24 14 2b cd c1 f9 02 3b d1 73 4c 8b 2b 8b 4c 24 44 8b 14 18 6a 0f 55 51 52 e8 ?? ?? ?? ?? 8b 7c 24 20 8b 54 24 20 8b f0 8b cd 8b c1 c1 e9 02 f3 a5}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 8c 18 8b 54 bc 10 0f b6 c0 89 54 8c 18 89 44 bc 10 33 d2 8d 46 01 f7 f3 8b 44 8c 1c 0f b6 14 2a 03 d0 03 fa 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CF_2147651561_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CF"
        threat_id = "2147651561"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 3b 8b 45 f0 33 d2 f7 75 f4 0f af 45 fc 89 45 a8 83 65 ac 00 df 6d a8 dd 1d}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 0c 48 48 0f 84 c9 00 00 00 83 e8 0d 74 75 2d 02 01 00 00 74 30 e8}  //weight: 1, accuracy: High
        $x_1_3 = {01 01 20 a1 07 00 0f 82 ?? fc ff ff 8b 45 ec c9 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {7e 1c 81 bc 82 6c 2b 00 00 b0 21 40 00 0f}  //weight: 1, accuracy: High
        $x_1_5 = {61 73 74 72 6f 20 25 30 34 78 2d 2d 25 30 34 78 20 70 65 72 20 70 69 78 65 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CG_2147651579_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CG"
        threat_id = "2147651579"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 c0 59 05 01 01 01 00 05 01 01 01 01 81 f9 35 7c 01 00 72 03 89 45}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7d fc 33 c0 f3 a4 5e 56 33 c9 66 8b 4e 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CH_2147651660_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CH"
        threat_id = "2147651660"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 0f be 14 02 38 d6 74 09 c1 cb 0d 90 03 da 40 eb eb}  //weight: 1, accuracy: High
        $x_1_2 = {68 c0 97 e2 ef}  //weight: 1, accuracy: High
        $x_1_3 = {68 56 87 d9 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CI_2147651708_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CI"
        threat_id = "2147651708"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 48 48 0f 84 ?? 00 00 00 83 e8 0d 74 ?? 2d 02 01 00 00 74 30 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 05 ab 35 01 01 74 89 35 ?? 3e 01 01 c6 05 ?? ?? 01 01 ?? c6 05 ?? 35 01 01}  //weight: 1, accuracy: Low
        $x_1_3 = {01 01 0f b6 10 2b d1 74 24 41 81 f9 8b 00 00 00 89 0d ?? 3e 01 01 76 10}  //weight: 1, accuracy: Low
        $x_1_4 = {83 ec 10 c7 45 f0 01 00 00 00 c7 45 f4 01 00 00 00 c7 45 f8 02 00 00 00 c7 45 fc b8 0b 00 00 6a 10}  //weight: 1, accuracy: High
        $x_1_5 = {68 00 7f 00 00 6a 00 89 45 e8 ff 15 ?? ?? 01 01 6a 6c 89 45 ec ff 75 e4 c7 45 f0 06 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_CeeInject_FW_2147651793_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FW"
        threat_id = "2147651793"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {cf 54 ad 05 e9}  //weight: 1, accuracy: High
        $x_1_2 = {35 24 7c 7d 32 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FX_2147651812_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FX"
        threat_id = "2147651812"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 00 00 00 01 8b 4d e4 8d 8c 41 44 06 00 00 0f b7 01 73 17}  //weight: 1, accuracy: High
        $x_1_2 = {9c 60 68 00 00 3c f0 8b 74 24 28 fc bf ?? ?? ?? 00 03 34 ?? 8a 06 0f b6 c0 46 ff 34 85 06 36 3c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CK_2147651831_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CK"
        threat_id = "2147651831"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 48 48 0f 84 ?? ?? 00 00 83 e8 0d 0f 84 ?? ?? 00 00 2d 02 01 00 00 74 30 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {35 01 01 74 c6 05 ?? ?? 01 01 74 c6 05 ?? ?? 01 01 6f c6 05 ?? ?? 01 01 61}  //weight: 1, accuracy: Low
        $x_1_3 = {01 01 0f b6 08 2b 0d ?? ?? 01 01 74 1e ff 05 ?? ?? 01 01 81 3d ?? ?? 01 01 8b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {83 ec 10 c7 45 f0 01 00 00 00 c7 45 f4 01 00 00 00 c7 45 f8 02 00 00 00 c7 45 fc b8 0b 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 00 7f 00 00 6a 00 89 45 e8 ff 15 ?? ?? 01 01 6a 6c 89 45 ec ff 75 e4 c7 45 f0 06 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_CeeInject_CM_2147651900_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CM"
        threat_id = "2147651900"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 00 e9 83 c4 0c ff 06 8b 06 2b d8 8d 4c 3b fc 89 08 8b 46 04 89 38 8b 46 04 83 c9 ff 2b 08 5f 01 0e 8b c6 5e 5b 5d c2 0c 00}  //weight: 1, accuracy: High
        $x_1_2 = "SetThreadContext" ascii //weight: 1
        $x_1_3 = {b8 4d 5a 00 00 83 c4 0c 89 35 ?? ?? ?? 00 c7 05 ?? ?? ?? 00 07 00 01 00 89 1d ?? ?? ?? 00 66 39 03 0f 85 ?? 01 00 00 8b 43 3c 03 c3 a3 ?? ?? ?? 00 81 38 50 45 00 00 0f 85 ?? 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CN_2147651946_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CN"
        threat_id = "2147651946"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 30 44 00 00 00 c7 44 24 74 07 00 01 00 89 1d ?? ?? ?? ?? 66 81 3b 4d 5a 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 54 9c 18 8a 1c 01 32 da 88 1c 01 41 3b cd 72 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FY_2147651959_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FY"
        threat_id = "2147651959"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 76 50 ff 76 34}  //weight: 1, accuracy: High
        $x_1_2 = {8b 47 0c 03 46 34}  //weight: 1, accuracy: High
        $x_1_3 = {07 00 01 00 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_2_4 = {56 8b cf 80 f3 08 e8 ?? ?? ?? ?? 46 88 18 83 fe ?? 72 e7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_FZ_2147651976_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!FZ"
        threat_id = "2147651976"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 a1 ?? ?? ?? ?? ff 70 50 a1 ?? ?? ?? ?? ff 70 34}  //weight: 1, accuracy: Low
        $x_1_2 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 34 8b 0d ?? ?? ?? ?? 03 41 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GA_2147652017_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GA"
        threat_id = "2147652017"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 50 8b 55 08 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 8b 95 ?? ?? ff ff 8b 42 ?? 50 8b 4d ?? 51 8b 95 ?? ?? ff ff 8b 42 ?? 50 8b 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? c7 85 ?? ?? ff ff 00 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 04 8b 8d ?? ?? ff ff 83 c1 34 51 8b 95 ?? ?? ff ff 83 c2 08 52 8b 85 ?? ?? ff ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GC_2147652344_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GC"
        threat_id = "2147652344"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 30 00 00 ff 76 50 [0-16] ff 76 34}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 46 28 05 00 00 40 00 a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GD_2147652801_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GD"
        threat_id = "2147652801"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b cf 80 f3 08 e8 ?? ?? ?? ?? 46 88 18 83 fe ?? 72 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 07 08 00 01 00 ff 0f}  //weight: 1, accuracy: High
        $x_1_3 = {8b 46 0c 03 43 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_GE_2147652805_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GE"
        threat_id = "2147652805"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 30 00 00 8b 15 ?? ?? ?? ?? 8b 42 50 50 8b 0d ?? ?? ?? ?? 8b 51 34}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 50 28 b9 00 00 40 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GF_2147652859_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GF"
        threat_id = "2147652859"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 00 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {03 43 28 89 87 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 87 a4 00 00 00 83 c0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GF_2147652859_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GF"
        threat_id = "2147652859"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 50 6a 01 55 81 c5 ?? ?? ?? ?? c7 40 04 ?? ?? ?? ?? c7 00 01 00 00 00 89 78 08 ff d5 be 10 00 00 00 39 74 24 50 72 0d 8b 44 24 3c 50 e8 ?? ?? ?? ?? 83 c4 04 c7 44 24 50 0f 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 8b f8 8b 46 ?? 6a 02 ff d0 8b e8 [0-4] 83 fd ff 0f 84 ?? ?? 00 00 68 28 01 00 00 8d 4c 24 1c 6a 00 51 e8 ?? ?? ?? ?? 8b 46 ?? 83 c4 0c 8d 54 24 18 52 55 c7 44 24 20 28 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {01 00 00 c1 4d ?? 0f 0f be 10 8b 4d ?? 03 ca 40 89 4d ?? 38 18 75 ?? 81 f9 ?? ?? ?? ?? 74 ?? 81 f9 ?? ?? ?? ?? 74 ?? 81 f9 ?? ?? ?? ?? 74 ?? 81 f9}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 04 50 6a 01 57 81 c7 ?? ?? ?? ?? c7 40 04 ?? ?? ?? ?? c7 00 01 00 00 00 89 48 08 ff d7 be 10 00 00 00 39 b5 ?? ?? ?? ?? 72 ?? 8b 95 ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 04 c7 85 ?? ?? ?? ?? 0f 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_GH_2147653111_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GH"
        threat_id = "2147653111"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 42 28 50 68 00 00 40 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 68 00 30 00 00 8b 15 ?? ?? ?? ?? 8b 42 50 50 8b 0d ?? ?? ?? ?? 8b 51 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CT_2147653745_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CT"
        threat_id = "2147653745"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 3b 4d 5a 0f 85 ?? ?? 00 00 8b 73 3c 8b 04 1e 03 f3 3d 50 45 00 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8d a4 24 00 00 00 00 8a 96 ?? ?? 40 00 8b 0d f8 9a 40 00 30 14 01 8b 35 ?? ?? 40 00 8a 86 ?? ?? 40 00 46 84 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 08 8b 4c 24 10 6a 40 68 00 30 00 00 52 8b 54 24 20 51 52 a3 ?? ?? 40 00 ff d0 8b 46 54 8b 4e 34 8b 15 ?? ?? 40 00 6a 00 50 53 51 52 ff 54 24 20 33 ff 66 39 7e 06 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GK_2147653822_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GK"
        threat_id = "2147653822"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 03 43 83 c6 03 ff 4d fc 59 75 02 00 34}  //weight: 1, accuracy: Low
        $x_1_2 = {80 39 b8 75 ?? 80 79 09 cd 75 ?? 80 79 0a 2e eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 3c 03 45 0c 57 8d 84 30 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 37 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_CU_2147653823_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CU"
        threat_id = "2147653823"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 f1 de 09 21 03 e8 ff d6 69 c0 a3 b1 01 45}  //weight: 1, accuracy: High
        $x_1_2 = {30 14 01 8b 35 ?? ?? ?? ?? 8a 86 ?? ?? ?? ?? 46 84 c0 89 35 ?? ?? ?? ?? 75 ?? 33 f6}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 07 00 01 00 c7 05 ?? ?? ?? ?? 44 00 00 00 a3 ?? ?? ?? ?? a3 ?? ?? ?? ?? 66 81 3b 4d 5a 0f ?? ?? ?? ?? ?? 8b 73 3c 8b 04 1e 03 f3 3d 50 45 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CV_2147654014_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CV"
        threat_id = "2147654014"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 c0 ea 02 8a cd c0 e1 04 80 e2 0f 32 d1}  //weight: 1, accuracy: High
        $x_1_2 = {ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 ?? ?? ?? ?? 8b f0}  //weight: 1, accuracy: Low
        $x_1_3 = {d5 53 ff d6 6a 02 6a 64 8d 4c 24 18 51 89 44 24 1c ff d7 85 c0 74 e3 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GL_2147654121_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GL"
        threat_id = "2147654121"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 30 eb de 8b 55 08 8b 02 89 45 f8 8b 45 f8 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 02 33 c1 8b 4d 08 03 4d f4 88 01}  //weight: 1, accuracy: High
        $x_1_3 = {8b 08 c6 01 e9 8b 55 ?? 8b 02 83 c0 01 8b 4d ?? 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_CX_2147654159_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CX"
        threat_id = "2147654159"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 51 3c 89 55 f0 8b 45 f0 81 38 50 45 00 00 74 0f 8b 4d c8}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 48 06 39 4d ec 7d 3d 8b 55 ec 6b d2 28 8b 45 f8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 08 ff d1 8b 55 fc 83 7a 04 00 74 23 68 00 80 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CY_2147654205_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CY"
        threat_id = "2147654205"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 76 6f 48 6a 69 76 75 79 7c 70 7f 80 50 84 76 77 77 85 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 5a 73 7c 3c 3b 58 7b 79 6e 71 80 81 00}  //weight: 1, accuracy: High
        $x_1_3 = {4f 76 4a 69 79 49 76 76 7d 6f 83 80 61 76 81 75 72 76 00}  //weight: 1, accuracy: High
        $x_10_4 = {60 31 c0 40 0f a2 89 1d ?? ?? 40 00 89 15 ?? ?? 40 00 61}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_CW_2147654293_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CW"
        threat_id = "2147654293"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 55 fc 8b 45 f8 0f b7 4e 06 83 45 f0 28 40 89 45 f8 3b c1 7c bf}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4e 54 8b 55 08 6a 00 51 8b 4d 0c 53 52 89 45 fc 51 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_CZ_2147654332_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.CZ"
        threat_id = "2147654332"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 11 00 00 00 8b 4d c4 3b c1 0f 85 13 00 00 00 50}  //weight: 1, accuracy: High
        $x_1_2 = {46 89 7d fc 83 fe 17}  //weight: 1, accuracy: High
        $x_1_3 = {3d 68 0d 00 00 0f 84 0d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {83 f9 28 0f 82 95 ff ff ff 5f 5e 5b c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GM_2147654363_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GM"
        threat_id = "2147654363"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 44 00 00 00 c7 05 ?? ?? ?? 00 07 00 01 00 05 00 c7 05}  //weight: 1, accuracy: Low
        $x_2_2 = {68 00 30 00 00 ff 76 50 ff 76 34 ff 75 ?? e8 ?? ?? ?? ?? 53 ff 76 54 57 ff 76 34 ff 75 ?? ff 15 ?? ?? ?? ?? 33 c0 66 3b 46 06 73 ?? 21 45 0c 8b 47 3c 03 45 0c 6a 00 8d 84 38 f8 00 00 00 ff 70 10 8b 48 14 8b 40 0c 03 46 34 03 cf}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 00 68 00 30 00 00 8b 45 f8 8b 48 50 51 8b 55 f8 8b 42 34 50 8b 4d ?? 51 e8 ?? ?? ?? ?? 6a 00 8b 55 f8 8b 42 54 50 8b 4d 0c 51 8b 55 f8 8b 42 34 50 8b 4d ?? 51}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_DA_2147654365_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.DA"
        threat_id = "2147654365"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 4d 08 03 c1 a3 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 47 2d 2f 03 00 00 4f 8b 00 03 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 83 ea 0a 39 55 f4 74 ?? 0f b7 05 ?? ?? ?? ?? 2b 45 08 0f b7 4d f4 03 c1 89 45 08}  //weight: 1, accuracy: Low
        $x_1_3 = {83 d6 00 0f b6 05 ?? ?? ?? ?? 99 03 c8 13 f2 89 0d ?? ?? ?? ?? 8a 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GN_2147654555_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GN"
        threat_id = "2147654555"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 3c 8b 7c 06 78 03 fe 8b 4f 18 8b 5f 20 03 de e3 ?? 49 8b 04 8b 03 c6 56 57 8b f0 33 ff 33 c0 ac 85 c0 74 07 c1 cf ?? 03 f8 eb f4 8b c7 5f 5e [0-6] 75 ?? 8b 47 24 03 c6 66 8b 0c 48 8b 47 1c 03 c6 8b 04 88 03 c6 eb 02 33 c0 89 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GN_2147654555_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GN"
        threat_id = "2147654555"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 08 8b 46 3c 8b 7c 06 78 03 fe 8b 4f 18 8b 5f 20 03 de e3 38 49 8b 04 8b 03 c6 56 57 8b f0 33 ff 33 c0 ac 85 c0 74 07 c1 cf 04 03 f8 eb f4 8b c7 5f 5e 3b 45 0c 75 db 8b 47 24 03 c6 66 8b 0c 48 8b 47 1c 03 c6 8b 04 88 03 c6 eb 02 33 c0 89 45 fc 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 48 10 89 0d ?? ?? ?? ?? 8b 00 8b 48 10 89 0d ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GP_2147654602_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GP"
        threat_id = "2147654602"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 70 28 68 00 00 40 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {ff 70 34 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 00 68 00 30 00 00 8b 85 e0 cf ff ff ff 70 50}  //weight: 1, accuracy: Low
        $x_1_3 = {07 00 01 00 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 09 33 c8 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 88 08 8b 85 ?? ?? ?? ?? 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_DC_2147654614_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.DC"
        threat_id = "2147654614"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vmware" ascii //weight: 1
        $x_1_2 = "OLLYDBG" ascii //weight: 1
        $x_1_3 = "icu_dbg" ascii //weight: 1
        $x_1_4 = {03 01 8b ce 99 f7 f9 8a 84 95 ?? ?? ff ff 30 03 ff 45 10 8b 45 10 3b 45 0c 7c 9e}  //weight: 1, accuracy: Low
        $x_1_5 = {07 00 01 00 06 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_6 = "PROCMON_WINDOW_CLASS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GO_2147654679_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GO"
        threat_id = "2147654679"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 28 57 03 45 f4 89 87 b0 00 00 00 ff 75}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 8b c8 81 e1 ff 07 00 00 8a 89 ?? ?? ?? ?? 00 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 e4}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0c 02 8d 34 02 8a 83 ?? ?? ?? ?? 22 c2 f6 d1 32 c1 83 c9 ff 88 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GQ_2147654684_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GQ"
        threat_id = "2147654684"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 31 32 d0 88 14 31 41 3b cf 7e e4}  //weight: 1, accuracy: High
        $x_1_2 = {81 cb 00 ff ff ff 43 8a 9c 9d ?? ?? ff ff 8b 7d ?? 30 1c 02 42 3b d7 72}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 00 e9 8b 16 42 8b c2 89 16 2b d8 8d 54 3b fc}  //weight: 1, accuracy: High
        $x_1_4 = {66 8b 41 06 83 c3 28 3b f8 7c af a1 ?? ?? ?? ?? 6a 00 8b 50 3c 03 d3 8d 84 32 f8 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_GR_2147654724_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GR"
        threat_id = "2147654724"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 51 34 89 55 ?? 8b 45 ?? 8b 48 50 89 4d ?? 6a 40 68 00 30 00 00 8b 55 02 52 8b 45 00 50}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 42 34 89 45 ?? 8b 0d ?? ?? ?? ?? 8b 51 50 89 55 ?? 6a 40 68 00 30 00 00 8b 45 02 50 8b 4d 00 51}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 51 34 89 55 ?? a1 ?? ?? ?? ?? 8b 48 50 89 4d ?? 6a 40 68 00 30 00 00 8b 55 02 52 8b 45 00 50 8b 0d ?? ?? ?? ?? 51}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c2 50 52 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c [0-32] 6a 40 68 00 30 00 00 (8b 0d ?? ?? ?? ?? 51 8b 15 ?? ?? ?? ?? 52 a1 ?? ?? ?? ??|a1 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 8b 15 ?? ?? ?? ??) 6a 05}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c0 50 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c [0-32] 6a 40 68 00 30 00 00 8b 15 ?? ?? ?? ?? 52 a1 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 6a 05}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 40 68 00 30 00 00 57 ff b5 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? ff d0 a1 ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 33 db 53 ff 70 54 56 ff 70 34}  //weight: 1, accuracy: Low
        $x_1_7 = {68 00 00 40 00 ff 75 ?? ff 55 ?? 89 45 ?? 85 c0 0f 88 ?? ?? ?? ?? 8b 46 34 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {83 c2 34 52 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 6a 04 a1 ?? ?? ?? ?? 83 c0 50 50 68 ?? ?? ?? ?? [0-72] 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
        $x_1_9 = {07 00 01 00 06 00 [0-4] c7}  //weight: 1, accuracy: Low
        $x_1_10 = {83 00 01 00 6a 04 8d 45 ?? 50 68 ?? ?? ?? ?? e8 06 00 [0-4] c7}  //weight: 1, accuracy: Low
        $x_1_11 = {0f b7 42 06 39 85 ?? ?? ?? ?? 7d 66 8b 0d ?? ?? ?? ?? 8b 51 3c 8b 85 00 6b c0 28 03 45 ?? 8d 8c 10 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_12 = {0f b7 51 06 39 55 ?? 7d ?? a1 ?? ?? ?? ?? 8b 48 3c 8b 55 00 6b d2 28 03 55 ?? 8d 84 0a f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_13 = {0f b7 48 06 39 4d ?? 7d ?? 8b 55 00 6b d2 28 a1 ?? ?? ?? ?? 8b 48 3c 03 55 ?? 8d 94 0a f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_14 = {0f b7 42 06 39 45 ?? 7d 60 8b 0d ?? ?? ?? ?? 8b 51 3c 8b 45 00 6b c0 28 03 45 ?? 8d 8c 10 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_15 = {0f b7 48 06 39 4d ?? 7d ?? 8b 15 ?? ?? ?? ?? 8b 42 3c 8b 4d ?? 6b c9 28 03 4d ?? 8d 94 01 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_16 = {0f b7 42 06 39 45 ?? 7d ?? 8b 4d 00 6b c9 28 8b 15 ?? ?? ?? ?? 8b 42 3c 03 4d ?? 8d 8c 01 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_17 = {66 3b 48 06 73 ?? 8b 0d ?? ?? ?? ?? 8b 49 3c 03 cb 8d 8c 31 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_18 = {83 c2 01 89 55 ?? 0f b7 45 ?? 39 45 00 7d ?? 8b 4d 00 6b c9 28 8b 15 ?? ?? ?? ?? 8b 42 3c 03 4d ?? 8d 8c 01 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_19 = {83 c2 01 89 95 ?? ?? ?? ?? 0f b7 45 ?? 39 85 00 7d ?? 8b 8d 00 6b c9 28 8b 15 ?? ?? ?? ?? 8b 42 3c 03 4d ?? 8d 8c 01 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_20 = {0f b7 46 06 ff 45 ?? 83 45 ?? 28 39 45 ?? 8b 7d ?? 8b 45 ?? 8b 4f 3c 03 c7 8d bc 08 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_21 = {83 c1 01 89 8d ?? ?? ?? ?? 0f b7 55 ?? 39 95 00 7d ?? 8b 85 00 6b c0 28 8b 0d ?? ?? ?? ?? 8b 51 3c 03 45 ?? 8d 84 10 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_22 = {83 c0 01 89 85 ?? ?? ?? ?? 0f b7 4d ?? 39 8d ?? ?? ?? ?? 7d 65 8b 95 ?? ?? ?? ?? 6b d2 28 a1 ?? ?? ?? ?? 8b 48 3c 03 55 ?? 8d 94 0a f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_23 = {33 d0 8b 45 08 03 45 f8 88 10 8b 4d 08 03 4d f8 0f b6 11 83 c2 (07|08|12)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_DD_2147655117_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.DD"
        threat_id = "2147655117"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 49 0c 8a 04 01 2c ?? 34 ?? 3c}  //weight: 10, accuracy: Low
        $x_1_2 = {8b 4d fc 66 8b 09 b8 ?? ?? 00 00 [0-16] 66 2b c8 [0-112] b8 ?? ?? 00 00 66 33 c8 b8 ?? ?? 00 00 66 3b c8 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d fc 66 8b 09 b8 ?? ?? 00 00 66 2b c8 b8 ?? ?? 00 00 66 33 c8 66 3b cb 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_DF_2147655364_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.DF"
        threat_id = "2147655364"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 02 66 c1 e8 0c 66 25 0f 00 25 ff ff 00 00 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff 04 0f 87 ?? ?? 00 00 8b 8d ?? ?? ff ff ff 24 8d ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 b8 8c 00 00 00 00 0f 84}  //weight: 1, accuracy: High
        $x_1_3 = {83 ba 8c 00 00 00 00 0f 84}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4d 08 03 48 10 89 4d}  //weight: 1, accuracy: High
        $x_1_5 = {8b 42 3c 8b 4d 08 8d 54 01 18}  //weight: 1, accuracy: High
        $x_1_6 = {8b 51 10 52 8b 45 ?? 8b 4d 08 03 48 14 51 8b 55 ?? 8b 45 0c 03 42 0c 50 (e8|ff)}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 48 10 51 8b 55 ?? 8b 45 08 03 42 14 50 8b 4d ?? 8b 55 0c 03 51 0c 52 (e8|ff)}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 51 38 81 c2 00 10 00 00 52 6a 00 6a 04 6a 00 6a ff ff 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_9 = {8a 1c 10 03 cb 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41}  //weight: 1, accuracy: High
        $x_1_10 = "MapViewOfFileEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule VirTool_Win32_CeeInject_DG_2147655500_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.DG"
        threat_id = "2147655500"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 54 18 78 56 8b 32 03 f3 8b 46 24 8b 4e 1c 03 c3 89 45 ?? 8b 46 20}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 04 88 03 c3 50 ff 75 ?? e8 ?? ?? ?? 00 59 59 85 c0 75 ?? 8b 4d ?? 8b 45 ?? 0f b7 04 48 8b 4d ?? 8b 3c 81}  //weight: 1, accuracy: Low
        $x_1_3 = "%s%s%s%s%s%s" ascii //weight: 1
        $x_1_4 = {6a 07 33 c0 89 55 ?? 5a c6 45 ?? 00 8b ca 8d 7d ?? f3 ab 66 ab aa 33 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 70 10 8b 50 14 8b 40 0c 03 41 34 03 d7 52 50 ff 75 ?? ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GT_2147655851_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GT"
        threat_id = "2147655851"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 28 01 d0 a3}  //weight: 1, accuracy: High
        $x_1_3 = {8b 40 34 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 40 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GU_2147656427_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GU"
        threat_id = "2147656427"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 07 00 c7 84 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 16 8b 07 6a 40 68 00 30 00 00 51 52 50 ff 94 24}  //weight: 1, accuracy: High
        $x_1_3 = {03 51 3c 89 55 ?? 8b 45 00 0f b7 48 06 89 4d ?? 8b 55 00 81 c2 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 48 3c 03 c8 0f b7 51 06 8d 81 f8 00 00 00 8d 4a ff 3b cf 76 05 6b c9 28 03 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_GV_2147656670_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GV"
        threat_id = "2147656670"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 8b 45 ?? 8b 48 50 51 8b 55 ?? 8b 42 34}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 8b 95 ?? ff ff ff 83 c2 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GX_2147657214_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GX"
        threat_id = "2147657214"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 8b 95 ?? ?? ?? ?? 8b 42 50 89 44 24 ?? 8b 42 34 89 44 24 ?? 8b 45 ?? 89 04 24 ff 95}  //weight: 1, accuracy: Low
        $x_1_2 = {07 00 01 00 02 00 c7}  //weight: 1, accuracy: Low
        $x_1_3 = {66 83 7a 06 00 0f 84 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 00 00 00 00 c7 85 ?? ?? ?? ?? 00 00 00 00 89 bd ?? ?? ?? ?? 8b bd ?? ?? ?? ?? 8b 46 3c 8d 9c 07 f8 00 00 00 03 9d 01}  //weight: 1, accuracy: Low
        $x_1_4 = {03 78 28 8b 95 ?? ?? ?? ?? 89 ba b0 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_GY_2147657237_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GY"
        threat_id = "2147657237"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 56 50 8b 46 34 8b 8d ?? ?? ?? ?? 6a 40 68 00 30 00 00 52 50 51 ff 95}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 84 38 f8 00 00 00 8b 40 0c 03 46 34 6a 00 51 8b 8d ?? ?? ?? ?? 03 d7 52 50 51 ff 95 ?? ?? ?? ?? 0f b7 56 06 83 85 ?? ?? ?? ?? 28}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 4d 08 8a 55 24 30 14 01 8b 4d 08 39 5d 1c 73 03 8d 4d 08 8a 55 28 30 14 01 8b 4d 08 39 5d 1c 73 03 8d 4d 08 8a 55 2c 30 14 01 40 3b 45 18 72 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GZ_2147657554_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!GZ"
        threat_id = "2147657554"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3e 8b 48 3c a1 [0-32] 36 03 04 24 [0-16] 3e 0f b7 40 06 83 f8 ?? 74 01 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 54 32 ff 33 d3 88 54 30 ff 4b 85 db 75 ?? 46 4f 75 ?? be ?? ?? ?? ?? b8 ?? ?? ?? ?? bb ?? ?? ?? ?? 30 18 4b 85 db 75 f9 40 4e 75 f0 8d 05 [0-16] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HA_2147657649_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HA"
        threat_id = "2147657649"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 fc 88 10 eb 45 8b 45 fc 99 b9 03 00 00 00 f7 f9 85 d2 74 1c 8b 15 ?? ?? ?? ?? 03 55 fc 0f be 02 83 f0 47 8b 0d 00 03 4d fc 88 01 eb 1a 8b 15 00 03 55 fc 0f be 02 83 f0 42 8b 0d 00 03 4d fc 88 01 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HB_2147657696_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HB"
        threat_id = "2147657696"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 34 03 48 28}  //weight: 1, accuracy: High
        $x_1_2 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 30 00 00 ff 70 50 ff 70 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HC_2147657826_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HC"
        threat_id = "2147657826"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff 76 54 03 c7 50 ff 76 34}  //weight: 1, accuracy: High
        $x_1_3 = {03 46 34 89 85 09 00 [0-6] 8b 46 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HD_2147658214_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HD"
        threat_id = "2147658214"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 b9 03 00 00 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8a 8c 8d ?? ?? ?? ?? 30 0c 1a 99 6a 03 59 f7 f9 6a 05 59 99 f7 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 8d 4c fe ff ff 03 8d 58 fe ff ff 89 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HE_2147658283_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HE"
        threat_id = "2147658283"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 57 28 53 03 d5 89 93 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 03 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 47 50 8b 4f 34 8b 54 24 ?? 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HF_2147658489_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HF"
        threat_id = "2147658489"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 9d a4 00 00 00 83 c3 08}  //weight: 1, accuracy: High
        $x_1_3 = {8b 5d 34 03 5d 28 53 8d ac 24 ?? ?? ?? ?? 58 89 85 b0 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_DZ_2147659413_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.DZ"
        threat_id = "2147659413"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 20 dc 41 00 30 1c 30 83 c4 08 83 ee 01 0f 85 6b ff ff ff ff 15 20 dc 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HG_2147659894_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HG"
        threat_id = "2147659894"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f bf 5d 06 4b 3b 9c 24 ?? ?? ?? ?? 0f 8c ?? ?? ?? ?? 68 28 00 00 00 8b 9c 24 ?? ?? ?? ?? 8d 6c 24 ?? 8b 7d 3c 8b b4 24 ?? ?? ?? ?? 6b f6 28 01 f7 81 c7 f8 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 5d 34 03 5d 28 53 8d ac 24 ?? ?? ?? ?? 58 89 85 b0 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {89 e8 01 f0 89 c5 8a 26 8a 07 88 c3 88 e7 30 df 88 3e 41 46 47 39 ee 7d 0c}  //weight: 1, accuracy: High
        $x_1_4 = {00 36 35 35 34 33 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_HH_2147660274_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HH"
        threat_id = "2147660274"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 8d 6c fe ff ff 03 8d 78 fe ff ff 89 8d 24 fc ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 85 5c fe ff ff 03 85 68 fe ff ff 89 85 14 fc ff ff}  //weight: 1, accuracy: High
        $x_2_3 = {b8 58 59 59 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_HI_2147660314_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HI"
        threat_id = "2147660314"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 34 03 48 28}  //weight: 1, accuracy: High
        $x_1_3 = {8b 50 34 8b ?? ?? ?? ?? ?? 33 f6 56 68 00 30 00 00 ff 70 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HJ_2147661039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HJ"
        threat_id = "2147661039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 51 34 a1 ?? ?? ?? ?? 03 50 28 89 15}  //weight: 1, accuracy: Low
        $x_1_2 = {07 00 01 00 06 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 30 00 00 a1 ?? ?? ?? ?? 8b 48 50 51 8b 15 ?? ?? ?? ?? 8b 52 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HL_2147661239_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HL"
        threat_id = "2147661239"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 04 24 ff d5 83 ec 28 85 c0 0f 84 ?? ?? 00 00 c7 44 24 0c 04 00 00 00 c7 44 24 08 00 10 00 00 c7 44 24 04 04 00 00 00 c7 04 24 00 00 00 00 ff 54 24 ?? 83 ec 10 a3 ?? ?? ?? ?? c7 00 07 00 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HL_2147661239_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HL"
        threat_id = "2147661239"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f a2 0f 31 [0-10] 0f a2 0f 31 [0-8] 29 f8 29 f2 89 45 fc 89 55 f8 83 7d fc 06 [0-48] 81 7d fc 56 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c9 74 06 30 17 49 47 eb f6 59 0c 00 00 00 00 ba ?? 00 00 00 8b 7c 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HL_2147661239_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HL"
        threat_id = "2147661239"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 00 85 fb 8b 7c 24 0c 85 fb 83 ef 06 85 fb 85 c9 74 ?? 85 fb 30 17 85 fb 49 85 fb 4f 85 fb eb ee 07 00 b9 ?? ?? 00 00 ba}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7c 24 0c 90 90 83 ef 06 90 90 85 c9 74 10 90 90 30 17 90 90 49 90 90 4f 90 90 eb ee 0c 00 b9 ?? ?? 00 00 ba ?? ?? ?? ?? 90 90}  //weight: 1, accuracy: Low
        $x_1_3 = {84 e8 8b 7c 24 0c 84 e8 83 ef 06 84 e8 85 c9 74 10 84 e8 30 17 84 e8 49 84 e8 4f 84 e8 eb ee 0a 00 b9 ?? ?? 00 00 ba}  //weight: 1, accuracy: Low
        $x_1_4 = {84 f1 8b 7c 24 10 84 f1 85 c9 74 ?? 84 f1 30 17 84 f1 49 84 f1 47 84 f1 eb ee 0c 00 b9 ?? 00 00 00 84 f1 ba}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 7c 24 0c 90 90 85 c9 74 ?? 90 90 90 90 30 17 90 90 49 90 90 47 90 90 eb ec 0e 00 b9 ?? 00 00 00 90 90 ba}  //weight: 1, accuracy: Low
        $x_1_6 = {84 f1 8b 7c 24 10 84 f1 83 ef 08 84 f1 85 c9 74 10 84 f1 30 17 84 f1 49 84 f1 4f 84 f1 eb ee}  //weight: 1, accuracy: High
        $x_1_7 = {57 52 51 b9 ?? ?? 00 00 ba ?? ?? ?? ?? 8b 7c 24 10 83 ef 08 85 c9 74 06 30 17 49 4f eb f6 59 5a 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_HL_2147661239_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HL"
        threat_id = "2147661239"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 08 8b 45 08 69 c0 ?? ?? ?? ?? 29 03 01 01 01 c1 c2 c3 89 03 01 01 01 c8 d0 d8 89 45 08}  //weight: 1, accuracy: Low
        $x_1_2 = {00 48 00 00 eb ba ?? ?? 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c0 eb 05 ?? ?? ?? ?? ?? 74 ?? eb 30 ?? eb 48 eb (42|47) eb}  //weight: 1, accuracy: Low
        $x_1_4 = {85 db eb 05 ?? ?? ?? ?? ?? 74 ?? eb 30 ?? eb 4b eb 03 01 01 01 42 46 47 eb}  //weight: 1, accuracy: Low
        $x_1_5 = {85 f6 eb 05 ?? ?? ?? ?? ?? 74 ?? eb 30 ?? eb 4e eb 04 01 01 01 01 41 42 46 47 eb}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 00 eb da a1 ?? ?? ?? ?? ff d0 0e 00 30 18 b8 ?? ?? ?? ?? ff 08 b8}  //weight: 1, accuracy: Low
        $x_1_7 = {0f a2 0f 31 [0-5] 89 c6 [0-5] 89 d7 [0-5] 0f a2 0f 31 [0-5] 29 f0 [0-5] 29 fa [0-5] 89 45 fc [0-5] 89 55 f8 [0-5] 5f [0-5] 5e [0-5] 81 7d fc}  //weight: 1, accuracy: Low
        $x_1_8 = {0f a2 0f 31 [0-2] (50|52) [0-2] (52|50) [0-2] 0f a2 [0-2] 0f 31}  //weight: 1, accuracy: Low
        $x_1_9 = {0f a2 0f 31 [0-8] [0-6] [0-8] 50 [0-8] [0-4] 0f a2}  //weight: 1, accuracy: Low
        $x_1_10 = {0f a2 0f 31 [0-4] 52 50 [0-4] 0f a2 0f 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_HN_2147662128_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HN"
        threat_id = "2147662128"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 56 28 03 56 34 8b 0d ?? ?? ?? ?? 8d 44 24 ?? 50 51}  //weight: 1, accuracy: Low
        $x_1_2 = {07 00 01 00 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 46 50 8b 4e 34 8b 15 ?? ?? ?? ?? 6a 00 68 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HO_2147662222_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HO"
        threat_id = "2147662222"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 02 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 50 8b 50 34 6a 40 68 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 48 28 03 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 89 8a b0 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HP_2147662670_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HP"
        threat_id = "2147662670"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 57 68 00 30 00 00 ff 76 50 ff 76 34 ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 4e 06 3b c1 72 0b 00 a1 ?? ?? ?? ?? 40 a3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 46 28 03 46 34 89 (84 24 ?? ?? ?? ??|45 ??) 8d (44 24|45)}  //weight: 1, accuracy: Low
        $x_1_4 = {33 db 53 68 00 30 00 00 ff 76 50 e8 ?? ?? ?? ?? 53 ff 76 54 57 ff 76 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_HQ_2147663069_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HQ"
        threat_id = "2147663069"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 56 68 00 30 00 00 ff 70 50 ff 70 34 ff (75 ??|35 ?? ?? ?? ??) e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 48 06 39 0d ?? ?? ?? ?? 72 0b 00 ff 05 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 51 06 3b c2 7c 11 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 40 a3}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 48 34 03 48 28 8d (45 ??|85 ?? ?? ?? ??) 50 ff 75 ?? 89 (4d|8d)}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 48 34 03 48 28 8d 44 24 ?? 50 ff 35 ?? ?? ?? ?? 89 8c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_HR_2147663070_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HR"
        threat_id = "2147663070"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 00 30 00 00 8b 45 ?? 8b 48 50 51 8b 55 ?? 8b 52 34 8b 4d ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 01 a3 ?? ?? ?? ?? 8b 4d ?? 0f b7 51 06 39 15 ?? ?? ?? ?? 73 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 42 34 8b 4d ?? 03 41 28 89 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HS_2147663074_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HS"
        threat_id = "2147663074"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 50 8b 50 34 8b 44 24 ?? 6a 00 68 00 30 00 00 51 52 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 01 a3 ?? ?? ?? ?? 0f b7 51 06 3b c2 72}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 50 34 03 50 28 8b 4c 24 ?? 8d 44 24 ?? 50 51 89 94 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HU_2147663165_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HU"
        threat_id = "2147663165"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 50 8b 4e 34 8b 15 ?? ?? ?? ?? 6a 00 68 00 30 00 00 50 51 52 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 56 06 3b c2 72 0b 00 a1 ?? ?? ?? ?? 40 a3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 56 28 8b 7e 34 8b 0d ?? ?? ?? ?? 8d 44 24 ?? 50 03 d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HV_2147663255_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HV"
        threat_id = "2147663255"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 70 40 00 00 c7 44 24 04 05 2d 31 01 c7 04 24 89 46 46 47 e8}  //weight: 1, accuracy: High
        $x_1_2 = {85 d8 30 17 85 d8 49 85 d8 47 85 d8 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HW_2147663264_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HW"
        threat_id = "2147663264"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 50 ff 75 08 68 6e 1c 04 45 e8 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 59 ff d0 5e 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {68 12 ba 0c c3 e8 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 59 a3 ?? ?? ?? ?? 5e ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 4d fc 83 45 f8 03 8b f1 c1 ee 02 8a 1c 3e 0f b6 75 fd 88 1a 83 e1 03 8b de c1 e1 04 c1 eb 04 0b d9 8a 0c 3b 88 4a 01 83 f8 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_HX_2147663282_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HX"
        threat_id = "2147663282"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4e 50 8b 56 34 6a 00 68 00 30 00 00 51 8b 4c 24 ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 4e 06 3b c1 72 0b 00 a1 ?? ?? ?? ?? 40 a3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4e 28 8b 7e 34 8b 44 24 ?? 8d 54 24 ?? 52 03 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_HZ_2147663909_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!HZ"
        threat_id = "2147663909"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 75 ?? ff 75 ?? ff 75 ?? ff d0 a1 ?? ?? ?? ?? 33 f6 56 ff 70 54 53 ff 70 34 ff 35 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 48 06 ff 05 ?? ?? ?? ?? 39 0d 00 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 48 34 03 48 28 8d 85 ?? ?? ?? ?? 50 ff 35 ?? ?? ?? ?? 89 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 70 50 ff 70 34 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? [0-4] 33 f6 56 ff 70 54 53 ff 70 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_IA_2147664333_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IA"
        threat_id = "2147664333"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 56 50 8b 46 34 8b 8d ?? ?? ?? ?? 6a 40 68 00 30 00 00 52 50 51 ff 95}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 56 06 83 85 ?? ?? ?? ?? 28 43 3b da 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 46 28 03 46 34 8b 95 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 51 52 89 85}  //weight: 1, accuracy: Low
        $x_1_4 = {ff ff 02 00 01 00 04 00 c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_IE_2147664395_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IE"
        threat_id = "2147664395"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8a 40 02 88 85 ?? ?? ff ff 8b 85 ?? ?? ff ff 25 ff 00 00 00 85 c0 74 11 8b f4 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 01 8d 45 fc 50 8b 0d ?? ?? ?? ?? 51 8b fc ff 15 ?? ?? ?? ?? 3b fc e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b 55 fc 81 e2 ff 00 00 00 81 fa e9 00 00 00 75 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_IG_2147664915_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IG"
        threat_id = "2147664915"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 02 32 d1 3d ?? ?? 00 00 88 90 ?? ?? 40 00 76 e8 33 c0 8a 88 ?? ?? 40 00 40 f6 d1 88 88 ?? ?? 40 00 3d ?? ?? 00 00 76 ea 8a 15 ?? ?? 40 00 b9 01 00 00 00 b8 ?? ?? 40 00 8a 18 83 c1 02 32 da 88 18 83 c0 02 81 f9 ?? ?? 00 00 76 ec 33 c0 b1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_IH_2147665351_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IH"
        threat_id = "2147665351"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ?? ?? 8b 40 50 50 8b 85 ?? ?? ?? ?? 8b 40 34}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 34 8b 95 ?? ?? ?? ?? 03 42 28 89 85}  //weight: 1, accuracy: Low
        $x_1_3 = {07 00 01 00 06 00 c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_IJ_2147665820_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IJ"
        threat_id = "2147665820"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ff ff 8b 48 50 51 8b 95 ?? ?? ff ff 8b 42 34 50 8b 8d ?? ?? ff ff 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 66 8b 48 06 39 8d ?? ?? ff ff 7d}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 8b 51 34 8b 85 ?? ?? ff ff 03 50 28 89 95 ?? ?? ff ff 04 00 8b 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_IK_2147666755_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IK"
        threat_id = "2147666755"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 41 54 41 54 41 54 41 23 52 40 23 33 72 32 69 33 30 72 69 32 33 30 69 66 30 69 33 30 32 69 30 33 32 66 6b 77 30 66 6b 52 54 00}  //weight: 1, accuracy: High
        $x_10_2 = {77 44 62 6e 6b 6b 40 6b 60 74 73 71 68 55 00 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 10, accuracy: High
        $x_10_3 = {8a 84 14 e4 03 00 00 fe c0 88 01 41 83 ea 01 79 ef 83 ef 01 8b 0e 8b 56 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_IL_2147667051_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IL"
        threat_id = "2147667051"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8d 4d ?? 51 89 55 ?? 8b 40 0d 6a 00 8d 55 ?? 89 45 ?? 8b 45 ?? 52 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 8d 41 08 50 0f b6 42 02 50 8b 01 8d 51 04 52 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {5a 77 53 65 74 43 6f 6e 74 65 78 74 54 68 72 65 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_EW_2147667548_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.EW"
        threat_id = "2147667548"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 78 3a 5c 77 65 72 64 6f 6e 2e 70 64 62 00}  //weight: 2, accuracy: High
        $x_1_2 = {00 66 6f 72 73 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 37 9e c7 45 03 00 c7 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_IN_2147667647_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IN"
        threat_id = "2147667647"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Krypton\\Krypton_7.1\\Bin\\Stub" ascii //weight: 1
        $x_1_2 = {4e 74 57 72 69 74 65 56 69 00 00 [0-16] 5a 77 50 72 6f 74 65 63 74 56 69 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 70 54 ff 75 ?? ff b5 ?? ?? ff ff ff b5 ?? ?? ff ff ff 55 ?? 85 c0 0f 8c 04 00 50 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_IO_2147670566_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IO"
        threat_id = "2147670566"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 8b 1d 30 00 00 00 8b 5b 0c 8b 5b 14 8b 1b 8b 1b 8b 5b 10}  //weight: 10, accuracy: High
        $x_1_2 = {03 d6 52 50 51 ff 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 0f b7 53 06 ff 0d ?? ?? ?? ?? 83 85 ?? ?? ff ff 28}  //weight: 1, accuracy: Low
        $x_1_3 = {52 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 8b 45 08 50 ff 95 ?? ?? ff ff 85 c0 0f 84}  //weight: 1, accuracy: Low
        $x_1_4 = {50 57 57 6a 04 57 57 57 57 ff b5 ?? ff ff ff ff 95 ?? ff ff ff 85 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 00 07 00 01 00 8b 95 ?? ?? ff ff 50 52 [0-10] ff 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_IP_2147670831_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IP"
        threat_id = "2147670831"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 28 03 85 ?? ?? ff ff 8b b5 ?? ?? ff ff 89 86 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 80 a4 00 00 00 6a 00 6a 04 ff b5 ?? ff ff ff 83 c0 08}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 00 07 00 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_IQ_2147676005_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IQ"
        threat_id = "2147676005"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 51 3c 8b 45 ?? 6b c0 28 03 45 08 8d 8c 10 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {03 41 28 a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 52 ff 55 ?? a1 02 50 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_IS_2147678617_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IS"
        threat_id = "2147678617"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 14 83 e9 70 83 c4 10 89 4d f8 33 c0 b1 ?? 30 88 ?? ?? ?? ?? 40 83 f8 ?? 7c f4 8b 45 f4 50 05 ff 0f 00 00 03 45 f8 8d 35 01 ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 45 f0 2d dc 07 00 00 d0 e0 33 c9 (04|2c) ?? 8b 15 ?? ?? ?? ?? 30 04 0a 41 83 f9 5a 7c f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_IW_2147679574_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IW"
        threat_id = "2147679574"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 0f a2 3d 00 00 00 80 04 00 b8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c2 41 88 10 39 f0 75 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8a 04 11 30 04 37 46}  //weight: 1, accuracy: High
        $x_1_4 = {00 52 65 73 75 6d 65 54 68 72 65 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_IX_2147679613_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IX"
        threat_id = "2147679613"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f bf 5d 06 4b 3b ?? ?? ?? ?? ?? 0f 8c ?? ?? 00 00 ff 35 ?? ?? ?? ?? 68 28 00 00 00 8b 1d ?? ?? ?? ?? 8d 2d ?? ?? ?? ?? 8b 7d 3c 8b 35 ?? ?? ?? ?? 6b f6 28 01 f7 81 c7 f8 00 00 00 (01|11) fb 53}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 0c ff 75 08 e8 ?? ?? ?? ?? 85 c0 74 13 ff 75 20 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff d0 eb 02 33 c0 5d c2 1c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 18 89 c3 8b 2d ?? ?? ?? ?? 0f bf 45 14 01 c3 89 1d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 8b 2d ?? ?? ?? ?? 0f bf 5d 06 4b 3b 1d ?? ?? ?? ?? 0f 8c ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_IX_2147679613_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IX"
        threat_id = "2147679613"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 67 66 66 66 f7 eb c1 fa 02 8b cb 8b da}  //weight: 1, accuracy: High
        $x_1_2 = {ff 75 0c ff 75 08 e8 ?? ?? ?? ?? 85 ?? 74 22 ff 75 34 ff 75 30 ff 75 2c ff 75 28 ff 75 24 ff 75 20 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff d0 eb 02 33 c0 5d c2 30 00}  //weight: 1, accuracy: Low
        $x_1_3 = {31 fb 8b 7c 24 ?? 31 fb 8b 7c 24 04 6b ff 03 8b 74 24 04 01 f6 29 f7 31 fb 8b 7c 24 ?? 31 fb 89 d8 88 44 24 ?? 0f be 44 24 ?? 50 8b 5c 24 ?? 03 5c 24 ?? 89 d8 e8 ?? ?? ?? ?? ff 44 24 ?? 8b 5c 24 ?? 3b 5c 24 ?? 7e 08 c7 44 24 ?? 00 00 00 00 ff 44 24 ?? 0f 81 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {0f bf 5d 06 4b 3b ?? ?? ?? ?? ?? 0f 8c ?? ?? 00 00 ff 35 ?? ?? ?? ?? 68 28 00 00 00 8b 1d ?? ?? ?? ?? 8d 2d ?? ?? ?? ?? 8b 7d 3c 8b 35 ?? ?? ?? ?? 6b f6 28 01 f7 81 c7 f8 00 00 00 01 fb 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_IZ_2147679962_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!IZ"
        threat_id = "2147679962"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 17 d3 e0 31 d0 01 e8 0f b6 db 31 d8 88 c3 88 06 42 39 54 24 ?? 77 e6 89 e8 31 d2 f7 74 24 ?? 32 1c 17 88 1e 45 46 39 6c 24 ?? 77}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 17 d3 e0 31 d0 03 45 ?? 0f b6 db 31 d8 88 c3 88 06 42 39 55}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 00 07 00 01 00 89 44 24 ?? a1 ?? ?? ?? ?? 89 04 24 ff (54 24|55)}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c5 28 0f b7 50 06 39 fa 7f ?? 81 ff 0c 06 00 00 75}  //weight: 1, accuracy: Low
        $x_1_5 = {66 83 78 06 00 0f 84 ?? 00 00 00 31 c0 31 ff 89 75 ?? 89 de 89 c3 90 8b 46 3c 8d 94 06 f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3c 79 0f 84 ?? ?? ff ff 3c 59 0f 84 ?? ?? ff ff 3c 6e 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_JA_2147679995_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JA"
        threat_id = "2147679995"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f a2 0f 31 89 d6 50 90 85 c0 0f a2 0f 31 5f 29 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_JB_2147680017_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JB"
        threat_id = "2147680017"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d c8 10 27 00 00 0f 86 fd 00 00 00 c7 45 c0 ?? ?? ?? ?? ff 75 fc c7 45 bc 00 30 00 00 8b 85 78 ff ff ff 8b 4d ec 89 08 c7 85 50 ff ff ff 00 00 00 00 8f 45 fc ba 20 00 00 00 83 c2 20 b9 00 0b 00 00 52 81 c1 00 05 00 00 8b c1 50 c7 45 fc fb ff 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 43 61 72 64 49 6e 74 72 6f 64 75 63 65 43 61 72 64 54 79 70 65 57 00 57 69 6e 73 63 61 72 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_JC_2147680114_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JC"
        threat_id = "2147680114"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 7d f8 03 0f 8d 9a 00 00 00 c7 45 f4 00 00 00 00 eb 09 8b 55 f4 83 c2 01 89 55 f4 83 7d f4 06 7d 38 00 [0-24] 0f be 88 ?? ?? 41 00 8b 55 fc 83 c2 01 (81|83) [0-5] 2b ca 8b 45 fc 88 88}  //weight: 2, accuracy: Low
        $x_2_2 = {81 7d fc da 25 00 00 0f 84 ?? 00 00 00 8b 45 fc 0f be 88 ?? ?? ?? ?? 8b 55 fc 83 c2 01 (81|83) [0-5] 2b ca 8b 45 fc 88 88 ?? ?? ?? ?? c7 45 f8 ?? ?? ?? ?? eb 18 8b 4d f8 0f be 11}  //weight: 2, accuracy: Low
        $x_1_3 = {00 68 6f 6d 65 77 6f 72 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_JF_2147680278_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JF"
        threat_id = "2147680278"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 45 f2 74 00 66 c7 45 f4 2e 00 66 c7 45 f6 78 00 8b}  //weight: 1, accuracy: High
        $x_1_2 = {0f 31 89 c3 0f 31 29 d8 77 fa}  //weight: 1, accuracy: High
        $x_1_3 = {89 55 f0 1e 8d 45 f0 0f a9 65 ff 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_JG_2147680356_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JG"
        threat_id = "2147680356"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d f8 0f be 11 52 e8 ?? ?? ?? 00 83 c4 04 8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 0f be 11 83 fa 21 74 ?? eb}  //weight: 2, accuracy: Low
        $x_1_2 = "Hello, World!" ascii //weight: 1
        $x_1_3 = {54 6f 74 61 6c 3a 20 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_JH_2147680380_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JH"
        threat_id = "2147680380"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 11 52 e8 ?? ?? ?? ?? 83 c4 04 8b ?? ?? ?? ?? ?? 83 c0 01 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 0f be 11 83 fa 21 74 02 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 11 52 e8 ?? ?? ?? ?? 83 c4 04 8b ?? ?? 83 c0 01 89 ?? ?? 8b ?? ?? 0f be 11 83 fa 21 74 02 eb}  //weight: 1, accuracy: Low
        $x_2_3 = {75 73 61 00 (48 65 6c 6c 6f 2c 20 57 6f 72 6c 64|54 6f 74 61 6c 3a 20 25 64)}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_JI_2147680388_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JI"
        threat_id = "2147680388"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 8b 00 00 00 74 11 8b 45 ?? 03 05 ?? ?? ?? ?? 0f b6 00 83 f8 55 75 28 8b 45 ?? 03 05 ?? ?? ?? ?? 0f b6 00 8b 4d ?? 0f b6 89 ?? ?? ff ff 2b c1}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 09 0f b6 00 8b 04 85 ?? ?? ?? ?? 8a 00 8b 0d ?? ?? ?? ?? 03 ce a2 ?? ?? ?? ?? 30 01 ff 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_JJ_2147681162_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JJ"
        threat_id = "2147681162"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ee 6e 8b 06 8b f0 c1 e6 10 66 33 f6 68 ?? ?? ?? ?? 81 ee ?? ff 00 00 50 64 8b 19 64 89 21 b0 50 07 00 (59 41|2b c9) be}  //weight: 10, accuracy: Low
        $x_10_2 = {9d 6a 07 ff 35 ?? ?? ?? ?? ff 0c 24 ff 24 24}  //weight: 10, accuracy: Low
        $x_1_3 = {38 06 74 03 83 c6 08 8d 86 ac 00 00 00 b6 38 38 30 77 0e b5 1c 38 28 72 08 8d 3d ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_4 = {2a 06 74 03 83 ee 08 8d 86 ac 00 00 00 b6 38 2a 30 72 0e b5 1c 2a 28 77 08 (68|8d 3d) ?? ?? ?? ?? [0-1] 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_JK_2147681380_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JK"
        threat_id = "2147681380"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 83 ee 6e 8b 06 8b f0 c1 e6 10 66 33 f6 81 ee ?? ?? ?? ?? 64 8b 01 8b 58 04 c7 40 04 ?? ?? ?? ?? b0 4c 3a 06 74 03 83 ee 08 2a 06 74 03 83 ee 08 8d 86 a8 00 00 00 b1 38 2a 08 74 06 b5 1c 2a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_JL_2147681441_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JL"
        threat_id = "2147681441"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 56 57 68 40 42 0f 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {83 c1 04 83 ee 01 75 f3 8d 78 06 bb 49 e8 01 00 eb 09}  //weight: 1, accuracy: High
        $x_1_3 = {c1 ef 05 8b d9 c1 e3 04 33 fb 05 47 86 c8 61 8b d8 83 e3 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FJ_2147681583_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.FJ"
        threat_id = "2147681583"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? ff d0 8b 45 fc 8b 0d ?? ?? ?? ?? 8b 09 89 08 c7 45 f8 00 00 00 00 a1 ?? ?? ?? ?? 8b 4d f8 3b c1 0f 85 1c 00 00 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 01 e9 27 00 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 33 c1 a3 ?? ?? ?? ?? 8b 45 f8 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 01 08 8b 45 fc 8b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 53 44 53 [0-32] 3a 5c [0-16] 5c [0-16] 5c [0-16] 5c [0-32] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = {3d a7 72 5c 5e c7 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_JP_2147681590_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JP"
        threat_id = "2147681590"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 3c 03 c6 a3 ?? ?? ?? ?? 81 38 50 45 00 00 0f 85 0d 00 4d 5a 00 00 66 39 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 50 50 8b 40 34 8b 0d ?? ?? ?? ?? 6a 40 68 00 30 00 00 52 50 51 ff (55|54 24)}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 50 06 47 83 c3 28 3b fa 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_JQ_2147681626_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JQ"
        threat_id = "2147681626"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 81 ce 00 ff ff ff 46 0f b6 54 b4 ?? 8b b4 24 ?? ?? ?? ?? 30 14 30 40 3b c5 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b c6 f7 f3 0f b6 14 2a 03 54 8c ?? 03 fa 81 e7 ff 00 00 80 79}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 0c 11 8d 84 bd ?? ?? ff ff 03 08 03 d9 81 e3 ff 00 00 80 79}  //weight: 1, accuracy: Low
        $x_1_4 = {49 81 c9 00 ff ff ff 41 8a 8c 8d ?? ?? ff ff 30 08 46 3b 75 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_5 = {72 f2 8b 45 f8 85 0e 00 33 c0 f6 90 ?? ?? ?? ?? 40 3d ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {4e 75 f5 33 c0 c6 45 f4 00 8d 7d f5 ab ab 66 ab aa 0d 00 be ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_7 = {4e 74 50 6f 77 65 72 49 6e 66 6f 72 6d 61 74 69 6f 6e 00 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_JR_2147681627_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JR"
        threat_id = "2147681627"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 81 cb 00 ff ff ff 43 0f b6 54 9c ?? 30 14 30 40 3b c5 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b c1 f7 f5 0f b6 14 1a 03 54 8c ?? 03 fa 81 e7 ff 00 00 80 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_JV_2147681804_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JV"
        threat_id = "2147681804"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff 75 ?? ff 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {ff b4 08 08 01 00 00 8b 94 08 0c 01 00 00 8d 84 08 f8 00 00 00 03 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_JW_2147681832_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JW"
        threat_id = "2147681832"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0a 32 8c 85}  //weight: 2, accuracy: High
        $x_1_2 = {33 c9 66 8b 08 81 f9 4d 5a 00 00 74}  //weight: 1, accuracy: High
        $x_1_3 = {8d 94 01 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8d 54 01 18}  //weight: 1, accuracy: High
        $x_1_5 = {33 d2 66 8b 51 12 81 e2 00 20 00 00 85 d2 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_JX_2147682131_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JX"
        threat_id = "2147682131"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 00 10 40 00 8b 1d ?? ?? ?? ?? 89 d9 ff 11}  //weight: 1, accuracy: Low
        $x_1_2 = {16 17 9c 8a ?? 24 01 83 c4 04 f6 ?? 01}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 31 52 50 0f a2 0f 31}  //weight: 1, accuracy: High
        $x_1_4 = {7f 09 81 7d fc ?? 01 00 00 7f 08 83 7d f8 00 75 02 eb 09 c7 45 f4 01 00 00 00 eb 07}  //weight: 1, accuracy: Low
        $x_1_5 = {7e 03 cc eb fd 04 00 83 7d}  //weight: 1, accuracy: Low
        $x_1_6 = {83 7d f8 0a 7e 04 cd ?? eb fc}  //weight: 1, accuracy: Low
        $x_1_7 = {83 7d f8 09 7e 04 cd ?? eb fc}  //weight: 1, accuracy: Low
        $x_1_8 = {0b 7e 04 cd ?? eb fc}  //weight: 1, accuracy: Low
        $x_1_9 = {64 a1 30 00 00 00 [0-2] 8b 40 10 8b 40 3c 89 45 ?? [0-10] 8b (45|75) 01}  //weight: 1, accuracy: Low
        $x_1_10 = {64 8b 1d 30 00 00 00 [0-4] 8b 43 10 [0-4] 8b 40 3c [0-4] 89 45}  //weight: 1, accuracy: Low
        $x_1_11 = {64 8b 0d 30 00 00 00 [0-4] 8b 41 10 [0-4] 8b 40 3c [0-4] 89 45}  //weight: 1, accuracy: Low
        $x_1_12 = {64 8b 15 30 00 00 00 [0-4] 8b 42 10 [0-4] 8b 40 3c [0-4] 89 45}  //weight: 1, accuracy: Low
        $x_1_13 = {64 a1 30 00 00 00 [0-4] 8b 40 10 [0-4] 8b 40 3c [0-4] 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_JY_2147682169_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JY"
        threat_id = "2147682169"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 32 00 00 00 f7 f9 83 c2 32}  //weight: 1, accuracy: High
        $x_1_2 = {8b 51 3c 8b 45 f8 6b c0 28 03 45 08 8d 8c 10 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 48 3c 8b 55 f8 6b d2 28 03 55 08 8d 84 0a f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f be 11 0f be 85 ?? ?? ff ff 33 d0 8b 4d ?? 03 8d ?? ?? ff ff 88 11 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_JZ_2147682191_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!JZ"
        threat_id = "2147682191"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 3c 8b 4c 30 34 03 c6 8b de 2b d9 0f 84}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 4d 06 40 83 ?? 28 3b c1 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KA_2147682201_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KA"
        threat_id = "2147682201"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b ?? ?? ?? ?? ?? 8b ?? 50 ?? 8b ?? 01 8b ?? 34}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 30 00 00 8b 15 ?? ?? ?? ?? 8b 42 50 50 8b 0d ?? ?? ?? ?? 8b 51 34}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 48 34 8b 15 ?? ?? ?? ?? 03 4a 28 89 0d}  //weight: 2, accuracy: Low
        $x_2_4 = {8d 94 01 f8 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = {0f be 11 0f be 85 ?? ?? ff ff 33 d0 8b 4d ?? 03 8d ?? ?? ff ff 88 11 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_FN_2147682630_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.FN"
        threat_id = "2147682630"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 ff 00 00 00 f7 f9 89 74 24 ?? 42 3b de 76 ?? 8b 44 24 ?? 8a 0c 38 80 e9 ?? 32 ca ff 44 24 ?? 88 0c 38 39 5c 24 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = "|WriteProcessMemory|CreateProcessW|SetThreadContext|GetThreadContext|ResumeThread|FindResourceA|LoadResource|SizeofResource|" ascii //weight: 1
        $x_1_3 = {00 35 39 32 30 71 68 62 30 77 33 6a 66 71 61 77 32 33 00 00 00 25 64 00 00 7c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_KC_2147682658_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KC"
        threat_id = "2147682658"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 00 ba 30 75 00 00 e8 02 00 b9}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 68 ?? 61 00 00 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KC_2147682658_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KC"
        threat_id = "2147682658"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 00 00 00 89 84 bd ?? fb ff ff 8b 84 9d 00 fb ff ff 03 84 bd 00 fb ff ff 25 ff 00 00 80 79}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 02 03 3e 03 c7 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8b f8}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 04 02 8b 55 ?? 8b 94 95 ?? ?? ff ff 03 55 ?? 03 c2 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40}  //weight: 1, accuracy: Low
        $x_1_4 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 (32|8a) ?? fb ff ff 1c 00 8b 84 9d ?? fb ff ff 03 84 bd ?? fb ff ff}  //weight: 1, accuracy: Low
        $x_10_5 = {6a 1f 6a 20 8d 85 ?? ?? ff ff b9 ?? ?? 00 00 ba ?? ?? 00 00}  //weight: 10, accuracy: Low
        $x_10_6 = {50 6a 40 68 8d 22 00 00 8b 45 f8 50 e8}  //weight: 10, accuracy: High
        $x_10_7 = {6a 1f 6a 20 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b 45 ?? e8}  //weight: 10, accuracy: Low
        $x_10_8 = {50 6a 20 ba ?? ?? ?? ?? b9 1f 00 00 00 b8 ?? ?? 00 00 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_KD_2147682759_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KD"
        threat_id = "2147682759"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8a 55 e3 88 95 ?? f0 ff ff 8b 45 ?? 8a 8d 00 f0 ff ff 88 88 ?? ?? ?? ?? eb ?? 8b 95 ?? f0 ff ff 81 c2 ?? ?? ?? ?? ff d2}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 8a 4d e3 88 8d ?? f0 ff ff 8b 55 ?? 8a 85 00 f0 ff ff 88 82 ?? ?? ?? ?? eb ?? 8b 8d ?? f0 ff ff 81 c1 ?? ?? ?? ?? ff d1}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 04 89 85 ?? ?? ff ff 8a 85 ?? ?? ff ff 88 85 ?? ?? ff ff 8b 8d ?? ?? ff ff 8a 95 ?? ?? ff ff 88 94 0d ?? ?? ff ff e9 ?? ff ff ff 8b 85 ?? ?? ff ff 8d 8c 05 05 ff ff ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_KE_2147682774_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KE"
        threat_id = "2147682774"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4e 50 8b c1 c1 e9 02 8b f3 8b fd f3 a5 8b c8 83 e1 03 55 f3 a4 e8 54 fe ff ff 8b 8c 24 68 01 00 00 8b 54 24 20 51 b8 10 21 40 00 52 2b c3 55 03 c5 ff d0 83 c4 10 e9 70 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KF_2147682776_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KF"
        threat_id = "2147682776"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4e 50 8b d1 c1 e9 02 8b f3 8b fd f3 a5 8b ca 83 e1 03 55 f3 a4 e8 c2 fe ff ff 8b 44 24 1c 8d 48 d8 51 ba 10 47 40 00 50 2b d3 55 03 d5 ff d2 83 c4 10 e9 18 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KI_2147682973_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KI"
        threat_id = "2147682973"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 41 3c 0f b7 54 08 14 03 c1 0f b7 48 06 53 03 d0 56 8d 34 89 8d 44 f2 ?? 33 d2 85 c9 76 0f 8a 58 ?? 84 db 74 0a 42 83 e8 28 3b d1 72 f1 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KJ_2147683317_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KJ"
        threat_id = "2147683317"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 b8 0b 00 00 6a 00 ff 15 ?? ?? ?? ?? b9 ee 02 00 00 be ?? ?? ?? ?? 8b f8 f3 a5 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 54 08 0a 88 91 ?? ?? ?? ?? 41 81 f9 b8 0b 00 00 72 ed 8a 45 f9 a2 ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {34 08 00 00 7d ?? e8 ?? ff ff ff 06 00 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_KK_2147683524_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KK"
        threat_id = "2147683524"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 86 57 0d 00 68 88 4e 0d 00 e8 1a 00 00 00 89 45 fc 68 fa 8b 34 00 68 88 4e 0d 00 e8 08 00 00 00 89 45 f8 e9 b5 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {99 f7 fe 8b 75 f8 8a 84 95 ?? ?? ff ff 30 06 ff 45 14 8b 45 14 3b 45 10 72 95}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 72 01 8b 54 24 10 8a 02 88 01 41 42 4e 75 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KK_2147683524_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KK"
        threat_id = "2147683524"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 86 57 0d 00 68 88 4e 0d 00 e8 1a 00 00 00 89 45 fc 68 fa 8b 34 00 68 88 4e 0d 00 e8 08 00 00 00 89 45 f8 e9 ?? ?? ?? ?? 55 8b ec 53 56 57 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KM_2147684190_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KM"
        threat_id = "2147684190"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 83 bd ?? ?? ff ff 32 7c ?? 8b 85 ?? ?? ff ff 83 c0 01 89 85 02 ff ff 8b 8d 02 ff ff 83 c1 01 83 f1 ?? 88 8d ?? ?? ff ff 8b 95 02 ff ff 0f be 84 15 ?? ?? ff ff 0f be 8d ?? ?? ff ff 03 c1 88 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 08 83 bd ?? ?? ff ff 32 7c ?? 8b (4d|55) ?? 83 (c1|c2) 01 89 (4d|55) 03 8b (45|55) 03 83 (c0|c2) 01 (35 ?? 00|83 (f0|f2) ??) 88 (85|95) ?? ?? ff ff 8b (45|4d) 03 0f be (8c 05|94 0d) ?? ?? ff ff 0f be (85|95) ?? ?? ff ff 03 (ca|d0) 88 (4d|55)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_FV_2147686980_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.FV"
        threat_id = "2147686980"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 7d ec dd 07 00 00 75 02 eb 02 eb c0}  //weight: 2, accuracy: High
        $x_1_2 = {0f b7 45 fc 89 45 d4 8d 45 f0 50 e8 ?? ?? ?? ?? 0f b7 45 f6 89 45 e0 0f b7 45 f8 89 45 dc 0f b7 45 fa 89 45 d8 0f b7 45 fc 89 45 d0 8b 5d d0 3b 5d d4 75 02 eb d1}  //weight: 1, accuracy: Low
        $x_1_3 = {57 72 69 74 65 41 6e 64 57 61 74 63 68 54 68 69 73 52 74 6c 5a 65 72 6f 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_2_4 = {8a 06 46 51 8a 4d f7 d2 c8 59 50 56 ff 45 f8 8b 75 f8 8a 06 46 8b 5d fc 39 5d f8 75 0c 8b 55 10 89 55 f8 8b 75 f8 8a 06 46 88 45 f7 5e 58 88 07 47 49 83 f9 00 75 c9}  //weight: 2, accuracy: High
        $x_2_5 = {33 c0 33 f6 33 c9 eb 26 6b c6 28 03 45 a0 8b 5d a4 03 58 0c 8b 15 ?? ?? ?? ?? 03 50 14 6a 00 ff 70 10 52 53 ff 75 a8 ff 15 ?? ?? ?? ?? 46 66 3b 77 06 72 d4}  //weight: 2, accuracy: Low
        $x_2_6 = {ff 75 fc ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0b c0 0f 84 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 0f 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 03 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_FW_2147687889_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.FW"
        threat_id = "2147687889"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChoxoticSign" ascii //weight: 1
        $x_1_2 = {b0 4b 35 f7 20 87 21 92 73 65 40 48 54 f5 34 c7 0c 6e 23 26 a4 c5 02 1c 4a 7e 14 70 f7 c3 ad b0 4e b3 3c 26 c6 fc 88 08 0b ac 3a ef a2 44 9c 8a}  //weight: 1, accuracy: High
        $x_1_3 = {8a 00 31 d0 88 01 83 45 ?? 02 83 55 ?? 00 8b 85 ?? ?? ?? ?? 8b 55 ?? 89 d3 31 c3 8b 85 ?? ?? ?? ?? 8b 55 ?? 89 d6 31 c6 89 d8 09 f0 85 c0 0f 95 c0 84 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {89 c7 81 e7 ff 03 00 00 0f b6 bc 3d ?? ?? ?? ?? 89 fb 30 19 83 c0 02 83 d2 00 83 c1 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_LA_2147689092_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!LA"
        threat_id = "2147689092"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 06 50 c6 46 01 24 c6 46 02 78 e8 00 00 00 00 58 89 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LA_2147689092_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!LA"
        threat_id = "2147689092"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 33 c9 83 7c 24 10 ff a3 ?? ?? ?? ?? 74 17 a1 ?? ?? ?? ?? 8a 54 24 0c 30 14 08 03 c1 8b c1 41 3b 44 24 10 75 e9 a1 ?? ?? ?? ?? c2 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_FZ_2147689820_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.FZ"
        threat_id = "2147689820"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 fb 05 47 86 c8 61 8b d8 83 e3 03 8b 1c 9e}  //weight: 1, accuracy: High
        $x_1_2 = {57 bf b0 1e 04 00 68 ?? ?? ?? ?? ff d6 4f (75 f6|33 ff) e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 f0 75 73 65 72 8d 45 f0 50 66 c7 45 f4 33 32 c6 45 f6 00 ff d3}  //weight: 1, accuracy: High
        $x_1_4 = {6a 07 6a ff be 01 00 00 00 c7 45 fc 00 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 78 08 83 7d fc 00 75 02 33 f6 6a 00 6a 00 6a 11 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GA_2147689890_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GA"
        threat_id = "2147689890"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f0 81 78 60 45 76 38 12 75 12}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 7f ff ff ff 6d c6 45 80 70 c6 45 81 72 c6 45 82 65 c6 45 83 73}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 90 74 c6 45 91 65 c6 45 92 46 c6 45 93 69}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 f8 63 c6 45 f9 3a c6 45 fa 5c c6 45 fb 30 c6 45 fc 00 8d 45 f8 50 ff 55 08}  //weight: 1, accuracy: High
        $x_1_5 = {81 ef 5d 00 00 00 b9 20 00 00 00 b8 5f c3 5f c3 f3 ab cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KW_2147691754_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KW"
        threat_id = "2147691754"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 28 03 45 ?? 89 87 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4e 50 8b 56 34 8b 45 ?? 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
        $x_2_3 = {3d 75 f2 1f 0f 74 07 3d 75 85 86 06 75 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_GC_2147692435_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GC"
        threat_id = "2147692435"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f a2 0f a2 0f 31}  //weight: 1, accuracy: High
        $x_1_2 = {0f 31 0f 31 0f a2}  //weight: 1, accuracy: High
        $x_1_3 = {0f a2 0f a2 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 31 0f 31 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_KY_2147693864_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KY"
        threat_id = "2147693864"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 ff ff 00 00 03 c8 46 66 85 d2 75 e3 81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4e 28 8b 45 ?? 03 cf 89 88 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 46 34 50 8b 45 ?? 8b 80 a4 00 00 00 83 c0 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KZ_2147694105_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!KZ"
        threat_id = "2147694105"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6a 10 50 ff 15 ?? ?? ?? ?? 53 6a 2f 68 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? 68 fb 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 75 6e 6b 30 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 56 57 c6 85 ?? ?? ?? ?? 45 c6 85 ?? ?? ?? ?? 9b c6 85 ?? ?? ?? ?? fc c6 85 ?? ?? ?? ?? 91 c6 85 ?? ?? ?? ?? fc c6 85 ?? ?? ?? ?? 6c c6 85 ?? ?? ?? ?? 14 c6 85 ?? ?? ?? ?? 10 c6 85 ?? ?? ?? ?? 10 c6 85 ?? ?? ?? ?? 43 c6 85 ?? ?? ?? ?? 23 c6 85 ?? ?? ?? ?? cb c6 85 ?? ?? ?? ?? 46 c6 85 ?? ?? ?? ?? 47 c6 85 ?? ?? ?? ?? d6 c6 85 ?? ?? ?? ?? 55 c6 85 ?? ?? ?? ?? c4 c6 85 ?? ?? ?? ?? 35 c6 85 ?? ?? ?? ?? d6 c6 85 ?? ?? ?? ?? 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GF_2147694609_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GF"
        threat_id = "2147694609"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 38 e9 75 0b ba ff ff 00 00 66 39 50 03 74 07 40 41 83 f9 1e 7c e9 80 38 e9}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 64 a9 dd e5 62 c7 44 24 68 86 00 c2 1b 8b 74 24 10 8d 74 b4 38 ff 36 57 e8}  //weight: 1, accuracy: High
        $x_1_3 = {c7 84 3d e0 fe ff ff 2e 64 6c 6c c6 84 3d e4 fe ff ff 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GF_2147694609_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GF"
        threat_id = "2147694609"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 85 c8 fd ff ff 8b 0d ?? ?? ?? 00 51 ff 15 ?? ?? ?? 00 83 c4 04 8b 55 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {00 03 95 58 ff ff ff 88 0a 8b 85 bc fe ff ff 83 e0 d2 0f b6 4d f2 0f b7 95 40 ff ff ff 2b ca 0b c1 88 85 2f ff ff ff 0f b7 85 08 ff ff ff b9 26 00 00 00 05 00 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GF_2147694609_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GF"
        threat_id = "2147694609"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 21 89 95 fc fe ff ff 6a 40 68 00 10 00 00 8b 85 00 ff ff ff 50 6a 00 ff 15 9c e0 40 00 a3 ?? ?? ?? 00 0f b7 8d 6c fd ff ff 83 c1 60 0f b6 95 f3 fe ff ff 33 ca}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 85 fc fe ff ff 57 00 00 00 8b 95 e8 fe ff ff 2b 95 48 fe ff ff 83 ea 26 66 89 95 34 fe ff ff a1 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LB_2147694714_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!LB"
        threat_id = "2147694714"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 34 8b 4c 24 ?? 6a 40 68 00 30 00 00 53 50 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {3b c1 c7 44 24 ?? 07 00 01 00 75 ?? 8b 46 28 8b 4e 34 03 c1 89 84 24 dc 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {03 d8 8b 44 24 ?? 33 c9 66 8b 4e 06 40 83 c5 28 3b c1 89 44 24 00 7c}  //weight: 1, accuracy: Low
        $x_1_4 = {50 c6 44 24 ?? 4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LC_2147695008_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!LC"
        threat_id = "2147695008"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 55 f8 0f b6 04 02 8b 55 f8 8b 4d 10 89 45 fc 8b c2 99 f7 f9 8b 45 0c 0f b6 04 02 8b 55 fc 33 d0 8b 45 08 8b 4d f8 88 14 01 ff 45 f8 8b 45 f8 8b 55 14 3b c2 7c c6 c9 c3}  //weight: 1, accuracy: High
        $x_1_2 = {c7 85 e4 fd ff ff 8d 00 00 00 8b 85 e4 fd ff ff f7 d8 05 ba 00 00 00 89 85 e8 fd ff ff 8d 85 28 fd ff ff ba 30 30 00 10 8b f8 8b f2 b9 24 00 00 00 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 83 c4 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GG_2147696230_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GG"
        threat_id = "2147696230"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb fe 55 8b ec 81 ec (70|2d|8f) 00 00 00 56}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff d0 8d 85 (70|2d|8f) ff ff ff ff d0 8d 85 (70|2d|8f) ff ff ff ff d0 8d 85 (70|2d|8f) ff ff ff ff d0 [0-128] 8d 85 (70|2d|8f) ff ff ff ff d0 4e 75 (80|2d|bf)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GH_2147696319_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GH"
        threat_id = "2147696319"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 4e 54 42 42 5f 42 42 4e ad 89 07 03 fa 49 75 f8}  //weight: 1, accuracy: High
        $x_1_2 = {55 4e 4e 5f 33 c0 8b 06 89 07 47 47 47 47 83 c6 04 e2 f3 e8 ?? ?? 00 00 e9 ?? (20|2d|40) 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3e 0f 18 00 50 16 33 c0 85 c0 17 74 [0-40] 05 00 10 00 00 8b 48 fc 32 cd 80 f9 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_LD_2147696621_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!LD"
        threat_id = "2147696621"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 9d fa ff ff 71 c6 85 9e fa ff ff 66 c6 85 9f fa ff ff 7a c6 85 a0 fa ff ff 71 c6 85 a1 fa ff ff 78 c6 85 a2 fa ff ff 27 c6 85 a3 fa ff ff 26 c6 85 a4 fa ff ff 3a c6 85 a5 fa ff ff 70 c6 85 a6 fa ff ff 78 c6 85 a7 fa ff ff 78 c6 85 a8 fa ff ff 00 33 c9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 95 e0 fa ff ff 83 c2 01 89 95 e0 fa ff ff 83 bd e0 fa ff ff 0c 7d 37 c7 85 cc f9 ff ff c6 00 00 00 8b 85 e0 fa ff ff 0f be 8c 05 9c fa ff ff 81 f1 14 07 00 00 8b 95 e0 fa ff ff 88 8c 15 9c fa ff ff c7 85 d0 f9 ff ff 9e 01 00 00 eb b1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LE_2147696623_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!LE"
        threat_id = "2147696623"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {18 03 07 03 04 18 5c 41 48 11 01 0d 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 66 75 6d 61 74 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = {b8 07 00 00 00 c7 84 24 90 04 00 00 31 00 00 00 8b 8c 24 94 04 00 00 0f be 8c 0c a2 04 00 00 8b 94 24 94 04 00 00 89 84 24 d0 00 00 00 89 d0 99 8b b4 24 d0 00 00 00 f7 fe 0f be 84 14 9a 04 00 00 31 c1 88 cb 8b 84 24 94 04 00 00 88 9c 04 a2 04 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GI_2147696838_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GI"
        threat_id = "2147696838"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {c7 00 63 61 74 73 05 04 00 00 00 c7 00 72 76 2e 64 05 04 00 00 00 c7 00 6c 6c 00 00 05 04 00 00 00}  //weight: 4, accuracy: High
        $x_1_2 = {ff 10 85 c0 0f 85 25 00 00 00 0f 85 1f 00 00 00 0f 85 19 00 00 00 0f 85 13 00 00 00 0f 85 0d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {60 8b da 50 4b 03 de 88 03 58 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_GJ_2147696926_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GJ"
        threat_id = "2147696926"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 8b 45 fc 83 c0 01 89 45 fc 81 7d fc 00 01 00 00 0f 8d (a0|2d|f0) 00 00 00 e9 (a0|2d|f0) 00 00 00 e9 (a0|2d|f0) 00 00 00 [0-255] 8b 4d fc 8b 55 fc 89 94 8d f8 fb ff ff e9 ?? ?? ff ff c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 81 7d fc 00 01 00 00 0f 8d ?? ?? 00 00 e9 (a0|2d|f0) 00 00 00 e9 (a0|2d|f0) 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 0b 8d 8d 4c ff ff ff 51 e8 ?? ?? ff ff 83 c4 10 e9 (a0|2d|f0) 00 00 00 e9 (a0|2d|f0) 00 00 00}  //weight: 1, accuracy: Low
        $x_2_3 = {41 0f b6 8c 0d f8 fe ff ff 89 8d f4 fe ff ff eb (08|2d|14) eb (06|2d|12) [0-20] 8b 95 e8 fe ff ff 03 95 ec fe ff ff 0f be 02 33 85 f4 fe ff ff 8b 8d e8 fe ff ff 03 8d ec fe ff ff 88 01 eb (08|2d|14) eb (06|2d|12) [0-20] e9 ?? ?? ff ff 8b 85 e8 fe ff ff eb (08|2d|14) eb (06|2d|12)}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_GK_2147697012_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GK"
        threat_id = "2147697012"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba ac 3d 60 00 33 c0 f0 0f b1 0a 85 c0 74}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 5f 40 8b 06 46 46 89 07 46 46 83 c7 04 49 75 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GK_2147697012_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GK"
        threat_id = "2147697012"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ef c1 fa 0a 8b c2 c1 e8 1f 8b 94 02 ?? ?? ?? ?? 33 d1 80 fa f2 88 94 35 ?? ?? ?? ?? 77 09 fe ca 88 94 35 ?? ?? ?? ?? 46 81 c7 a2 0c 00 00 89 75 ec db 45 ec de 1d ?? ?? ?? ?? df e0 f6 cc 41 75 b3 68 ?? ?? ?? ?? 6a 00 8d 8d ?? ?? ?? ?? ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LF_2147697382_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!LF"
        threat_id = "2147697382"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 8c 05 dc fd ff ff 8b 85 70 fd ff ff 99 f7 7d f4 8b 45 10 0f be 14 10 33 ca 8b 85 74 fd ff ff 88 8c 05 dc fd ff ff 8b 8d 70 fd ff ff 83 c1 01 89 8d 70 fd ff ff 8b 85 74 fd ff ff 99 f7 7d f4 85 d2 75}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 08 8b 85 70 fd ff ff 99 f7 bd 88 fd ff ff 8b 45 20 0f be 14 10 33 ca 8b 45 f0 03 85 10 fc ff ff 88 08}  //weight: 1, accuracy: High
        $x_1_3 = {8b f4 8b 95 a8 fb ff ff 52 8b 85 f4 fb ff ff 50 ff 95 44 fb ff ff 3b f4 e8 ?? ?? ?? ?? c7 85 40 fb ff ff f7 2d 00 00 8d 8d 40 fb ff ff 89 8d 3c fb ff ff c7 85 38 fb ff ff 00 00 00 00 c7 85 34 fb ff ff 1c 02 00 00 c7 85 34 fb ff ff 8d 07 00 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GL_2147697719_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GL"
        threat_id = "2147697719"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 00 00 99 b9 ?? ?? 00 00 f7 f9 33 d2 8a 90 ?? ?? ?? 00 8b ca 83 f1 ?? 33 d2 8a 15 ?? ?? ?? 00 33 ca 83 f1 06 00 8b 45 ?? 69}  //weight: 1, accuracy: Low
        $x_1_2 = {00 df e0 f6 c4 41 75 ?? 68 00 dc ab 40 6a 00 90 90 e9 08 00 db 45 ?? dc 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GL_2147697719_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GL"
        threat_id = "2147697719"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 69 c0 15 1a 00 00 99 b9 15 1a 00 00 f7 f9 0f b6 0c 85 ?? ?? ?? 00 0f b6 05 ?? ?? ?? 00 33 c8 8b 45 fc 69 c0 15 1a 00 00 99 be 15 1a 00 00 f7 fe e9}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c0 c5 11 00 00 99 b9 c5 11 00 00 f7 f9 d9 04 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8a d8 81 e3 ff ?? 00 00 d9 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? 25 ff ?? 00 00 33 d8 8b 45 f0 69 c0 c5 11 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 ff a3 a4 52 f7 e9 c1 fa 0b 8b ca c1 e9 1f 03 d1 d9 04 95 ?? ?? ?? ?? e8 ?? ?? ?? ?? d9 05 ?? ?? ?? ?? 8a d8 e8 ?? ?? ?? ?? 32 d8 b8 4b 94 aa 3b}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 5d 1c 68 0e 8d b4 15 50 e2 ff ff f7 ef 12 00 b8 ?? be a0 2f f7 6d f8 c1 fa 03 8b c2 c1 e8 1f 03 d0}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 e5 dc 55 51 f7 6d ?? c1 fa 0a 8b ca c1 e9 1f 03 d1 8b fa dd 04 fd ?? ?? ?? ?? e8 ?? ?? ?? ?? dd 05 ?? ?? ?? ?? 8a d8 e8 ?? ?? ?? ?? 32 d8 88 9c 3d ?? ?? ?? ?? 90}  //weight: 1, accuracy: Low
        $x_1_6 = {b8 3b 72 95 73 f7 6d d8 c1 fa 08 8b c2 c1 e8 1f 03 d0 02 84 15 30 eb ff ff 3c 05 8d 8c 15 30 eb ff ff 77 22 90 90 90 90 90 b8 83 be a0 2f}  //weight: 1, accuracy: High
        $x_1_7 = {68 00 1f c1 40 6a 00 8d 54 24 48 ff d2 83 c4 08 b8 bb 57 9e 77 f7 ef c1 fa 0c 8b c2 c1 e8 1f 03 d0 dd 04 d5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8a c8 b8 67 66 66 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_GM_2147706119_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GM"
        threat_id = "2147706119"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? 00 0f b6 44 24 f1 3c ff 75 02 eb 1b c1 e0 15 74 fb c1 e3 02 ff e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GM_2147706119_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GM"
        threat_id = "2147706119"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d9 c1 d8 e1 d8 e1 d8 c1 d8 c1 d8 c1 dd da d9 c1 dc 1d 00 46 40 00 df e0 9e 76 e5}  //weight: 1, accuracy: High
        $x_1_2 = {8b c7 6a 21 99 59 f7 f9 dd 04 c5 ?? ?? 40 00 8d b4 05 34 f0 ff ff e8 f3 0d 00 00 dd 05 ?? ?? 40 00 8a d8 e8 e6 0d 00 00 32 d8 88 1e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LG_2147706138_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.gen!LG"
        threat_id = "2147706138"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 50 ff 75 ?? ff 95}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 47 28 03 45 ?? 89 85 03 00 ff 55}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 47 06 ff 45 ?? 83 45 ?? 28 39 45 ?? 7c c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GN_2147706147_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GN"
        threat_id = "2147706147"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d9 c1 d8 c1 d8 c1 d8 e1 d8 e1 d8 c1 d8 c1 d8 c1 d8 c1 dd da d9 c1 dc 1d ?? ?? 40 00 df e0 9e 76 df}  //weight: 1, accuracy: Low
        $x_1_2 = {8b de 8a 88 ?? ?? 40 00 8b 45 fc 99 f7 fb 32 0d ?? ?? 40 00 8b 5d 08 88 8c 05 58 eb ff ff 8a 8c 1d 58 eb ff ff 8d 84 1d 58 eb ff ff 80 f9 f2 77 04 fe c9 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GN_2147706147_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GN"
        threat_id = "2147706147"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 01 6a 0c 68 ?? ?? ?? 00 e8 ?? ?? ff ff 83 c4 08 c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? 6a 0e 8d 4d 02 51 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {00 6a 08 8d 45 ?? 50 e8 ?? ?? ff ff 23 00 c6 45 00 ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45}  //weight: 1, accuracy: Low
        $x_1_3 = {ff f3 a5 66 a5 6a 1a 8d 8d ?? ?? ff ff 51 e8 ?? ?? ff ff 05 00 8d bd 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LH_2147706374_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LH"
        threat_id = "2147706374"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 4c a8 fe ff 00 00 80 a9 c7 85 50 a8 fe ff 83 96 c0 41}  //weight: 1, accuracy: High
        $x_1_2 = {df e0 f6 c4 41 74 38 dd 85 ?? ?? ?? ?? dc 25 ?? ?? ?? ?? dd 95 ?? ?? ?? ?? dc 05 ?? ?? ?? ?? dd 95 ?? ?? ?? ?? dc 25 ?? ?? ?? ?? dd 95 ?? ?? ?? ?? dc 05 ?? ?? ?? ?? dd 9d ?? ?? ?? ?? eb 8b 36 00 dd 85 ?? ?? ?? ?? dc 05 ?? ?? ?? ?? dd 95 ?? ?? ?? ?? dc 05 ?? ?? ?? ?? dd 95 ?? ?? ?? ?? dc 05 ?? ?? ?? ?? dd 9d ?? ?? ?? ?? dd 85 ?? ?? ?? ?? dc 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LH_2147706374_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LH"
        threat_id = "2147706374"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 53 56 57 dc 05 ?? ?? 40 00 dc 25 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 25 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 15 ?? ?? 40 00 df e0 f6 c4 41 75 d5 8d 85 ?? ?? ff ff 68 e8 03 00 00 04 00 dd}  //weight: 1, accuracy: Low
        $x_1_2 = {df e0 f6 c4 01 75 b7 48 00 dd 05 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 05 02 40 00 dc 25 02 40 00 dc 05 02 40 00 dc 05 02 40 00 dc 05 02 40 00 dc 05 02 40 00 dc 05 02 40 00 dc 05 02 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {df e0 f6 c4 01 75 b7 48 00 dd 05 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 05 02 40 00 dc 25 02 40 00 dc 05 02 40 00 dc 05 02 40 00 dc 05 02 40 00 dc 05 02 40 00 dc 05 ?? ?? 40 00 dc 05 02 40 00}  //weight: 1, accuracy: Low
        $x_1_4 = {40 00 dc 05 ?? ?? 40 00 dc 25 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 05 ?? ?? 40 00 90 05 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 25 ?? ?? 40 00 dc 15 ?? ?? 40 00 df e0 f6 c4 01 75 b7 04 00 dc 05}  //weight: 1, accuracy: Low
        $x_1_5 = {00 df e0 f6 c4 41 75 cf 23 00 dc 05 ?? ?? ?? 00 dc 05 01 00 dc 25 01 00 dc 05 01 00 dc 25 01 00 90 15}  //weight: 1, accuracy: Low
        $x_1_6 = {df e0 f6 c4 41 75 cf 30 00 dd 05 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 25 ?? ?? 40 00 dc 05 ?? ?? 40 00 dc 25 ?? ?? 40 00 36 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_GO_2147706408_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GO"
        threat_id = "2147706408"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 45 fc ff 35 ?? ?? ?? ?? ff 75 fc e8 ?? ?? ?? ?? 89 45 f0 ff 75 f8 ff 75 f4 ff 35 ?? ?? ?? ?? 6a 00 ff 55 f0 89 45 fc 68 ?? ?? ?? ?? 68 ?? ?? 00 00 68 ?? ?? ?? ?? ff 75 fc e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 fc c3 0a 00 68 ?? ?? ?? ?? e8}  //weight: 3, accuracy: Low
        $x_1_2 = {0f 9f c1 d3 f8 0b 00 8b ?? 33 ?? ?? ?? 33 c9 83}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 9d c1 2b c1 0c 00 33 ?? [0-2] 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_GO_2147706408_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GO"
        threat_id = "2147706408"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 71 f6 e9 8a c8 8a c3 02 05 ?? ?? 00 10 80 c2 4b 80 3d c2 ?? ?? 10 21 88 0d c1 ?? ?? 10 88 15 ?? ?? 00 10 a2 c7 ?? ?? 10 c6 05 ?? ?? 00 10 7c 7c 1a}  //weight: 1, accuracy: Low
        $x_1_2 = {68 45 42 0f 00 6a 00 ff d7 8b 95 ?? ?? ff ff 6a 00 8d 8d ?? ?? ff ff 51 8b d8 0f b6 05 ?? ?? ?? 10 68 46 42 0f 00 56 04 71}  //weight: 1, accuracy: Low
        $x_1_3 = {83 fe 39 0f 95 c0 0b c3 33 c9 83 fa 3c 0f 94 c1 c1 e6 64 03 c1 85 f6 74 07}  //weight: 1, accuracy: High
        $x_1_4 = {69 c9 9c 37 00 00 03 ca 8d 54 ?? ?? 52 6a 40 89 0d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 68 04 30 00 00 51 c7 44 ?? ?? 40 00 00 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_GP_2147706522_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GP"
        threat_id = "2147706522"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 03 8b 95 d4 b1 ff ff 8d 14 92 0f af d6 2b c2 88 85 da b1 ff ff 8a 85 da b1 ff ff 88 03 43 4f 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 31 89 c2 0f 31 29 d0 77 fa 64 8b 1d 30 00 00 00 8b 5b 0c 8b 5b 0c 8b 1b 8b 1b 8b 5b 18 89 5d fc 33 c0 89 c3 c6 45 a9 47 c6 45 aa 50 c6 45 ab 41 8b 45 fc 89 85 c4 fd ff ff 8b 75 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_GS_2147707016_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GS"
        threat_id = "2147707016"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 c0 07 32 03 43 80 3b 00 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = {66 ad 66 a9 00 30 74 08 25 ff 0f 00 00 01 14 07 e2 ee}  //weight: 1, accuracy: High
        $x_1_3 = {03 d6 88 3a fe c7 66 46 66 81 fe 00 01 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_LI_2147707129_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LI"
        threat_id = "2147707129"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 08 8b 11 8b 5c 24 2c 89 5c 24 0c 8b 5c 24 28 89 5c 24 08 89 44 24 04 8b 44 24 20 89 04 24 ff 12 83 ec 10 83 c4 18 5b c3 [0-3] 55 57 56 53}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 dc 83 f8 16 0f 96 c0 84 c0 0f 85 ?? ?? ?? ?? c7 45 ?? 00 00 00 00 eb (01|2d|10) [0-16] (01|2d|10) [0-16] (01|2d|10) [0-16] (01|2d|10) [0-16] eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 dc 83 f8 16 0f 96 c0 84 c0 0f 85 ?? ?? ?? ?? c7 45 ?? 00 00 00 00 eb (01|2d|10) [0-16] eb (01|2d|10) [0-16] c7 45 ?? 00 00 00 00 e9}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 dc 83 f8 16 0f 96 c0 84 c0 0f 85 ?? ?? ?? ?? c7 45 ?? 00 00 00 00 eb (00|2d|11) [0-17] eb (00|2d|11) [0-17] eb}  //weight: 1, accuracy: Low
        $x_3_5 = {3d 40 42 6f eb [0-3] [0-16] eb [0-3] [0-17] eb [0-3] 40 00 ff ff ff ff ff ff ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_LJ_2147707130_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LJ"
        threat_id = "2147707130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 02 eb 12 b8 00 01 00 00 80 fc 01 74 f6 fb 83 c3 02 63 c4 33 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_GX_2147708160_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.GX"
        threat_id = "2147708160"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e9 66 81 e9 ?? (80|2d|ff) 0f 82 ?? ?? ?? ?? 87 ?? ?? 01 (c0|2d|ff) 87 [0-40] 68 ?? ?? ?? ?? 6a 00 68 00 00 10 00 2e ff 15 ?? ?? ?? ?? 85 c0 0f 85 [0-255] 68 06 6a 00 68 00 00 10 00 2e ff 15 07 83 f8 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LQ_2147714339_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LQ!bit"
        threat_id = "2147714339"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 32 59 f8 83 da ?? f7 d1 f8 83 d1 ?? d1 c1 c1 c9 09 01 f1 83 e9 01 51 5e c1 c6 09 d1 ce 51 8f 07 f8 83 d7 04 f8 83 d0 04 3d ?? ?? ?? ?? 75 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 25 98 6d 46 00 13 00 5f 8b 35 ?? ?? ?? ?? 56 68 7d 4b 46 00 89 3d 98 6d 46 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LL_2147714342_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LL!bit"
        threat_id = "2147714342"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 69 06 c7 44 24 ?? ?? 00 00 00 8d 9b 00 00 00 00 8a 04 0e 33 d2 0f b6 c0 f6 c1 01 75 0c f7 f5 66 0f be 82 ?? ?? ?? 00 eb 0c f7 74 24 ?? 66 0f be 82 ?? ?? ?? 00 66 89 04 4b 41 3b cf 72 d2}  //weight: 5, accuracy: Low
        $x_3_2 = {72 d2 c6 04 3e 00 5f 5e 5b c3 1b 00 8b 04 dd ?? ?? ?? ?? 8a 89 ?? ?? ?? ?? 32 0c 30 88 0c 3e 46 3b 34 dd}  //weight: 3, accuracy: Low
        $x_2_3 = {8b 54 24 10 5e 8b 42 24 8d 04 78 0f b7 0c 28 8b 42 1c 5f 5b 8d 04 88 8b 4c 24 18 8b 04 28 03 c5 5d 89 01}  //weight: 2, accuracy: High
        $x_1_4 = {83 c4 18 33 f6 8d a4 24 00 00 00 00 ff d7 00 44 34 08 46 83 fe 04 72 f4 8b 44 24 08 5f a3 ?? ?? ?? 00 33 c0 5e 59 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 04 68 00 30 00 00 57 6a 00 55 6a 05 68 ?? ?? ?? ?? 6a 11 e8 ?? ?? ?? ff 8b 1d ?? ?? ?? ?? 8b f0 83 c4 20 85 f6 75 15 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_LP_2147714347_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LP!bit"
        threat_id = "2147714347"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 56 8d 05 ?? ?? ?? ?? ff 10 a3 ?? ?? ?? ?? 8d 3d ?? ?? ?? ?? 47 57 50 68 ?? ?? ?? ?? 8b ?? ?? c6 07 4c 08 00 8d 35 ?? ?? ?? ?? c6 06}  //weight: 1, accuracy: Low
        $x_1_2 = {29 f6 4e 23 37 83 c7 04 f7 d6 f8 83 de 18 c1 ce 09 d1 c6 01 c6 8d 76 ff 29 c0 29 f0 f7 d8 c1 c0 09 d1 c8 56 8f 03 83 c3 04 83 c2 fc 85 d2 75 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LM_2147714365_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LM!bit"
        threat_id = "2147714365"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 01 8a ?? ?? ?? ?? ?? ?? 32 da 88 1c 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 5d 00 8b ?? ?? ?? 8a ?? ?? ?? 32 d8 46 85 d2 88 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LN_2147714366_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LN!bit"
        threat_id = "2147714366"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 15 ?? ?? ?? ?? 88 84 15 24 00 be ?? ?? ?? ?? 8d bd ?? ?? ?? ?? b9 06 00 00 00 f3 a5 a4 0f bf 05 ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 8b ca 99}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f9 8b 15 ?? ?? ?? ?? 88 84 15 11 00 0f bf 05 ?? ?? ?? ?? 0f be 15 ?? ?? ?? ?? 8b ca 99}  //weight: 1, accuracy: Low
        $x_1_3 = "SnubCicala.bfJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LO_2147714368_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LO!bit"
        threat_id = "2147714368"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a5 66 a5 a4 5e a0 ?? ?? ?? ?? 02 05 ?? ?? ?? ?? 0f bf 15 ?? ?? ?? ?? 88 84 15 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 2a 0d ?? ?? ?? ?? 0f bf 05 ?? ?? ?? ?? 88 8c 05}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f9 0f bf 15 ?? ?? ?? ?? 88 84 15 11 00 0f bf 05 ?? ?? ?? ?? 0f bf 15 ?? ?? ?? ?? 8b ca 99}  //weight: 1, accuracy: Low
        $x_1_3 = "Thong.j" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LS_2147714369_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LS!bit"
        threat_id = "2147714369"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wavtqchqmjy" ascii //weight: 1
        $x_1_2 = "nyzbqgazfzkdfa" ascii //weight: 1
        $x_1_3 = {29 c9 49 23 08 f8 83 d8 fc f7 d1 8d 49 e8 d1 c1 c1 c9 09 01 d1 f8 83 d1 ff 31 d2 4a 21 ca c1 c2 09 d1 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LW_2147716260_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LW"
        threat_id = "2147716260"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 33 85 ?? ?? ff ff 8b 4d ?? 89 01 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 08 8b 08 03 4d 0c 8b 55 08 89 0a 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_LY_2147716342_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.LY!bit"
        threat_id = "2147716342"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 85 c0 89 45 e8 ?? ?? 33 45 ?? ff 45 ?? 8a 4d ?? 33 c6 d3 c8 8b 4d ?? 89 4d ?? 89 02 83 c2 04 4f}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0a 0f b6 c9 8b f9 33 f8 83 e7 0f c1 e8 04 33 04 bd ?? ?? ?? ?? c1 e9 04 8b f8 83 e7 0f 33 cf c1 e8 04 33 04 8d ?? ?? ?? ?? 4e 42 85 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_JJ_2147717908_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.JJ!bit"
        threat_id = "2147717908"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f 84 1b 00 00 00 8b ce c1 e1 05 8b fe c1 ef 02 03 cf 0f be 3a 03 cf 33 f1 42 48 0f 85 e5 ff ff ff}  //weight: 2, accuracy: High
        $x_1_2 = {8b 40 78 83 65 fc 00 03 c1 8b 78 1c 8b 58 24 8b 70 20 8b 40 18 03 f9 03 d9 03 f1}  //weight: 1, accuracy: High
        $x_1_3 = {8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 89 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_JK_2147718087_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.JK!bit"
        threat_id = "2147718087"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 56 8b 4c 24 0c 8b 74 24 10 8b 54 24 14 8b 44 24 18 85 f6 0f 95 c3 74 10 85 c0 74 0c 50 8a 02 30 01 58 42 41 4e 48 eb e9}  //weight: 1, accuracy: High
        $x_1_2 = {8b d7 03 50 24 8b c8 8b c7 03 41 1c 0f b7 14 72 03 3c 90 8b c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_NA_2147718223_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NA!bit"
        threat_id = "2147718223"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = {46 69 6c 65 20 64 65 73 63 72 69 70 74 69 6f 6e [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {61 63 74 69 6f 6e 3d 63 77 00 3f 61 63 74 69 6f 6e 3d 72 77}  //weight: 1, accuracy: High
        $x_1_4 = "gateway.php" ascii //weight: 1
        $x_1_5 = {8b 45 dc 8b 50 04 8b 45 dc 8b 40 08 89 c1 8b 45 d4 29 c1 89 c8 01 d0 83 e8 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_CeeInject_NB_2147718303_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NB!bit"
        threat_id = "2147718303"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 a4 df ff ff 25 ff 90 00 90 8b 4d fc 33 d2 8a 94 0d b4 d2 ff ff 33 c2 8b 4d fc}  //weight: 1, accuracy: High
        $x_1_2 = {70 f8 27 41 6a ?? 8d 95 d4 df ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_NB_2147718303_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NB!bit"
        threat_id = "2147718303"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 e9 ?? 03 4c 24 ?? 8b d7 c1 e2 ?? 03 54 24 ?? 8d 04 3b 33 ca 33 c8 6a 00 2b f1 ff 15 ?? ?? ?? ?? 8b ce c1 e9 ?? 03 4c 24 ?? 8b d6 c1 e2 ?? 03 54 24 ?? 8d 04 33 33 ca 33 c8 2b f9 81 c3 ?? ?? ?? ?? 83 ed 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 06 88 10 8b 55 ?? 41 40 3b ca 72 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ND_2147718350_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ND!bit"
        threat_id = "2147718350"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 00 4e 6f 52 75 6e 00 00 00 4e 6f 44 72 69 76 65 73}  //weight: 1, accuracy: High
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b 00 00 4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b}  //weight: 1, accuracy: High
        $x_2_3 = {0f b7 06 8b c8 c1 e9 0c 25 ?? ?? ?? ?? 83 f9 03 75 ?? 8b 4d 0c 01 0c 18 8b 42 04 83 e8 08 47 d1 e8 83 c6 02 3b f8 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_JL_2147718408_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.JL!bit"
        threat_id = "2147718408"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 fa 0b 8b c2 c1 e8 1f 03 d0 8a 82 ?? ?? ?? 00 32 c1 88 84 15 ?? ?? ?? ff 8a 84 35 ?? ?? ?? ff 3c 3a 77 09 fe c8 88 84 35 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 8d 85 ?? ?? ?? ff ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_NK_2147719009_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NK!bit"
        threat_id = "2147719009"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 0f b6 00 3d cc 00 00 00 74 0d 8b 45 fc 0f b6 00 3d 90 00 00 00 75 06}  //weight: 1, accuracy: High
        $x_1_2 = {89 4d 94 81 7d 94 31 33 24 72 74 1d [0-48] ff 55 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_NK_2147719009_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NK!bit"
        threat_id = "2147719009"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 89 85 ?? ?? ?? ?? 8b 4d ec 03 8d ?? ?? ?? ?? 8b 55 f4 03 95 ?? ?? ?? ?? 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 f8 8b 0d ?? ?? ?? ?? 89 4d f8 8b 45 f8 31 45 fc 8b 55 fc 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 8b e5}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f6 ff 35 ?? ?? ?? ?? 8b f6 33 d2 8d 05 ?? ?? ?? ?? 48 03 10 8b c9 8b c9 8b c9 ff e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_NN_2147719071_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NN!bit"
        threat_id = "2147719071"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 04 4a 8b 8d ?? ?? ?? ?? 0f af 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 2b 95 ?? ?? ?? ?? 03 ca 03 c1 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 08 8b cb 33 f6 66 d1 e8 66 d1 e0 8b 0d ?? ?? ?? ?? 97 8b d9 93 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_NU_2147719135_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NU!bit"
        threat_id = "2147719135"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 14 41 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 2b 8d ?? ?? ?? ?? 03 c1 03 d0 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cb 33 f6 66 d1 e8 66 d1 e0 8b 0d ?? ?? ?? ?? 97 8b d9 93 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_NO_2147719136_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NO!bit"
        threat_id = "2147719136"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d2 8b d0 ff d2 8b d0 89 55 ?? 8b 4d ?? 89 0d}  //weight: 1, accuracy: Low
        $x_1_2 = "interface\\{3050f1f7-98b5-11cf-bb82-00aa00bdce0b}" wide //weight: 1
        $x_1_3 = "4rwet34344" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_NY_2147719663_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NY"
        threat_id = "2147719663"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4d 61 69 6e 00 00 00 00 57 6f 72 6b 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {12 65 63 79 63 6c 2e 02 69 6e 1c 74 61 73 6b 68 6f 73 74 2e 65 78 65 c0}  //weight: 1, accuracy: High
        $x_1_3 = {c0 13 65 72 76 65 72 03 6f 72 65 2e 64 61 74 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_NG_2147719818_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NG!bit"
        threat_id = "2147719818"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 fc ff 35 50 43 43 00 ff 75 e8 ff 75 f4 a1 c4 ab 43 00 a3 e4 ab 43 00 ff 15 e4 ab 43 00}  //weight: 1, accuracy: High
        $x_1_2 = {eb 04 cd 37 cd 37 eb 04 cd 37 cd 37 eb 04 cd 37 cd 37}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 f8 89 45 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 03 55 ?? 8a 02 88 01 8b 4d ?? 83 c1 01 89 4d ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OA_2147720137_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OA!bit"
        threat_id = "2147720137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 02 8b 44 24 ?? 09 c0 8b 54 24 ?? 09 d2 8b 74 24 ?? 89 54 24 ?? 89 44 24 ?? 8b 44 24 ?? 88 1c 06 81 e1 ?? ?? ?? ?? 89 4c 24 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {89 e1 8b 54 24 ?? 89 51 0c 8b 74 24 ?? 89 71 04 89 01 c7 41 08 ?? ?? ?? ?? 8b 44 24 ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OA_2147720137_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OA!bit"
        threat_id = "2147720137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 31 83 f9 3d 7f 14 74 5e 83 e9 2b 74 4f 83 e9 04 74 4f 49 83 e9 0a 72 33 eb 4f}  //weight: 1, accuracy: High
        $x_1_2 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ?? ff 50 8b 85 ?? ?? ?? ff 50 ff 15 ?? ?? ?? 00 89 45 fc 83 7d fc 00 75 19 6a 40 68 00 30 00 00 8b 85 ?? ?? ?? ff 50 6a 00 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {f3 a5 66 81 bd ?? ?? ?? ff 4d 5a 0f 85 ?? ?? ?? 00 a1 ?? ?? ?? 00 33 d2 52 50 8b 85 ?? ?? ?? ff 99 03 04 ?? 13 54 ?? ?? 83 c4 08 8b f0 8d bd 04 ff ff ff b9 3e 00 00 00 f3 a5 81 bd 04 ff ff ff 50 45 00 00 0f 85 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_OC_2147720331_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OC!bit"
        threat_id = "2147720331"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 db 33 1e 83 c6 ?? f7 d3 83 c3 ?? c1 cb ?? d1 c3 01 cb f8 83 d3 ?? 53 59 c1 c1 ?? d1 c9 89 1a 83 ea ?? f8 83 df ?? 81 ff ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OC_2147720331_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OC!bit"
        threat_id = "2147720331"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {29 c9 33 0f 83 ef fc f7 d1 8d 49 e5 c1 c9 09 d1 c1 8d 49 ff 01 f1 31 f6 01 ce c1 c6 09 d1 ce 89 0b 83 eb fc 8d 52 04 81 fa ?? ?? ?? ?? 75 d1}  //weight: 2, accuracy: Low
        $x_1_2 = {ff 33 2e e8 ?? ?? ?? ff 58 c6 05 ?? ?? ?? 00 61 c6 05 ?? ?? ?? 00 73 c6 05 ?? ?? ?? 00 79 c6 05 ?? ?? ?? 00 63 8d 15 ?? ?? ?? 00 42 52 ff 15 ?? ?? ?? 00 50 85 c0 0f 84 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 10 6a 00 6a 08 68 ?? ?? ?? 00 ff 35 ?? ?? ?? 00 6a ff ff d0 8d 1d ?? ?? ?? 00 ff 33 2e e8 ?? ?? ?? ff 8d 0d ?? ?? ?? 00 81 39 ff 0f 00 00 0f 87 ?? ?? ?? 00 81 19 40 02 00 00 0f 82 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {00 00 63 00 78 00 72 00 72 00 66 00 69 00 6c 00 74 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_OE_2147720485_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OE!bit"
        threat_id = "2147720485"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 d8 8b 45 f8 99 8b cf f7 f9 8b ce 89 9c 05 ?? ?? ?? ff 8b 45 f4 99 f7 f9 8a 8c 05 ?? ?? ?? ff 80 f9 3a 8d 84 05 ?? ?? ?? ff 77 04 fe c9}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 45 fc 81 45 08 ?? 00 00 00 db 45 fc 01 7d f8 01 75 f4 dc 1d ?? ?? ?? 00 df e0 9e 72 ?? 68 ?? ?? ?? ?? 8d 85 ?? ?? ?? ff ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_NF_2147720487_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.NF!bit"
        threat_id = "2147720487"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 8b d1 c1 ea ?? 32 14 07 46 88 10 40 3b 75 ?? 7c e3}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 40 52 53 ff d0 ff 55 ?? 5f 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OD_2147720565_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OD!bit"
        threat_id = "2147720565"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 fd 43 03 00 81 c1 ?? ?? ?? ?? 8b d1 c1 ea ?? 32 14 07 46 88 10 40 3b 75 ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 40 52 53 ff d0 ff 55 ?? 5f 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OB_2147720571_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OB!bit"
        threat_id = "2147720571"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8a 04 07 88 45 ?? 8b 45 ?? 0f af 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 4d dc 75 03 8a 4d ?? 88 0c 17}  //weight: 1, accuracy: Low
        $x_1_3 = {84 c0 75 0d 0f b6 0d ?? ?? ?? ?? 0f af c8 29 4d ?? 32 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OB_2147720571_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OB!bit"
        threat_id = "2147720571"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e9 1f 03 d1 8b fa 8d 14 f6 8d 04 d6 8a 4c 3c 10 c1 e0 04 03 c6 80 f1 ec 8d 34 c0 b8 63 20 d5 31 f7 ee c1 fa 0b 8b c2 c1 e8 1f 03 d0 88 8c 14 dc 0a 00 00 8a 84 3c dc 0a 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "mengyuworkroom.y365.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OH_2147720574_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OH!bit"
        threat_id = "2147720574"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 40 80 40 00 03 55 8c a1 74 2a 44 00 03 45 8c 8a 0a 88 08}  //weight: 1, accuracy: High
        $x_1_2 = {74 78 8b 0d ?? ?? ?? ?? 33 d2 8a 51 01 83 ea 4c 85 d2}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 fc a1 30 e0 43 00 89 42 6c 8b 4d fc 51 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_QJ_2147720984_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.QJ!bit"
        threat_id = "2147720984"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 45 e4 0f 43 45 e4 c6 40 ?? ?? 50 90 90 90 90 90 90 90 90 90 90 90 90 58}  //weight: 2, accuracy: Low
        $x_1_2 = {89 37 8b 06 8b 40 ?? 8b 4c 30 ?? 85 c9 74 05 8b 01 ff 50 04}  //weight: 1, accuracy: Low
        $x_1_3 = {72 28 2b 3e 33 c9 c1 ff 02 42 8b c7 d1 e8 2b d8 03 c7 3b df 0f 43 c8 3b ca 0f 43 d1 8b ce 52 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_OI_2147720991_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OI!bit"
        threat_id = "2147720991"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af 11 0f af 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 45 fc 8b 0c 85 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 8b 55 fc 8b 45 d0 89 0c 90}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 e0 c1 e0 ?? 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OJ_2147720992_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OJ!bit"
        threat_id = "2147720992"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {79 05 4a 83 ca ?? 42 85 d2 75 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 8a 82 ?? ?? ?? ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ec 51 8b 45 0c 89 45 fc 8b 4d 08 33 4d fc 89 4d 08 8b 55 fc 83 c2 ?? 89 55 fc 8b 45 08 2d ?? ?? ?? ?? 89 45 08 8b 4d fc 81 e9 ?? ?? ?? ?? 89 4d fc c1 4d 08 ?? 8b 45 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OM_2147720995_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OM!bit"
        threat_id = "2147720995"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 26 0f b7 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 ?? 88 10 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 45 f4 35 ?? ?? ?? ?? 0f b7 0d ?? ?? ?? ?? 33 4d f4 81 f1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ON_2147720996_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ON!bit"
        threat_id = "2147720996"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 ef 8b 0d ?? ?? ?? ?? 03 8d b8 fe ff ff 8b 55 9c 8b 45 d8 8a 14 50 88 11}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 85 c9 a1 c8 ?? 41 00 0b fb 2b f9 93 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OL_2147721028_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OL!bit"
        threat_id = "2147721028"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 10 33 5c 24 ?? 33 5c 24 ?? 33 5c 24 ?? 33 5c 24 ?? 03 5c 24 ?? 2b 5c 24 ?? 2b 5c 24 ?? 03 5c 24 ?? 89 5c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 5c 24 10 33 5c 24 ?? 33 5c 24 ?? 33 5c 24 ?? 8b 7c 24 ?? 03 7c 24 ?? 01 ff 8b 74 24 ?? 03 74 24 ?? 01 f6 29 f7 03 7c 24 ?? 31 fb 89 5c 24}  //weight: 1, accuracy: Low
        $x_2_3 = {bd 30 a0 40 00 89 2d ?? ?? 48 00 ff 35 ?? ?? 48 00 ff 35 ?? ?? 48 00 ff 15 ?? ?? 48 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_RP_2147721060_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RP!bit"
        threat_id = "2147721060"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 8d bd ?? ?? ?? ff b9 10 00 00 00 f3 a5}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 08 8b f0 8d bd 04 ff ff ff b9 3e 00 00 00 f3 a5}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ?? ff 50 6a 00 e8 ?? ?? ?? ff 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_4 = {ff e0 6a 00 e8 ?? ?? ?? ff 1e 00 8b 85 ?? ?? ?? ff 2b 85 ?? ?? ?? ff 3b 45 ?? 0f 82 ?? ?? ?? ff 8b 45 fc 03 85 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RQ_2147721061_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RQ!bit"
        threat_id = "2147721061"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 0d 6a 21 8b 55 e4 83 c2 28 ff d2 83 c4 04 e9 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_2_2 = {6a 40 68 00 30 00 00 68 c5 3e 00 00 6a 00 ff 15 c8 00 01 02 89 45 e4 c7 45 f0 00 00 00 00 8a 95 ?? ?? ?? ff 88 95 ?? ?? ?? ff 8b 8d ?? ?? ?? ff [0-48] 8a 94 05 ?? ?? ?? ff 33 ca [0-32] 8b 55 e4 88 0c 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RR_2147721062_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RR!bit"
        threat_id = "2147721062"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ad c2 10 00 8b 46 14 8b 40 0c 8b 08 33 43 48 c2 08 00}  //weight: 2, accuracy: High
        $x_1_2 = {89 44 24 04 89 04 24 3b 43 4c 0f 86 ?? ?? ?? ff c1 e8 0a 25 ff 00 00 00 3b 43 50 0f 83 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_QX_2147721150_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.QX!bit"
        threat_id = "2147721150"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 cf 8d b1 ?? ?? ?? ?? 8a 16 0f b6 c2 03 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 23 c7 a3 ?? ?? ?? ?? 8d 80 ?? ?? ?? ?? 8a 18 88 10 88 1e 0f b6 00 0f b6 f3 03 f0 81 f9 ?? ?? ?? ?? 73 24}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 30 08 c3}  //weight: 1, accuracy: High
        $x_1_3 = {6a 6b 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 72 66 a3 ?? ?? ?? ?? 58 6a 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RB_2147721153_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RB!bit"
        threat_id = "2147721153"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 33 d2 b9 0f 00 00 00 f7 f1 8a 86 ?? ?? ?? ?? 8a 92 ?? ?? ?? ?? 32 c2 88 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {32 1e 83 c6 04 88 5e 0c 8a 5e fd 32 5c 24 15 88 5e 0d 8a 5e fe 32 5c 24 16 88 5e 0e 8a 5e ff 32 d8 8b 44 24 10 88 5e 0f 40 41}  //weight: 1, accuracy: High
        $x_1_3 = {73 06 89 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 19 30 1c 30 47 41 40 4d 75 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OP_2147721253_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OP!bit"
        threat_id = "2147721253"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b d1 c1 ea 10 30 14 06 8b 55 dc 40 3b c2 7c e4}  //weight: 1, accuracy: High
        $x_1_2 = {a1 08 ec 40 00 88 14 30 8b 55 dc 46 3b f2 72 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OQ_2147721254_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OQ!bit"
        threat_id = "2147721254"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qname\\underrun\\Chernbyl" ascii //weight: 1
        $x_1_2 = {8b 95 70 df ff ff 8b 85 4c df ff ff 33 85 5c df ff ff 88 02}  //weight: 1, accuracy: High
        $x_1_3 = {8b 95 fc fd ff ff 8d 43 08 89 42 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OR_2147721255_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OR!bit"
        threat_id = "2147721255"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f2 33 ce 03 c1 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c9 8b 0d ?? ?? ?? ?? 0b fb 2b fe 87 d9 8b fb ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RS_2147723787_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RS!bit"
        threat_id = "2147723787"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 50 6a 00 a1 ?? ?? ?? ?? 8b 00 ff d0 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 89 02 eb 67 68 c8 00 00 00 e8 ?? ?? ?? ?? 6a 00 a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 8b 00 ff d0 85 c0 76 da a1 ?? ?? ?? ?? 50 6a 00 a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RT_2147724813_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RT!bit"
        threat_id = "2147724813"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 01 69 c0 ?? ?? ?? ?? ff 4d 0c 05 ?? ?? ?? ?? 41 83 7d 0c 00 77 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 04 33 c0 eb ?? 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9}  //weight: 1, accuracy: Low
        $x_1_3 = {88 45 08 8a 45 fe 8a c8 c0 f9 ?? c0 e0 ?? 02 45 ff 80 e1 ?? c0 e2 ?? 32 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RT_2147724813_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RT!bit"
        threat_id = "2147724813"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 01 8b 40 0c 8b 40 0c 8b 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 00 8b 40 18 89 45 f8}  //weight: 1, accuracy: High
        $x_1_3 = {68 4d 12 1f 52 57 89 46 58}  //weight: 1, accuracy: High
        $x_1_4 = {50 c7 45 e4 ?? ?? ?? ?? c7 45 e8 ?? ?? ?? ?? ff 56 48 89 45 fc}  //weight: 1, accuracy: Low
        $x_5_5 = {8b c1 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 c6 ?? ?? ff 06 81 3e ?? ?? ?? ?? 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RT_2147724813_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RT!bit"
        threat_id = "2147724813"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "That plumber lent her a lot of money" ascii //weight: 1
        $x_1_2 = "Joe struck him a heavy blow" ascii //weight: 1
        $x_1_3 = "That guard sold him a ticket" ascii //weight: 1
        $x_1_4 = "That journalist showed them a photograph" ascii //weight: 1
        $x_1_5 = "That carpenter struck him a heavy blow" ascii //weight: 1
        $x_1_6 = "Lesters ex-wife orders her a new hat" ascii //weight: 1
        $x_1_7 = "Willie bought her a gift Jackie strikes him a heavy blow" ascii //weight: 1
        $x_1_8 = "Stephen struck him a heavy blow" ascii //weight: 1
        $x_1_9 = "Those police officers offered her a ride home" ascii //weight: 1
        $x_1_10 = "That student saved her a seat Betty gives him a magazine" ascii //weight: 1
        $x_1_11 = "Ed ordered her a new dress Abraham gives him a magazine" ascii //weight: 1
        $x_1_12 = "Those scientists told her the shortest way" ascii //weight: 1
        $x_1_13 = "Miss Johnson envied him his good fortune That janitor shows them a picture" ascii //weight: 1
        $x_1_14 = "Abraham brought her a small present Debbie taught them English" ascii //weight: 1
        $x_1_15 = "Ned sends him a package Those taxi drivers make him some coffee" ascii //weight: 1
        $x_1_16 = "That manager read the children a story" ascii //weight: 1
        $x_1_17 = "That teacher wrote her a letter" ascii //weight: 1
        $x_1_18 = "Albert lends him a pencil" ascii //weight: 1
        $x_1_19 = "Ann Lynn sent him a package Willie bought her a gift" ascii //weight: 1
        $x_1_20 = "Joannes mother offers her a bribe Those science teachers buy her a gift" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_SB_2147724815_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SB!bit"
        threat_id = "2147724815"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d8 8b 45 fc 69 c0 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 88 9c 05 ?? ?? ?? ?? 8b 45 fc 69 c0 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 33 d2 8a 94 05 ?? ?? ?? ?? 83 fa}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 69 c0 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 33 d2 8a 94 05 ?? ?? ?? ?? 8b ca 83 e9 01 8b 45 fc 69 c0 ?? ?? ?? ?? 99 be ?? ?? ?? ?? f7 fe 88 8c 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SC_2147724919_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SC!bit"
        threat_id = "2147724919"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 37 88 14 1e 83 fe ?? 75 ?? 8d 45 f0 50 6a ?? 68 ?? ?? ?? ?? 53 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d7 c1 ea ?? 03 55 ?? 8b c7 c1 e0 ?? 03 45 ?? 8d 0c 3b 33 d0 33 d1 2b f2 8b d6 c1 ea ?? 03 55 ?? 8b c6 c1 e0 ?? 03 45 ?? 8d 0c 33 33 d0 33 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TD_2147724933_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TD!bit"
        threat_id = "2147724933"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8a 08 32 4d 13 02 4d 13 88 08 40 89 45 08 b8 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 ?? ?? ?? ?? f7 c7 03 00 00 00 75 14 c1 e9 02 83 e2 03 83 f9 08 72 29 f3 a5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TI_2147724935_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TI!bit"
        threat_id = "2147724935"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 6a 00 ff 15 ?? ?? ?? ?? 69 0d 64 66 41 00 fd 43 03 00 8d 04 1e 6a 00 81 c1 c3 9e 26 00 89 0d 64 66 41 00 c1 e9 10 30 08 ff 15 ?? ?? ?? ?? 46 3b 75 fc 7c ca}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fe 05 75 09 c6 05 ?? ?? ?? ?? 41 eb 4c 83 fe 06 75 09 c6 05 ?? ?? ?? ?? 6c eb 3e 83 fe 07 75 09 c6 05 ?? ?? ?? ?? 6c eb 30 83 fe 08 75 09 c6 05 ?? ?? ?? ?? 6f eb 22 83 fe 09 75 09 c6 05 ?? ?? ?? ?? 63}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 04 0e 8d 49 01 88 41 ff 42 8b 45 fc 3b d0 72 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TL_2147725019_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TL!bit"
        threat_id = "2147725019"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 d2 75 09 8b 45 ?? 83 c0 03 89 45 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 8a 82 ?? ?? ?? 00 88 01 eb b6}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 73 13 8b 55 ?? 03 55 ?? 8b 45 ?? 8a 88 ?? ?? ?? 00 88 0a eb db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TL_2147725019_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TL!bit"
        threat_id = "2147725019"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04}  //weight: 1, accuracy: High
        $x_1_2 = {8a 00 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 71 ?? e8 ?? ?? ?? ?? 83 c4 08 5a 88 10}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 71 05 e8 ?? ?? ?? ?? 83 c4 08 32 0d ?? ?? ?? ?? 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ME_2147732292_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ME!bit"
        threat_id = "2147732292"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 0b 07 83 ef ?? f7 d0 f8 83 d8 ?? c1 c8 ?? d1 c0 01 f0 8d 40 ?? 8d 30 c1 c6 ?? d1 ce 50 8f 02 f8 83 da ?? 83 c1 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 de 51 8d 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 8d 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 51 8d 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 51 8d 05 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ME_2147732292_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ME!bit"
        threat_id = "2147732292"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 11 33 95 ?? fe ff ff 8b 85 ?? fe ff ff 03 85 ?? fe ff ff 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 48 06 39 4d ?? 0f 8d ?? ?? 00 00 8b 55 ?? 8b 45 ?? 03 42 3c 8b 4d ?? 6b c9 ?? 8d 94 08 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 8b 55 ?? 8b 42 ?? 50 8b 4d ?? 8b 55 ?? 03 51 ?? 52 8b 45 ?? 8b 4d ?? 03 48 ?? 51 8b 55 ?? 52 a1 ?? ?? ?? 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TW_2147732293_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TW!bit"
        threat_id = "2147732293"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 8a 00 ?? ?? ?? ?? ?? ?? ?? 34 28 8b 15 ?? ?? ?? ?? 03 d3 88 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 43 01 bf 75 00 00 00 33 d2 f7 f7 8b c1 03 c3 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UA_2147732298_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UA!bit"
        threat_id = "2147732298"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 35 8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 8b 45 08 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 00 88 45 ?? 90 8b 45 ?? 89 45 ?? 80 75 ?? d4 8b 45 ?? 03 45 ?? 73 05 e8 ?? ?? ?? ?? 8a 55 ?? 88 10}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 08 05 4d 36 00 00 73 05 e8 ?? ?? ?? ?? 89 45 ?? ff 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MF_2147732300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MF!bit"
        threat_id = "2147732300"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 fd 43 03 00 81 c1 ?? ?? ?? ?? 8b d1 c1 ea ?? 32 14 07 46 88 10 40 3b 75 f8 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f8 8d 4d ?? 51 6a 40 52 53 ff d0 ff 55 ?? 5f 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MG_2147732301_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MG!bit"
        threat_id = "2147732301"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 ?? 0f b6 02 0f b6 0d ?? ?? ?? ?? 33 c1 8b 55 0c 03 55 ?? 88 02 8b 45 0c 03 45 ?? 0f b6 08 0f b6 15 ?? ?? ?? ?? 2b ca 8b 45 0c 03 45 ?? 88 08 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 6b 05 ?? ?? ?? ?? 05 50 6a 00 ff 15 ?? ?? ?? ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MH_2147732302_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MH!bit"
        threat_id = "2147732302"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 37 8d 3c c7 03 3d ?? ?? ?? ?? 03 fe 03 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {88 0f 33 c9 41 2b 8d ?? ?? ?? ?? 8b d3 0f af 95 ?? ?? ?? ?? 2b c8 0f af ce 2b ca 0f af cb c1 e0 02 03 c8 0f af 8d ?? ?? ?? ?? 29 8d ?? ?? ?? ?? ff 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 3b 45 ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MJ_2147732303_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MJ!bit"
        threat_id = "2147732303"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 0f af c1 0f af c1 0f af c6 6a ?? 99 5f f7 ff 8b 7d ?? 01 45 ?? 8a c1 32 07 3b f3 75 ?? 8a 45 ?? 88 07}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c1 81 c7 ?? ?? ?? ?? 41 0f af f1 69 f6 ?? ?? ?? ?? 52 ff 75 ?? 89 35 ?? ?? ?? ?? ff 75 ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MJ_2147732303_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MJ!bit"
        threat_id = "2147732303"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 0a 00 00 00 6a 00 33 c9 58 f7 f1}  //weight: 1, accuracy: High
        $x_1_2 = {68 d2 07 00 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 3d 0c 03 00 00 76}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 a9 6d f1 f3 8b c0 49 75}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b c8 c1 e1 04 2b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MK_2147732304_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MK!bit"
        threat_id = "2147732304"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d a0 03 4d e4 8b 55 f0 03 55 bc 66 8b 01 66 89 02 8a 49 02 88 4a 02}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 03 45 fc 0f b6 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 33 ca 8b 45 08 03 45 fc 88 08 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {7d 1b 8b 55 ?? 03 55 ?? 0f b6 02 8b 4d ?? 6b c9 ?? 33 c1 8b 55 ?? 03 55 ?? 88 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MK_2147732304_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MK!bit"
        threat_id = "2147732304"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "==wVlxGZuFGSlxWdk9WT0V2R" wide //weight: 1
        $x_1_2 = "==Qey9Wbl1UZ29WTsRnU" wide //weight: 1
        $x_1_3 = "==wVlRXdjVGeFxGblh2U" wide //weight: 1
        $x_1_4 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide //weight: 1
        $x_1_5 = "swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM\\erawtfoS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_UB_2147732305_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UB!bit"
        threat_id = "2147732305"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 8b 45 08 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 45 ?? 8b 45 ?? 03 45 ?? 8a 00 88 45 [0-16] 8b 45 ?? 89 45 [0-16] 80 75 [0-16] 8b 45 ?? 03 45 ?? 8a 55 ?? 88 10}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 08 05 df 1e 00 00 89 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MN_2147732306_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MN!bit"
        threat_id = "2147732306"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c8 88 82 ?? ?? ?? ?? 32 0d ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 32 c1 88 8a ?? ?? ?? ?? 32 05 ?? ?? ?? ?? 8a 8a ?? ?? ?? ?? 32 c8 88 82 ?? ?? ?? ?? 32 0d ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 32 c1 88 8a ?? ?? ?? ?? 32 05 ?? ?? ?? ?? 88 82}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 81 0f e3 41 00 32 05 10 e3 41 00 30 81 10 e3 41 00 41 83 f9 12 72 e8}  //weight: 1, accuracy: High
        $x_1_3 = {56 57 8d 45 f1 50 ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8b f8 6a 73 57 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MO_2147732307_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MO!bit"
        threat_id = "2147732307"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 60 40 41 00 03 45 d8 8b 4d f0 8b 95 48 fe ff ff 8a 0c 8a 88 08}  //weight: 1, accuracy: High
        $x_1_2 = {8d 44 0a 0a 89 45 ec 8b 0d 60 40 41 00 03 4d d8 0f be 11 03 95 9c fd ff ff a1 60 40 41 00 03 45 d8 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MP_2147732308_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MP!bit"
        threat_id = "2147732308"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 2a 8b 45 ?? 89 85 ?? ?? ?? ?? 8b 4d ?? 03 8d ?? ?? ?? ?? 8b 55 ?? 03 95 ?? ?? ?? ?? 8a 02 88 01 8b 4d ?? 83 c1 01 89 4d ?? eb bc}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 ec e1 14 00 00 8b 0d ?? ?? ?? ?? 3b 0d ?? ?? ?? ?? 72 02 eb ?? eb 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c9 ff 35 ?? ?? ?? ?? 8b c9 ff 35 ?? ?? ?? ?? 33 d2 8d 05 ?? ?? ?? ?? 48 48 03 10 8b c0 52 8b c0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MX_2147732314_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MX!bit"
        threat_id = "2147732314"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 ?? 81 7d ?? ?? ?? ?? ?? 7d 16 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 55 ?? 8a 82 ?? ?? ?? ?? 88 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 03 00 00 00 f7 f9 85 d2 74 30 0f b7 15 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 75 1c a1 ?? ?? ?? ?? 03 45 ?? 0f be 08 81 f1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 88 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {75 1c 8b 0d ?? ?? ?? ?? 03 4d f4 0f be 11 81 f2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 f4 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MY_2147732315_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MY!bit"
        threat_id = "2147732315"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 01 51 8b 15 ?? ?? ?? ?? 52 8b 45 ?? 50 6a 00 8b 4d ?? 51 ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 33 eb 01 c3 8b 45 ?? 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 8a 02 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 08 33 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {8b ff 8b c9 8b ff 50 8b ff 8b c9 8b ff c3}  //weight: 1, accuracy: High
        $x_1_5 = {8b c9 8b c9 33 c9 8d 05 ?? ?? ?? ?? 48 03 08 51 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_CeeInject_MZ_2147732316_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MZ!bit"
        threat_id = "2147732316"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4d ff 30 0c 30 40 3b 07 7c f5}  //weight: 1, accuracy: High
        $x_1_2 = {e8 b9 86 00 00 99 b9 17 00 00 00 f7 f9 8d b5 ?? ?? ?? ?? 8d 5a 61 e8 ?? ?? ?? ?? 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MZ_2147732316_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MZ!bit"
        threat_id = "2147732316"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 01 e9 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 0c 8b 40 0c e9 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 18 89 04 24 e9 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {83 65 fc 00 03 c1 8b 78 1c 8b 58 24 8b 70 20 8b 40 18 03 f9 e9 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_2_5 = {0f be 3a 03 cf 33 f1 42 e9 ?? ?? ?? ff}  //weight: 2, accuracy: Low
        $x_3_6 = {68 22 02 bf 8a 57 e8 ?? ?? ?? 00 8b d8 e9 ?? ?? ?? 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_XF_2147732322_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.XF!bit"
        threat_id = "2147732322"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 b0 57 01 04 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 b0 57 01 04 c1 e8 10 25 ff 7f 00 00 c3}  //weight: 1, accuracy: High
        $x_1_2 = {ff 15 04 10 00 04 81 fe a9 c3 00 00 7e 27 81 bc 24 e0 01 00 00 e4 86 00 00 74 1a 81 bc 24 e4 01 00 00 20 40 3c 00 74 0d 81 bc 24 04 02 00 00 4f b7 23 00 75 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_XP_2147732329_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.XP!bit"
        threat_id = "2147732329"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 ef be ad de e8 [0-4] 89 04 24 8b 1c 24 43 39 0b 75 fb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4b 04 89 4c 24 04 8b 4b 08 89 4c 24 08 83 c3 0c 89 5c 24 0c 33 db 8b 54 24 0c 8b 12 33 d3 3b 54 24 08 74 03 43 eb ef}  //weight: 1, accuracy: High
        $x_1_3 = {8b 54 24 0c 33 c9 31 1c 0a 3b 4c 24 04 7d 05 83 c1 04 eb f2 8b e5 5d 5b ff e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_XQ_2147732331_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.XQ!bit"
        threat_id = "2147732331"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 73 70 72 69 6e 74 66 28 70 20 72 35 2c 20 74 20 27 25 73 25 73 25 73 25 73 25 73 25 69 25 73 27 2c [0-32] 64 6c 6c 3a 3a 4e 74 43 27 2c 20 74 20 27 72 65 61 74 27 2c 20 74 20 27 65 53 65 63 74 27 2c 20 74 20 27 69 6f 6e 28}  //weight: 1, accuracy: Low
        $x_1_2 = {75 73 65 72 33 32 3a 3a 77 73 70 72 69 6e 74 66 28 70 20 72 35 2c 20 74 20 27 6c 6c 3a 3a 25 73 25 73 25 73 25 73 25 64 27 20 2c 20 74 20 27 4e 74 4d 27 2c [0-32] 27 61 70 56 69 27}  //weight: 1, accuracy: Low
        $x_1_3 = "kernel32::ReadFile(i r10, p r11," ascii //weight: 1
        $x_1_4 = {75 73 65 72 33 32 3a 3a 77 73 70 72 69 6e 74 66 28 70 20 20 72 35 2c 20 74 [0-32] 3a 3a 25 64 25 73 [0-32] 69 20 72 31 32 2c 20 74 20 27 28 27 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_XS_2147732333_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.XS!bit"
        threat_id = "2147732333"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HK]M[EY_CUR]M[RENT_US]M[ER\\Sof]M[twar]M[e\\Mi]M[cro]M[soft\\W]M[indo]M[ws\\Cu]M[rre]M[ntVe]M[rsion\\R]M[un" wide //weight: 1
        $x_1_2 = "s]L[hel]L[lco]L[de" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_XW_2147732339_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.XW!bit"
        threat_id = "2147732339"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 04 0f 99 bb ?? ?? ?? ?? f7 fb 8b 45 ?? 8a 04 02 30 01 ff 4d ?? ff 45 ?? 41 81 7d ?? 00 04 00 00 7f 05 39 75 ?? 75 d8}  //weight: 2, accuracy: Low
        $x_2_2 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 45 ?? 8a 0c 02 8b 45 ?? 30 08 ff 45 ?? 8b 4d ?? 40 3b 4d ?? 89 45 ?? 7c d9}  //weight: 2, accuracy: Low
        $x_1_3 = {6a 40 03 df 8b 43 50 8b 4b 34 68 00 30 00 00 50 51 ff 75 ?? 89 4d ?? 8b 53 28 89 55 ?? ff 55}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 14 39 89 10 83 c1 28 83 c0 04 3b 4d ?? 7c f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AAI_2147732388_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAI!bit"
        threat_id = "2147732388"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 39 4d 5a 0f 85 ?? ?? ?? ?? 8b 41 3c 68 00 01 00 00 03 c1 50 a3 ?? ?? ?? ?? ff d3 85 c0 75 71 a1 ?? ?? ?? ?? 66 81 38 50 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 0c 03 75 08 b0 08 22 e0 a1 ?? ?? ?? ?? 03 f0 66 33 c0 8a 25 ?? ?? ?? ?? 80 e2 19 0a d9 30 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MM_2147732391_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MM!bit"
        threat_id = "2147732391"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 68 93 03 00 6a 00 ff d0 a3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 06 83 c6 04 33 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? c1 c0 ?? c1 c0 ?? ab 81 fe ?? ?? ?? ?? 7e da ff 35 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MM_2147732391_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MM!bit"
        threat_id = "2147732391"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 a4 df ff ff 25 ff 90 00 90 8b 4d fc 33 d2 8b 94 0d b4 d2 ff ff 33 c2 8b 4d fc 87 84 0d ac df ff ff 8b 55 fc 33 c0 8a 84 15 ac df ff ff 83 f8 3a 7f 19 8b 4d fc 33 d2 8a 94 0d ac df ff ff 83 ea 01 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {70 f8 27 41 6a 90 8d 95 d4 df ff ff ff d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SH_2147732392_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SH!bit"
        threat_id = "2147732392"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 6a 00 56 50 6a 00 6a 00 53 a1 ?? ?? ?? ?? 8b 00 ff d0 8b f8 80 7d 08 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {89 3b 83 c3 ?? 8b d7 2b 55 ?? 0f af 55 ?? 8b 45 ?? 0f af 45 ?? 03 c3 33 c9}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c3 83 c0 ?? 8b d7 0f af 55 ?? 03 c2 8b 4d ?? 2b cf 8b d6 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SN_2147732393_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SN!bit"
        threat_id = "2147732393"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8a 08 32 4d ec 8b 55 08 88 0a 8b 45 08 8a 08 02 4d ec 8b 55 08 88 0a}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 10 25 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 81 c2}  //weight: 1, accuracy: Low
        $x_1_3 = {8a c1 3c 61 7c 06 3c 7a 7f 02 24}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4d f8 8b 51 24 81 e2 ?? ?? ?? ?? f7 da 1b d2 f7 da 89 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SX_2147732394_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SX!bit"
        threat_id = "2147732394"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 07 c1 e0 02 33 d2 8a 57 01 c1 ea 04 0a c2 8b 15 ?? ?? ?? ?? 8b 0e 88 04 0a e8 ?? ?? ?? ?? ff 06 ff 05 ?? ?? ?? ?? 4b 75}  //weight: 1, accuracy: Low
        $x_1_2 = {75 34 8a 15 ?? ?? ?? ?? c1 e2 04 25 ?? ?? ?? ?? c1 e8 02 0a d0 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 54 08 01 8b 15 ?? ?? ?? ?? 83 c2 02 ff 05 ?? ?? ?? ?? 8b c2}  //weight: 1, accuracy: Low
        $x_1_3 = {33 db 8a da 83 fb 3d 7f ?? 74 ?? 83 eb 2b 74 ?? 83 eb 04 74 ?? 4b 83 eb 0a 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SY_2147732395_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SY!bit"
        threat_id = "2147732395"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 33 d2 b9 1d f3 01 00 f7 f1 8b c8 b8 a7 41 00 00 f7 e2 8b d1 8b c8 b8 14 0b 00 00 f7 e2 2b c8 33 d2 8b c1 8b d9 f7 75 0c}  //weight: 1, accuracy: High
        $x_1_2 = {b8 4d 5a 00 00 66 39 01 75 f3 8b 41 3c 03 c1 81 38 50 45 00 00 75 e6 b9 ?? ?? ?? ?? 66 39 48 18 75 db}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 75 18 8b 35 ?? ?? ?? ?? 8b ce ff 75 14 33 35 ?? ?? ?? ?? 83 e1 1f ff 75 10 d3 ce ff 75 0c ff 75 08 85 f6 75 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TA_2147732396_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TA!bit"
        threat_id = "2147732396"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 d2 74 7f 52 ac 30 07 47 5a 4a e2 f3 5b 5e 33 c0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {b8 c1 00 00 00 89 44 24 04 b9 ?? ?? ?? ?? 89 4c 24 08 b8 14 00 00 00 89 44 24 0c 8d 15 ?? ?? ?? ?? 89 14 24 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TQ_2147732397_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TQ!bit"
        threat_id = "2147732397"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 43 01 be ?? ?? ?? ?? 33 d2 f7 f6 8b c1 03 c3 88 10 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c3 8a 00 [0-16] 34 dc 8b 15 ?? ?? ?? ?? 03 d3 88 02 [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TQ_2147732397_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TQ!bit"
        threat_id = "2147732397"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f3 88 dd 88 4c 24 ?? 88 e9 8b 5c 24 ?? d3 e3 89 5c 24 ?? 8a 4c 24 ?? 88 0a 8b 54 24 ?? 81 c2 ?? ?? ?? ?? 8b 5c 24 ?? 83 d3 00 8b 7c 24 ?? 01 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1c 11 8a bc 02 ?? ?? ?? ?? 28 fb 8b 44 24 ?? 88 1c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TQ_2147732397_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TQ!bit"
        threat_id = "2147732397"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 7e 08 89 56 04 c7 46 0c 04 00 00 00 c7 06 00 00 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 50 8a 1c 15 ?? ?? ?? ?? 35 ?? ?? ?? ?? 8b 54 24 ?? 8a 3c 0a 8b 74 24 ?? 8b 7c 24 ?? 29 fe 28 df 89 74 24 ?? 8b 74 24 ?? 88 3c 0e 01 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 00 8b 44 24 ?? 8b 4c 24 ?? 81 c1 ?? ?? ?? ?? 8a 10 89 4c 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TT_2147732398_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TT!bit"
        threat_id = "2147732398"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 39 49 75 fa}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 89 0c ?? 33 c9 03 c8 8b f9 59 6a 00 89 04 ?? 33 c0 03 c7 89 83 ?? ?? ?? ?? 58 6a 00 89 04 ?? 2b c0 0b 83 ?? ?? ?? ?? 8b f0 58 6a 00 89 3c ?? 33 ff 0b bb ?? ?? ?? ?? 8b cf 5f f3 a4}  //weight: 1, accuracy: Low
        $x_1_3 = {52 59 03 cb 8b d1 59 23 d9 55 8b e8 33 eb 8b c5 5d ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TT_2147732398_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TT!bit"
        threat_id = "2147732398"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 f7 ff 0f b6 9a ?? ?? ?? ?? c1 e3 1b 8b d1 c1 e2 18 33 da c1 eb 18 88 1c 31 41 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 e9 8b d9 c1 fb 1f 03 d1 c1 fa 09 2b d3 69 d2 ef 02 00 00 f7 da 03 d1 0f b6 1c 32 30 1f 47 41}  //weight: 1, accuracy: High
        $x_1_3 = {f7 e9 8b f1 c1 fe 1f c1 fa 08 2b d6 69 d2 9a 04 00 00 47 f7 da 8b 74 24 ?? 03 d1 0f b6 14 32 41 30 13 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TV_2147732399_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TV!bit"
        threat_id = "2147732399"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 83 c4 08 8a 00 32 05 ?? ?? ?? ?? 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 83 c4 08 5a 88 10 41 4b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TV_2147732399_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TV!bit"
        threat_id = "2147732399"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 ?? 0f b6 08 0f b6 55 ?? 33 ca 8b 45 ?? 88 8c 05 ?? ?? ?? ?? 8b 4d ?? 83 c1 01 89 4d ?? 0f b6 4d ?? 8b 45 ?? 99 be 85 00 00 00 f7 fe 6b d2 03 03 ca 81 e1 ff 00 00 00 88 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e2 05 b8 01 00 00 00 6b c8 00 0f be 94 0a ?? ?? ?? ?? 85 d2 74 1f 8b 45 ?? c1 e0 05 05 ?? ?? ?? ?? 50 8b 4d ?? 83 c1 01 c1 e1 05 03 4d ?? 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {7d 2d 6b 45 ?? 28 8b 4d ?? 6b 55 ?? 28 8b 75 ?? 8b 5d 08 03 5c 16 14 6b 55 ?? 28 8b 75 ?? 8b 7d ?? 03 7c 16 0c 8b f3 8b 4c 01 10 f3 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TX_2147732400_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TX!bit"
        threat_id = "2147732400"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 14 18 8a 12 80 f2 bd 8d 0c 18 88 11}  //weight: 1, accuracy: High
        $x_1_2 = {8d 41 01 51 b9 ee 00 00 00 33 d2 f7 f1 59 03 ce 88 11}  //weight: 1, accuracy: High
        $x_1_3 = {30 30 45 40 42 42 54 60 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TX_2147732400_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TX!bit"
        threat_id = "2147732400"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 03 f3 73 05 e8 ?? ?? ?? ?? 8a 16 80 f2 4d 88 16 40 3d ?? ?? ?? ?? 75 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c3 a9 0a 00 00 73 05 e8 ?? ?? ?? ?? 89 5d fc ff 65 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TN_2147732401_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TN!bit"
        threat_id = "2147732401"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 40 89 45 08}  //weight: 1, accuracy: High
        $x_1_2 = {03 cf 8b f8 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4}  //weight: 1, accuracy: High
        $x_1_3 = {8a c1 3c 61 7c 06 3c 7a 7f 02 24 df c3}  //weight: 1, accuracy: High
        $x_1_4 = {8b 07 8b c8 8b d0 c1 e9 1d c1 ea 1e 8b f0 83 e1 01 83 e2 01 c1 ee 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TN_2147732401_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TN!bit"
        threat_id = "2147732401"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shutdown -s -t" ascii //weight: 1
        $x_1_2 = {8d 48 fb 30 4c 05 ?? 40 83 f8 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 34 08 8d 50 fb 40 30 16 83 f8 ?? 72 f2}  //weight: 1, accuracy: Low
        $x_1_4 = {0f be d3 8d 76 01 c1 c8 0d 80 fb 61 8a 1e 8d 4a e0 0f 4c ca 03 c1 84 db 75 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TN_2147732401_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TN!bit"
        threat_id = "2147732401"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 8b 75 ?? 88 14 06 8b 7d ?? 81 f7 ?? ?? ?? ?? 89 7d ?? 83 c0 01 8b 7d ?? 39 f8 89 45 06 00 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c8 31 d2 8b 74 24 ?? f7 f6 8b 7c 24 ?? 8a 1c 0f 2a 1c 15 ?? ?? ?? ?? 8b 54 24 ?? 88 1c 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TN_2147732401_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TN!bit"
        threat_id = "2147732401"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 07 89 45 ?? 33 45 ?? 43 33 45 ?? 8a cb d3 c8 8b 4d ?? 83 c7 04 89 4d ?? 89 06 83 c6 04 4a 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 07 32 55 0c 88 10 40 49 75 f4}  //weight: 1, accuracy: High
        $x_1_3 = {8a 0f 0f b6 e8 0f b6 c9 33 e9 83 e5 0f c1 e8 04 33 04 ad ?? ?? ?? ?? c1 e9 04 8b e8 83 e5 0f 4a 33 cd c1 e8 04 47 33 04 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TN_2147732401_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TN!bit"
        threat_id = "2147732401"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 31 d2 8b 74 24 ?? f7 f6 8b 7c 24 ?? 8a 1c 15 ?? ?? ?? ?? 89 7c 24 ?? 8b 54 24 ?? 8a 3c 0a 28 df 8b 7c 24 ?? 88 3c 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c1 83 e1 07 8a 14 05 ?? ?? ?? ?? 2a 14 0d ?? ?? ?? ?? 88 54 04 ?? 83 c0 01 89 44 24 ?? 83 f8 0e 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {31 c0 8b 4c 24 ?? 8b 51 3c 01 d1 8b 74 24 ?? 8b 14 16 81 fa 50 45 00 00 0f 44 c1 89 c1 83 c1 06 66 83 78 06 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TU_2147732403_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TU!bit"
        threat_id = "2147732403"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 db 33 db a1 ?? ?? ?? ?? 03 c3 8a 00 ?? ?? ?? ?? 89 db ?? ?? ?? ?? ?? ?? ?? ?? 34 16 8b 15 ?? ?? ?? ?? 03 d3 88 02 89 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 8a 00 50 8b c7 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 5a 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TU_2147732403_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TU!bit"
        threat_id = "2147732403"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 8b d6 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 04 0e 46 3b 74 24 0c 72}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b cf 8b c7 c1 e9 05 03 4d ?? c1 e0 04 03 45 ?? 33 c8 8d 04 3e 33 c8 2b d9 8b cb 8b c3 c1 e9 05 03 4d ?? c1 e0 04 03 45 ?? 33 c8 8d 04 1e 33 c8 8d b6 ?? ?? ?? ?? 2b f9 83 6d fc 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TY_2147732404_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TY!bit"
        threat_id = "2147732404"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 83 e2 03 8a 14 0a 30 14 38 40 3b c6 72 f0}  //weight: 1, accuracy: High
        $x_1_2 = {8b c3 c1 e8 08 8b d3 88 19 c1 eb 18 88 41 01 c1 ea 10 33 c0 88 59 03 88 51 02}  //weight: 1, accuracy: High
        $x_1_3 = {0f af c6 03 c0 03 c0 03 c0 bb ?? ?? ?? ?? 6a 01 2b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TY_2147732404_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TY!bit"
        threat_id = "2147732404"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8b 4d 18 03 4d f0 0f b6 09 33 8c 85 ?? ?? ?? ff 8b 45 18 03 45 f0 88 08}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 4d 08 03 48 10 89 4d ?? e8 ?? ?? ?? 00 6a 00 ff 75 0c ff 75 08 ff 55 ?? 89 45 ?? e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_XY_2147732406_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.XY!bit"
        threat_id = "2147732406"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 6c 33 32 c6 44 24 ?? 00 ff d3 a3}  //weight: 1, accuracy: Low
        $x_1_2 = {00 10 56 8b f8 ff 15 ?? ?? 00 10 68 ?? ?? 00 10 8b f0 ff d7 6a 00 ff d6}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c1 99 f7 fe 8a 04 2a 30 04 19 41 4f 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_AAU_2147732410_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAU!bit"
        threat_id = "2147732410"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 0f 8a 8d ?? ?? ?? ?? 8b 55 08 80 f1 ?? 88 4a 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 0c 80 c1 e1 03 8b d1 c1 e9 02 8d bd ?? ?? ?? ?? f3 a5 8b ca 83 e1 03 f3 a4}  //weight: 1, accuracy: Low
        $x_1_3 = {32 da 88 19 8b 8d ?? ?? ?? ?? 8a 94 29 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8a 8c 28 ?? ?? ?? ?? 8d 84 28 ?? ?? ?? ?? 32 ca 88 08}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 19 8a 94 2a ?? ?? ?? ?? 32 da 88 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAV_2147732411_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAV!bit"
        threat_id = "2147732411"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 04 24 bf ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 83 ec 04 89 3c 24 bb ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 83 ec 04 89 1c 24 be 00 00 00 00 83 ec 04 89 34 24 be ?? ?? ?? ?? 83 ec 04 89 34 24 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c9 2b 0a f7 d9 83 c2 04 8d 49 dd 01 f9 49 8d 39 c6 06 00 01 0e 83 ee fc 83 c3 fc 83 fb 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAW_2147732412_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAW!bit"
        threat_id = "2147732412"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 07 6b c6 47 ?? 65 c6 47 ?? 72 c6 47 ?? 6e c6 47 ?? 65 c6 47 ?? 6c c6 47 ?? 33}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 3a 83 ea ?? 4a f7 d7 83 ef ?? 4f 01 cf 83 ef 01 31 c9 01 f9 57 8f 46 00 83 c6 05 4e 83 c3 ?? 4b 8d 3d ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? ff e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UJ_2147732426_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UJ!bit"
        threat_id = "2147732426"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 03 4d f8 ?? ?? 8a 19 80 f3 ?? 88 19}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 05 ?? ?? ?? ?? 89 45 fc ?? ?? ff 65 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 40 68 ?? ?? ?? ?? 8b 45 fc 50 ff 55 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UM_2147732427_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UM!bit"
        threat_id = "2147732427"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe e6 26 00 00 7d 07 53 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 37 83 ee 01 79 e4}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 c2 03 c8 0f b6 c1 5e 8a 80 07 00 0f b6 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UQ_2147732428_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UQ!bit"
        threat_id = "2147732428"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 ?? c1 ea 05 03 54 24 ?? 33 c2 33 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cf 53 e8 ?? ?? ?? ?? 8b 54 24 ?? 2b f0 53 ff 74 24 ?? 8b ce e8 ?? ?? ?? ?? 2b f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UR_2147732429_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UR!bit"
        threat_id = "2147732429"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 2d 8b 55 ?? 0f b6 8c 15 ?? ?? ?? ?? 8b 45 ?? 99 be 06 00 00 00 f7 fe 0f b6 94 15 ?? ?? ?? ?? 33 ca 51 8b 45 ?? 50 8d 4d ac e8}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 89 4d ?? 8b 45 ?? 8b 08 8b 55 08 8a 45 0c 88 04 11 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_XZ_2147732431_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.XZ!bit"
        threat_id = "2147732431"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 73 70 72 69 6e 74 66 28 70 [0-16] 27 25 73 25 73 25 73 25 73 25 73 25 69 25 73 27 [0-16] 27 6e 74 [0-32] 64 6c 6c 3a 3a 4e 74 43 27 [0-16] 27 72 65 61 74 [0-16] 65 53 65 63 74}  //weight: 1, accuracy: Low
        $x_1_2 = {77 73 70 72 69 6e 74 66 28 70 [0-48] 25 73 25 73 25 73 25 73 25 64 [0-32] 61 70 56 69 [0-32] 65 77 4f [0-32] 66 53 65 63 74}  //weight: 1, accuracy: Low
        $x_1_3 = {2a 28 26 74 32 35 35 29 [0-32] 2e 72 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAC_2147732433_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAC!bit"
        threat_id = "2147732433"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8b 0d ?? ?? ?? ?? c1 e8 03 85 c0 76 14 56 57 8b f1 8b f8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f2 c1 ee 05 03 35 ?? ?? ?? ?? 8b fa c1 e7 04 03 3d ?? ?? ?? ?? 33 f7 8d 3c 10 33 f7 2b ce 8b f1 c1 ee 05 03 35 ?? ?? ?? ?? 8b f9 c1 e7 04 03 3d ?? ?? ?? ?? 33 f7 8d 3c 08 33 f7 2b d6 05 ?? ?? ?? ?? ff 4d fc 75 b8 8b 45 08 5f 89 10 89 48 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAD_2147732434_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAD!bit"
        threat_id = "2147732434"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 5b 8a 1c 30 80 f3 1a f6 d3 53 5b 80 f3 26 53 5b 88 1c 30 53 5b 50 58 53 5b 84 c0 46 53 5b 84 c0}  //weight: 1, accuracy: High
        $x_1_2 = {52 6a 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8b 45 ?? 2d ?? ?? ?? ?? 89 45 ?? 8d 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAG_2147732435_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAG!bit"
        threat_id = "2147732435"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 08 c1 ea 05 03 54 24 04 33 c2 33 c1 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b cf 56 e8 ?? ?? ?? ?? 8b 54 24 ?? 2b d8 56 ff 74 24 ?? 8b cb e8 ?? ?? ?? ?? 2b f8 b9 01 00 00 00 8b 44 24 ?? 83 c4 10 2b c8 03 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAM_2147732436_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAM!bit"
        threat_id = "2147732436"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 bf 0a 00 00 00 99 f7 ff 80 c2 30 33 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 8b d8 49 85 db 75 db}  //weight: 1, accuracy: High
        $x_1_2 = {89 c6 89 d7 89 c8 39 f7 77 13 74 2f c1 f9 02 78 2a f3 a5 89 c1 83 e1 03 f3 a4}  //weight: 1, accuracy: High
        $x_1_3 = {53 31 db 69 93 ?? ?? ?? ?? ?? ?? ?? ?? 42 89 93 ?? ?? ?? ?? f7 e2 89 d0 5b}  //weight: 1, accuracy: Low
        $x_1_4 = {8b d0 03 d7 89 d6 85 d2 75 05 e8 ?? ?? ?? ?? 6a 00 6a 01 57 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BAA_2147732437_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BAA!bit"
        threat_id = "2147732437"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 40 4b 4c 00 8d 64 24 00 e8 20 1a 00 00 0f af f0 4f 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = {81 3c c7 2e 72 65 6c}  //weight: 1, accuracy: High
        $x_1_3 = {b8 81 80 80 80 f7 e9 03 d1 c1 fa 07 8b c2 c1 e8 1f 03 c2 02 c1 30 81 ?? ?? ?? ?? 41 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BAE_2147732439_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BAE!bit"
        threat_id = "2147732439"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "protect.exe" ascii //weight: 1
        $x_1_2 = "C:\\Windows\\System32\\cBLK.dll" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\1234df.dll" ascii //weight: 1
        $x_1_4 = "FEATURE_Cross_Domain_Redirect_Mitigation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_BAF_2147732440_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BAF!bit"
        threat_id = "2147732440"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 e4 3b 55 10 7d 1e 8b 45 08 03 45 e4 0f b6 08 8b 55 0c 03 55 e4 0f b6 02 33 c8 8b 55 08 03 55 e4 88 0a}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 3c fe ff ff 5c c6 85 3d fe ff ff 00 c6 85 18 fe ff ff 5c c6 85 19 fe ff ff 76 c6 85 1a fe ff ff 62 c6 85 1b fe ff ff 63 c6 85 1c fe ff ff 2e c6 85 1d fe ff ff 65 c6 85 1e fe ff ff 78 c6 85 1f fe ff ff 65}  //weight: 1, accuracy: High
        $x_1_3 = {c6 85 dc fe ff ff 57 c6 85 dd fe ff ff 72 c6 85 de fe ff ff 69 c6 85 df fe ff ff 74 c6 85 e0 fe ff ff 65 c6 85 e1 fe ff ff 50 c6 85 e2 fe ff ff 72 c6 85 e3 fe ff ff 6f c6 85 e4 fe ff ff 63 c6 85 e5 fe ff ff 65 c6 85 e6 fe ff ff 73 c6 85 e7 fe ff ff 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BAH_2147732441_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BAH!bit"
        threat_id = "2147732441"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 1b 53 c6 44 24 1c 79 c6 44 24 1e 74 88 4c 24 1f c6 44 24 20 6d c6 44 24 21 33 c6 44 24 22 32 88 54 24 23 c6 44 24 25 76 c6 44 24 26 63 c6 44 24 27 68 c6 44 24 28 6f c6 44 24 2a 74 c6 44 24 2b 2e 88 4c 24 2c c6 44 24 2d 78 88 4c 24 2e c6 44 24 2f 00}  //weight: 1, accuracy: High
        $x_1_2 = {b2 5c 88 44 24 11 88 44 24 15 b1 65 88 44 24 1c 88 44 24 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RX_2147732459_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RX!bit"
        threat_id = "2147732459"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 18 7c 47 00 03 03 8a 10 [0-16] 89 c0 [0-16] 80 f2 94 a1 ?? ?? ?? ?? 03 03 88 10 [0-16] 89 c0 [0-16] ff 03 81 3b}  //weight: 1, accuracy: Low
        $x_1_2 = {31 f6 89 db 89 d2 68 e0 52 00 00 5f 01 f8 a1 ?? ?? ?? ?? 01 f8 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RY_2147732460_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RY!bit"
        threat_id = "2147732460"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 17 8d 44 10 ff 50 e8 ?? ?? ?? ?? 5a 88 02 ff 07 4b 75 e5 07 00 8b c6 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {25 ff 00 00 00 8b 15 e8 ea 46 00 33 c2 f7 d0 c3 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 1d b0 bb 46 00 8b 0d b4 bb 46 00 48 ff d1 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SA_2147732461_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SA!bit"
        threat_id = "2147732461"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 33 c1 8b d2 c7 45 fc 00 00 00 00 8b d2 01 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {ff 75 fc b8 ?? ?? ?? ?? 48 50 ff 75 ?? ff 75 ?? a1 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {1b c9 f7 d9 1d 00 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 39 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SE_2147732462_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SE!bit"
        threat_id = "2147732462"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 89 15 ?? ?? ?? ?? c7 45 f0 ?? ?? ?? ?? c7 45 f0 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 0f b6 08 89 0d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? a0 ?? ?? ?? ?? 88 02 c7 45 f0 ?? ?? ?? ?? 8b 4d f8 83 c1 01 89 4d f8 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c2 50 8f 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SF_2147732463_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SF!bit"
        threat_id = "2147732463"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d7 8a 96 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 14 30 46 3b 75 fc 72 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 c1 e8 05 03 45 f0 8b cf c1 e1 04 03 4d ec 8d 14 3b 33 c1 33 c2 2b f0 8b c6 c1 e8 05 03 45 e8 8b ce c1 e1 04 03 4d e4 8d 14 33 33 c1 33 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SG_2147732464_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SG!bit"
        threat_id = "2147732464"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 40 83 f0 06 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 8b 4d ?? ff 91 ?? ?? ?? ?? 50 8b 55 ?? ff 92}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d1 81 e2 ?? ?? ?? ?? 79 08 4a 81 ca ?? ?? ?? ?? 42 8b 4d ?? 0f b6 94 11 ?? ?? ?? ?? 33 c2 8b 4d ?? 8b 91 ?? ?? ?? ?? 8b 4d ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SL_2147732466_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SL!bit"
        threat_id = "2147732466"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba c0 15 40 00 83 c4 0c 2b d3 03 d7 89 55 f0 8b 45 f0 33 db 8b d8 ff d3}  //weight: 1, accuracy: High
        $x_1_2 = {8b fb 6a 04 c1 e7 0f 03 79 0c 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {57 8b 7c 24 0c 8b d7 2b d1 46 8a 01 88 04 0a 41 4e 75 f7}  //weight: 1, accuracy: High
        $x_1_4 = {8b d8 8d 45 fc 50 6a 40 8b 73 3c 03 f3 8b 4e 50 8b 56 34 51 52 ff 55 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UN_2147732468_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UN!bit"
        threat_id = "2147732468"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff ff ff 30 06 c3}  //weight: 2, accuracy: High
        $x_2_2 = {b8 fd 43 03 00}  //weight: 2, accuracy: High
        $x_2_3 = {b8 ff 7f 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {8b c8 0f af 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 54 01 01 89 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f b7 0d ?? ?? ?? ?? 23 c1 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {8b c8 0f af 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 c8 89 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f b7 15 ?? ?? ?? ?? 23 c2 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_UO_2147732469_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UO!bit"
        threat_id = "2147732469"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 55 08 8b c2 c1 e0 04 8b ca 03 45 0c c1 e9 05 03 4d 10 33 c1 8b 4d 14 03 ca 33 c1 5d}  //weight: 1, accuracy: High
        $x_1_2 = {33 c8 2b d9 53 e8 ?? ?? ?? ?? 33 c9 2b f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UP_2147732470_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UP!bit"
        threat_id = "2147732470"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8a 10 8a 4d 13 32 d1 02 d1 88 10}  //weight: 1, accuracy: High
        $x_1_2 = {55 03 c5 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 02 8b e8 81 e5 ?? ?? ?? ?? 81 fd ?? ?? ?? ?? 75 0d 8b 6c 24 18 25 ?? ?? ?? ?? 03 c7 01 28 8b 46 04 83 e8 08 83 c1 01 d1 e8 83 c2 02 3b c8 72 ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_US_2147732471_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.US!bit"
        threat_id = "2147732471"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 89 45 ?? 31 4d ?? 8b 45 [0-32] 01 05 [0-16] 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 8b 02 03 45 ?? 8b 4d 08 89 01}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 08 8d 94 11 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 88 10 8b 4d ?? 03 4d ?? 0f b6 11 81 ea ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABB_2147732487_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABB!bit"
        threat_id = "2147732487"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 8a 91 ?? ?? ?? ?? 80 f2 ba 88 10 41}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 5e 5b c3 70 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? [0-16] 83 fb ?? [0-16] 7e ?? [0-16] c7 05 ?? ?? ?? ?? ?? ?? ?? ?? [0-16] [0-2] e8 ?? ?? ?? ?? [0-16] eb ?? [0-16] 4e 75 ?? [0-16] 5f 5e 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABD_2147732489_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABD!bit"
        threat_id = "2147732489"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 c0 00 00 00 0b d0 88 55 ?? 0f b6 4d ?? 0f b6 55 ?? c1 e2 06 81 e2 c0 00 00 00 0b ca 88 4d ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 8b 02 8b 4d ?? 8a 54 01 03 88 55 ?? 0f b6 45 ?? 0f b6 4d ?? c1 e1 02 81 e1 c0 00 00 00 0b c1 88 45 ?? 0f b6 55 ?? 0f b6 45 ?? c1 e0 04}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 c8 8b 55 08 03 55 0c 0f be 02 33 c1 8b 4d 08 03 4d 0c 88 01 8b 55 0c 83 ea 01 89 55 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABE_2147732490_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABE!bit"
        threat_id = "2147732490"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c1 03 d0 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8a 84 15 ?? ?? ?? ?? 88 84 1d ?? ?? ?? ?? 88 8c 15 ?? ?? ?? ?? 0f b6 84 1d ?? ?? ?? ?? 0f b6 c9 03 c8 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8a 84 0d ?? ?? ?? ?? 30 04 3e 46 3b 75 0c 72 91}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 83 e0 03 8a 44 05 08 30 04 0e 46 3b f2 72 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABG_2147732491_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABG!bit"
        threat_id = "2147732491"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 02 a1 ?? ?? ?? ?? 32 0c 02 66 0f be c1 66 89 04 57 42 3b 15 ?? ?? ?? ?? 7c df 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 47 08 8b 0f 8a 04 30 32 04 31 88 04 1e}  //weight: 1, accuracy: High
        $x_1_3 = {ff 74 24 04 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 50 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABK_2147732493_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABK!bit"
        threat_id = "2147732493"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 52 50 8b 06 99 03 04 24 13 54 24 ?? 83 c4 08 8b d1 8a 12 80 f2 ?? 88 10 ff 06 41 81 3e ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c9 83 c1 5f 31 db 03 5d ?? 87 cb 01 cb 87 d9 ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABV_2147732496_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABV!bit"
        threat_id = "2147732496"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 fc 83 65 f4 00 a3 ?? ?? ?? ?? 81 f3 ?? ?? ?? ?? 81 6d f4 ?? ?? ?? ?? 81 45 f4 ?? ?? ?? ?? 8b 4d f4 d3 e8 5b 25 ff 7f 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 0c 5f 5e a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff d0 16 00 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABW_2147732497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABW!bit"
        threat_id = "2147732497"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 0e 80 f2 1a 88 11 41 4f 75 d8 1c 00 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 39 15 ?? ?? ?? ?? 7d 07}  //weight: 1, accuracy: Low
        $x_1_2 = {51 50 ff 54 24 ?? 6a 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff d0 be ?? ?? ?? ?? 8b c8 2b f0}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c0 8b 2d ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f bf 3d ?? ?? ?? ?? 8b c6 33 c2 89 44 24 ?? 0f bf 05 ?? ?? ?? ?? 0f af c6 33 fe 8b 35 ?? ?? ?? ?? 89 44 24 ?? 89 7c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABY_2147732498_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABY!bit"
        threat_id = "2147732498"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 75 ?? 5b 8a 82}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 37 4e 79 f5 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {88 0c 07 8a 4d ?? 47 88 0c 07 8a 4d ?? 22 ca 0a 4d ?? 47 88 0c 07 03 75 ?? 8b 45 ?? 47 3b 30}  //weight: 1, accuracy: Low
        $x_1_4 = {7c ea 50 56 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 39 35 ?? ?? ?? ?? 76 1f 8b 0d ?? ?? ?? ?? 8a 8c 08 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 0c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ACA_2147732500_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ACA!bit"
        threat_id = "2147732500"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fa 14 75 04 33 d2 eb 01 42 40 3b c6 72 e5 0c 00 8a 8a ?? ?? ?? ?? 30 88}  //weight: 1, accuracy: Low
        $x_1_2 = {40 3b c1 72 ea 11 00 ba ?? ?? ?? ?? 30 90 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {30 1c 30 40 3b c7 72 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ACB_2147732501_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ACB!bit"
        threat_id = "2147732501"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 40 89 45 fc 8b 45 fc 3b 45 0c 7d 1a 8b 45 08 03 45 fc 0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 fc 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 45 ?? 83 65 ?? 00 81 f3 ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 8b 45 ?? 23 45 ?? 89 45 ?? 8b 45 ?? 5b}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 0d 8b 85 ?? ?? ?? ?? 40 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 21 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 8a 89 ?? ?? ?? ?? 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AIA_2147732568_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AIA!bit"
        threat_id = "2147732568"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f8 85 db 7e 17 8d 9b 00 00 00 00 e8 bb ff ff ff 30 84 3e 00 fe ff ff 46 3b f3 7c ef 5f}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 2c 00 00 00 8b 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AMT_2147732632_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AMT!bit"
        threat_id = "2147732632"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 68 00 30 00 00 50 53 ff 15 ?? ?? ?? 00 89 85 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 de 44 00 50 ff d7}  //weight: 1, accuracy: High
        $x_1_3 = {8a c3 32 85 [0-48] 88 84 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ANG_2147732639_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ANG!bit"
        threat_id = "2147732639"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 8d 8f fc ff ff 33 8d 88 fc ff ff 88 8d 87 fc ff ff 8b 95 ec fd ff ff 03 55 10 8b 85 94 fc ff ff 2b 85 ec fd ff ff 03 95 cc fc ff ff 8d 8c 82 b9 00 00 00 89 8d cc fc ff ff 8b 95 cc fc ff ff 83 c2 08 39 95 ec fd ff ff 75 17 8b 85 88 fc ff ff 2b 45 10 8b 8d cc fc ff ff 2b c8 89 8d cc fc ff ff 8b 95 ac fc ff ff 03 15 40 91 45 00 03 15 4c 91 45 00 03 15 40 91 45 00 89 15 40 91 45 00 8a 85 87 fc ff ff 88 85 90 fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RW_2147732656_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RW!bit"
        threat_id = "2147732656"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 a5 a5 a5 a4 50 ff 15 ?? ?? ?? ?? 0f bf 05 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 7d 0a c7 05 ?? ?? ?? ?? 61 00 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f bf 05 ?? ?? ?? ?? 0f bf 15 ?? ?? ?? ?? 3b c2 7e 0a c7 05 ?? ?? ?? ?? 9b 00 00 00 33 c0 83 c4 10 5e 5f c2 0c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 56 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 45 81 fd 19 10 00 00 72 cc 47 81 ff 15 4f 00 00 73 04 8b ee eb bf 5b 5d 5e 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RW_2147732656_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RW!bit"
        threat_id = "2147732656"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f1 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f8 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 02 33 f7 2b ce 81 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? 8a 8e ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 0c 32 ff d7 46 3b 75 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 fc 8d 4d f8 51 8b 0d ?? ?? ?? ?? 6a 40 52 51 ff d0 8b 45 fc 8b 35 ?? ?? ?? ?? c1 e8 03 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UC_2147732657_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UC!bit"
        threat_id = "2147732657"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf 0f 44 f0 c1 e9 05 03 0d ?? ?? ?? ?? 8b c7 c1 e0 04 03 05 ?? ?? ?? ?? 33 c8 8d 04 3e 33 c8 2b d9 8b cb 8b c3 c1 e9 05 03 0d ?? ?? ?? ?? c1 e0 04 03 05 ?? ?? ?? ?? 33 c8 8d 04 1e 33 c8 2b f2 2b f9}  //weight: 1, accuracy: Low
        $x_1_2 = {05 32 09 00 00 50 6a 00 89 84 24 ?? 00 00 00 ff 15 ?? ?? ?? ?? 33 f6 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SM_2147732676_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SM!bit"
        threat_id = "2147732676"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c c1 e0 ?? 03 45 10 8b 4d 0c 03 4d 18 33 c1 8b 55 0c c1 ea ?? 03 55 14 33 c2 8b 4d 08 8b 11 2b d0 8b 45 08 89 10}  //weight: 1, accuracy: Low
        $x_1_2 = {33 ca 8b 45 ?? c1 e8 ?? 03 45 ?? 33 c8 8b 55 ?? 2b d1 89 55 ?? 8b 45 ?? 50 8b 4d ?? 51 8b 55 ?? 52 8b 45 ?? 50 8d 4d ?? 51 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ST_2147732677_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ST!bit"
        threat_id = "2147732677"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 0f b7 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 35 ?? ?? ?? ?? 33 c7 8a 88 ?? ?? ?? ?? 47 81 ff ?? ?? ?? ?? 88 0c 10 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 6a 03 99 5f f7 ff 85 d2 74 17 66 81 3d ?? ?? ?? ?? ?? ?? 75 21 a1 ?? ?? ?? ?? 03 c1 80 30 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TF_2147732679_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TF!bit"
        threat_id = "2147732679"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 fa 03 8a 14 3a 8a c8 80 e1 07 d2 fa 40 80 e2 01 3b c6 88 54 28 ff 7c e5}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 01 30 10 40 83 ee 01 75 f5}  //weight: 1, accuracy: High
        $x_1_3 = {8b 16 03 54 24 ?? 8b 46 f8 03 44 24 ?? 6a 00 51 8b 4c 24 ?? 52 50 51 ff 54 24}  //weight: 1, accuracy: Low
        $x_1_4 = {52 51 ff d0 85 c0 0f 84 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 54 24 ?? 50 52 ff 54 24 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d6 50 ff d7 8b 4d ?? 8b 55 ?? 6a 40 68 00 30 00 00 51 8b 4c 24 ?? 52 51 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CeeInject_TO_2147732680_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TO!bit"
        threat_id = "2147732680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 8b d1 8a 12 80 f2 eb 88 10 ff 06 41 81 3e ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 81 c2 ba 0a 00 00 89 55 fc 8b 7d fc ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TO_2147732680_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TO!bit"
        threat_id = "2147732680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 28 f6 d1 30 0c 18 40 3b c6 72 f3}  //weight: 1, accuracy: High
        $x_1_2 = {8b ce 2b c8 51 03 c3 50 ff 93 ?? ?? ?? ?? 01 44 24 ?? 59 59 39 74 24 ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 81 34 83 ?? ?? ?? ?? 40 83 f8 10 72 f3}  //weight: 1, accuracy: Low
        $x_1_4 = {50 53 8b c6 e8 ?? ?? ?? ?? 59 59 33 c9 8a 14 0b 8b 44 24 0c 30 14 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TO_2147732680_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TO!bit"
        threat_id = "2147732680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 bf 0a 00 00 00 99 f7 ff 80 c2 30 33 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 8b d8 49 85 db 75 db}  //weight: 1, accuracy: High
        $x_1_2 = {8b d0 83 e2 0f 8a 92 ?? ?? ?? ?? 33 db 8a d9 88 14 1e c1 e8 04 49 85 c0 75 e6}  //weight: 1, accuracy: Low
        $x_1_3 = {30 1a eb 05 ?? ?? ?? ?? ?? 42 eb 05 ?? ?? ?? ?? ?? 49 eb 05 ?? ?? ?? ?? ?? 83 f9 00 eb 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TO_2147732680_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TO!bit"
        threat_id = "2147732680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 08 80 f3 ?? f6 d3 80 f3 ?? 88 1c 08}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 40 18}  //weight: 1, accuracy: High
        $x_1_3 = {73 24 0f b6 55 ?? 8b 45 ?? 8b 08 0f b6 41 ?? 8b 4d ?? 0f b6 54 11 30 33 d0 0f b6 45 ?? 8b 4d ?? 88 54 01 30}  //weight: 1, accuracy: Low
        $x_1_4 = {52 8b 45 0c 50 8b 4d 08 51 8b 55 10 8b 42 34 50 8b 4d ?? 51 6a 02 8b 55 ?? 8b 42 10 ff d0 b9 4d 5a 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TO_2147732680_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TO!bit"
        threat_id = "2147732680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe c3 0f b6 f3 8a 14 3e 02 fa 0f b6 cf 8a 04 39 88 04 3e 88 14 39 0f b6 0c 3e 0f b6 c2 03 c8 0f b6 c1 8b 4c 24 ?? 8a 04 38 30 04 29 45 3b 6c 24 14 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 1f 33 c1 c1 e9 08 0f b6 c0 33 0c 85 ?? ?? ?? ?? 47 3b fa 72 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 0b 8b f1 8b 53 ?? 8d 5b ?? 8b c1 c1 c6 0f c1 c0 0d 33 f0 c1 e9 0a 33 f1 8b c2 8b ca c1 c8 07 c1 c1 0e 33 c8 c1 ea 03 33 ca 03 f1 03 73 ?? 03 73 ?? 89 73 ?? 83 ed 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TP_2147732681_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TP!bit"
        threat_id = "2147732681"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 37 5b f8 83 df fc f7 d3 83 eb 23 8d 5b ff 29 d3 89 da 89 1e f8 83 d6 04 83 c1 fc 85 c9 75 e0}  //weight: 1, accuracy: High
        $x_1_2 = {5e 8d 05 04 10 49 00 ff 30 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TP_2147732681_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TP!bit"
        threat_id = "2147732681"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3e 6a 00 05 00 e8 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 0f af 0d ?? ?? ?? ?? e8 ?? ff ff ff 03 c8 89 0d ?? ?? ?? ?? e8 ?? ff ff ff 0f b7 15 ?? ?? ?? ?? 23 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TP_2147732681_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TP!bit"
        threat_id = "2147732681"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 8b d1 8a 12 80 f2 81 88 10 ff 06 41 81 3e 2e 5b 00 00 75}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 51 81 c2 4a 53 00 00 89 55 fc 8b 7d fc [0-16] 87 fb ff e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TP_2147732681_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TP!bit"
        threat_id = "2147732681"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 8b 0c 24 81 c1 33 f9 03 59 89 4c 24 ?? 8b 4c 24 ?? 88 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = {89 54 24 7c 8b 96 ?? ?? ?? ?? 8b 9c 24 ?? 00 00 00 8b b6 ?? ?? ?? ?? 31 fe 81 f3 ?? ?? ?? ?? 8b 7c 24 ?? 01 c7}  //weight: 1, accuracy: Low
        $x_1_3 = {89 c8 31 d2 8b 74 24 ?? f7 f6 8b 7c 24 ?? 8a 1c 0f 2a 1c 15 ?? ?? ?? ?? 8b 54 24 ?? 88 1c 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TS_2147732682_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TS!bit"
        threat_id = "2147732682"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 24 8b 45 ?? 33 d2 f7 75 ?? 8b 45 ?? 0f b6 0c 10 8b 55 08 03 55 ?? 0f b6 02 33 c1 8b 4d 08 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {73 15 8b 4d ?? c1 e1 03 8b 55 ?? d3 ea 8b 45 ?? 03 45 ?? 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TS_2147732682_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TS!bit"
        threat_id = "2147732682"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? 99 f7 7d ?? 8b 45 ?? 8a 8a ?? ?? ?? ?? 8b 55 ?? c0 e1 03 32 c8 88 0c 02 40 3b c7 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 99 f7 7d ?? 8b 45 ?? 8a 04 02 30 04 3e 47 3b 7d ?? 7c eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c1 99 bf ?? ?? 00 00 f7 ff 8b 45 ?? 8a 04 02 30 04 31 41 81 f9 1d 02 00 00 7c e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TS_2147732682_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TS!bit"
        threat_id = "2147732682"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 08 03 55 fc 0f be 1a e8 ?? ?? ?? ff 33 d8 8b 45 08 03 45 fc 88 18 eb c7}  //weight: 2, accuracy: Low
        $x_1_2 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 c1 e8 10 25 ff 7f 00 00 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 00 ff 15 ?? ?? ?? 00 a3 ?? ?? ?? 00 68 ?? ?? ?? 00 6a 40 8b 8d ?? ?? ff ff 51 8b 15 ?? ?? ?? 00 52 ff 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 03 85 ?? ?? ff ff 8b 4d ?? 03 8d ?? ?? ff ff 8a 11 88 10 eb 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UH_2147732683_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UH!bit"
        threat_id = "2147732683"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 fc 0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 fc 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = {03 f0 89 35 [0-16] a1 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UK_2147732684_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UK!bit"
        threat_id = "2147732684"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 0b a3 14 00 2b c1 88 44 1d ?? 43 83 fb 08 7c ee}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 0c 8d 34 38 ff 15 ?? ?? ?? ?? 8b c8 8b 45 10 33 d2 f7 f1 8b 45 0c 8b 4d 08 8a 04 02 32 04 31 88 06 8b 45 10 40 89 45 10 3b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UT_2147732685_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UT!bit"
        threat_id = "2147732685"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 05 45 29 00 00 73 05}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 89 45 fc 8b 75 08 eb 05 80 33 08 eb 07 8b 5d fc 01 f3}  //weight: 1, accuracy: High
        $x_1_3 = {40 3d d3 57 00 00 75 e3 ff 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAX_2147732707_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAX!bit"
        threat_id = "2147732707"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 50 59 03 49 3c 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {57 72 69 74 c7 05 ?? ?? ?? ?? 63 65 73 73 c7 05 ?? ?? ?? ?? 4d 65 6d 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 0e f8 83 de fc f7 d9 8d 49 f1 c1 c9 09 d1 c1 31 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAZ_2147732708_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAZ!bit"
        threat_id = "2147732708"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 4d 0c 7d 1a 8b 55 08 03 55 ?? 0f be 1a e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 ?? 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 08 e8 ?? ?? ?? ?? 0f af 45 0c 89 45 ?? c7 45 ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 8b 4d 08 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAT_2147732709_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAT!bit"
        threat_id = "2147732709"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 00 00 00 83 6d ?? 7b 68 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 65 00 00 00 ?? 72 00 00 00 ?? 6e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d7 c1 ea 05 03 55 ?? 8b c7 c1 e0 04 03 45}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 0c 33 33 d0 33 d1 2b fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAR_2147732710_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAR!bit"
        threat_id = "2147732710"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4c 24 14 03 c3 03 c5 8a 10 32 d1 43 81 fb da 04 00 00 88 10}  //weight: 1, accuracy: High
        $x_1_2 = {03 c8 03 c3 0a 00 a1 ?? ?? ?? ?? b9}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 4e e6 40 bb}  //weight: 1, accuracy: High
        $x_1_4 = "SUUS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABL_2147732712_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABL!bit"
        threat_id = "2147732712"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 ?? 8a 00 88 45 ?? 8a 45 ?? 34 80 8b 55 08 03 55 ?? 88 02 ff 45 ?? 81 7d f4 ?? ?? ?? ?? 75 dc}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 5c 00 00 00 33 d2 f7 f1 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABM_2147732713_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABM!bit"
        threat_id = "2147732713"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 fb e8 ?? ?? ?? ?? 8b 4e 04 03 c7 8a 14 08 32 d3 32 16 43 88 54 3c ?? 66 3b 5e 02 72 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 de e8 ?? ?? ?? ?? 8b 4f 04 03 c3 66 0f be 14 08 0f b6 07 66 33 d0 66 33 d6 b9 ?? ?? ?? ?? 66 23 d1 46 66 89 54 5d 00 66 3b 77 02 72 d1}  //weight: 1, accuracy: Low
        $x_1_3 = {03 f2 81 e6 ?? ?? ?? ?? 79 08 4e 81 ce ?? ?? ?? ?? 46 8b 5c b4 ?? 0f b6 d2 89 5c 8c ?? 89 54 b4 ?? 8b 5c 8c ?? 03 da 81 e3 ?? ?? ?? ?? 79 08 4b 81 cb ?? ?? ?? ?? 43 0f b6 54 9c ?? 30 14 38 40 3b c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_ABN_2147732714_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABN!bit"
        threat_id = "2147732714"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 00 66 c7 45 ?? 65 00 66 c7 45 ?? 72 00 66 c7 45 ?? 6e 00 66 c7 45 ?? 65 00 66 c7 45 ?? 6c 00 66 c7 45 ?? 33 00 66 c7 45 ?? 32 00 66 c7 45 ?? 2e 00 66 c7 45 ?? 64 00 66 c7 45 ?? 6c 00 66 c7 45 ?? 6c 00 66 c7 45 ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1c 30 80 f3 0e f6 d3 80 f3 cf 88 1c 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABO_2147732715_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABO!bit"
        threat_id = "2147732715"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 02 89 45 ?? e8 ?? ?? ?? ?? 33 45 ?? 8b 4d 08 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 56 e8 ?? ?? ?? ?? 8b f0 0f af 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 44 06 01 a3 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? c1 ee ?? e8 ?? ?? ?? ?? 23 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABX_2147732716_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABX!bit"
        threat_id = "2147732716"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c1 83 e0 03 0f b6 44 04 ?? 30 81 ?? ?? ?? ?? 8d 82 ?? ?? ?? ?? 03 c1 83 e0 03 0f b6 44 04 ?? 30 81 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 03 c1 83 e0 03 0f b6 44 04 ?? 30 81 ?? ?? ?? ?? 8d 87 ?? ?? ?? ?? 03 c1 83 e0 03 0f b6 44 04 ?? 30 81}  //weight: 2, accuracy: Low
        $x_2_2 = {33 c9 81 ea ?? ?? ?? ?? 81 ee ?? ?? ?? ?? 81 ef}  //weight: 2, accuracy: Low
        $x_1_3 = {88 4c 24 0f 34 79 80 74 24 0f da 80 7c 24 0f e9 75 10 3c 40 75 0c 80 7c 24 10 31 75 05 80 fa 38 74 16 41 8b d1 8b c1 c1 ea 10 89 54 24 10 8b d1 c1 e8 08 c1 ea 18 eb c8}  //weight: 1, accuracy: High
        $x_1_4 = {88 44 24 0f 80 f1 79 80 74 24 0f da 80 7c 24 0f e9 75 0f 80 f9 40 75 0a 80 fb 31 75 05 80 fa 38 74 12 40 8b c8 8b d8 8b d0 c1 e9 08 c1 eb 10 c1 ea 18 eb cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AMO_2147732794_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AMO!bit"
        threat_id = "2147732794"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 0f 8a 04 10 39 9d ?? ?? ?? ff 75 0f 8b 95 ?? ?? ?? ff 8b b5 ?? ?? ?? ff 88 04 11 8b 85 ?? ?? ?? ff 39 85 ?? ?? ?? ff 75 0e 8b 85 ?? ?? ?? ff 01 05 ?? ?? ?? 00 eb 11 b8 f5 01 00 00 2b 85 ?? ?? ?? ff 01 85 ?? ?? ?? ff 41 3b 8d ?? ?? ?? ff 7c 95}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 f8 8a 0d ?? ?? ?? 00 02 4d fc 8b 45 08 02 c9 2a 4d f8 03 c3 2a 4d fc 02 4d 10 30 08 85 f6 74 0d 8b 45 fc 99 2b c2 d1 f8 01 45 fc eb 03 ff 45 fc 85 ff 75 06 ff 05 ?? ?? ?? 00 43 3b 5d 0c 7c c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_M_2147732933_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.M"
        threat_id = "2147732933"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AntiAntiVirus_command" ascii //weight: 1
        $x_1_2 = "WriteProcessMemory failed" ascii //weight: 1
        $x_1_3 = "New EXE image injected into process." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_M_2147732933_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.M"
        threat_id = "2147732933"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 00 65 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6c 00 7a 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 78 65 63 75 74 65 46 69 6c 65 00 44 61 74 61 00 [0-16] 4c 7a 6d 61 55 6e 63 6f 6d 70 72 65 73 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = ".Stone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_M_2147732933_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.M"
        threat_id = "2147732933"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 f4 8b 15 38 d7 41 00 8b 0d 3c d7 41 00 89 10 8b 15 40 d7 41 00 89 48 04 66 8b 0d 44 d7 41 00 89 50 08 8b 15 a4 63 42 00 52 66 89 48 0c 8d 84 24 20 03 00 00 68 48 d7 41 00 50}  //weight: 1, accuracy: High
        $x_2_2 = {00 00 6c 00 7a 00 2e 00 64 00 6c 00 6c 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 00 6c 00 72 00 69 00 2e 00 64 00 6c 00 6c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_M_2147732933_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.M"
        threat_id = "2147732933"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 08 89 44 24 1d 89 44 24 21 89 44 24 25 66 89 44 24 29 88 44 24 2b 8d 44 24 1c 68 ?? ?? 00 10 50 c6 44 24 24 00 e8 ?? ?? 00 00 8b 4d 3c 8d 3c 29 83 c4 0c 81 3f 50 45 00 00 74 14 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f b7 47 14 66 85 c0 75 07}  //weight: 2, accuracy: Low
        $x_2_2 = {6c 65 65 2e 64 6c 6c 00 44 61 74 61 00 45 78 65 63 75 74 65 46 69 6c 65 00 53 65 6c 66}  //weight: 2, accuracy: High
        $x_3_3 = "New EXE image injected into process." ascii //weight: 3
        $x_1_4 = "Allocated Mem for New EXE at %X. EXE will be relocated." ascii //weight: 1
        $x_1_5 = {45 6e 63 6f 64 65 00 00 73 74 6f 6e 65}  //weight: 1, accuracy: High
        $x_1_6 = {45 6e 63 6f 64 65 00 00 2e 53 74 6f 6e 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_M_2147732933_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.M"
        threat_id = "2147732933"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AAV_Unpack_dll_Mutex" wide //weight: 1
        $x_1_2 = "Path[ C:\\TEMP\\LRI_v0.0.1.9\\lri.dll]" wide //weight: 1
        $x_1_3 = "Fail to generate lri.dll." wide //weight: 1
        $x_1_4 = "Productinfo|Fail Decrypt AAV protected Code!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_M_2147732933_5
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.M"
        threat_id = "2147732933"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 14 02 00 00 a1 ?? f0 00 10 33 c4 89 84 24 10 02 00 00 56 57 8b bc 24 20 02 00 00 68 ?? c1 00 10 68 ?? c1 00 10 e8 ?? ?? 00 00 8b f0 83 c4 08 85 f6 0f 84 c6 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b b4 24 9c 00 00 00 c1 ee 02 83 c3 5c 66 81 7d 00 4d 5a 89 74 24 10 74 14 68 c8 c1 00 10 e8 b2 fc ff ff 83 c4 04 33 c0 e9 33 01 00 00 8b 45 3c 03 c5 81 38 50 45 00 00 74 14 68 b4 c1 00 10 e8 91 fc ff ff}  //weight: 1, accuracy: High
        $x_2_3 = ".smiley" ascii //weight: 2
        $x_2_4 = "This Dll algorithm isn't same ." ascii //weight: 2
        $x_2_5 = "C:\\LRILog.txt" ascii //weight: 2
        $x_2_6 = "This Dll have not encrypted. It runs in non-protection mode." ascii //weight: 2
        $x_2_7 = "LRI.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_M_2147732933_6
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.M"
        threat_id = "2147732933"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 f4 8b 15 58 e7 00 10 8b 0d 5c e7 00 10 89 10 8b 15 60 e7 00 10 89 48 04 8b 0d 64 e7 00 10 89 50 08 66 8b 15 68 e7 00 10 89 48 0c 66 89 50 10 8d 44 24 08 50 ff 15 04 c0 00 10 8b f0 68 6c e7 00 10 56}  //weight: 1, accuracy: High
        $x_1_2 = {75 f4 8b 0d bc d7 00 10 8b 15 c0 d7 00 10 89 08 8b 0d c4 d7 00 10 89 50 04 8b 15 c8 d7 00 10 89 48 08 66 8b 0d cc d7 00 10 89 50 0c 56 8d 54 24 04 52 66 89 48 10 ff 15 4c c0 00 10 8b f0 68 d0 d7 00 10 56}  //weight: 1, accuracy: High
        $x_1_3 = {6a 08 89 44 24 1d 89 44 24 21 89 44 24 25 66 89 44 24 29 88 44 24 2b 8d 44 24 1c 68 ?? ?? 00 10 50 c6 44 24 24 00 e8 ?? ?? 00 00 8b 4d 3c 8d 3c 29 83 c4 0c 81 3f 50 45 00 00 74 14 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f b7 47 14 66 85 c0 75 07}  //weight: 1, accuracy: Low
        $x_3_4 = "\\LRI.dll" wide //weight: 3
        $x_3_5 = "New EXE image injected into process." ascii //weight: 3
        $x_3_6 = "Ryan Project\\Anti-AntiVirus" ascii //weight: 3
        $x_1_7 = "Allocated Mem for New EXE at %X. EXE will be relocated." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_MD_2147732955_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MD!bit"
        threat_id = "2147732955"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 ac 83 c2 01 89 55 ac 81 7d ac 20 8b 00 00 7d ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 c4 03 45 ac 8b 4d fc 03 4d ac 8a 11 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MD_2147732955_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MD!bit"
        threat_id = "2147732955"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 51 52 e8 ?? ?? ?? ff 8b 54 ?? ?? a3 ?? ?? ?? 10 8b 44 ?? ?? 83 c4 14 8a 0c 30 32 cb 88 0c 16 46 83 fe 5e 0f 8c ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MD_2147732955_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MD!bit"
        threat_id = "2147732955"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 d2 fd 43 03 00 81 c2 ?? ?? ?? ?? 8b c2 c1 e8 10 32 04 0b 46 88 01 8b 7d ?? 41 3b f7 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 40 57 50 6a 00 ff 15 ?? ?? ?? ?? ff 55 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_MI_2147732956_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.MI!bit"
        threat_id = "2147732956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4c 24 10 51 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? 00 68 02 00 00 80 ff d6 ff d7 8d 54 ?? ?? a3 ?? ?? ?? 00 52 ff d3 4d 75 d7}  //weight: 1, accuracy: Low
        $x_2_2 = {8a 0c 11 88 0c 38 8b 4d 08 8a 45 0f d3 e3 33 db 8b 4d 08 8a 45 0f d3 e3 33 db 0b 1d ?? ?? ?? 00 03 d9 8a 0b [0-16] 33 c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ML_2147732957_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ML!bit"
        threat_id = "2147732957"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c b6 b8 ?? ?? ?? ?? c1 e1 ?? 2b ce c1 e1 ?? f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b fa 8d 14 f6 8d 04 d6 8a 4c 3c ?? c1 e0 ?? 03 c6 80 f1 ?? 8d 34 c0 b8 ?? ?? ?? ?? f7 ee c1 fa ?? 8b c2 c1 e8 ?? 03 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ML_2147732957_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ML!bit"
        threat_id = "2147732957"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 90 83 c2 01 89 55 90 81 7d 90 88 13 00 00 7d 1c b8 5f 00 00 00 2b 45 98 8b 4d e0 03 c8 89 4d cc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 98 83 c1 01 89 4d 98 81 7d 98 ?? ?? ?? ?? 7d 5e 8d 55 a0 52 ff 15 ?? ?? ?? ?? 8b 45 b0 03 45 98 33 c9 8a 08 89 4d e0}  //weight: 1, accuracy: Low
        $x_1_3 = "jkgaa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_PH_2147732963_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.PH!bit"
        threat_id = "2147732963"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 67 66 66 66 f7 6c 24 ?? d1 fa 8b c2 c1 e8 1f 03 c2 8b d8 0f af ?? 24 ?? 0f af 5d 10 8a c3 32 44 24}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 4d 10 85 c9 8b 45 08 74 0d 8a 54 24 ?? 8b 74 24 ?? 88 14 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_PH_2147732963_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.PH!bit"
        threat_id = "2147732963"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 3b 4d 0c 7d 1a 8b 55 08 03 55 fc 0f be 1a e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 fc 88 18 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? c1 e8 ?? 25 ?? ?? ?? ?? 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SV_2147732968_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SV!bit"
        threat_id = "2147732968"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 8b 45 fc 03 45 ?? 0f b6 08 8d 54 11 02 8b 45 fc 03 45 ?? 88 10 8b 4d fc 03 4d ?? 0f b6 11 83 ea 02 8b 45 fc 03 45 ?? 88 10 c7 45 f0 ?? ?? ?? 00 8b 4d f8 83 c1 01 89 4d f8 e9 43 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {8b ca 33 c1 [0-48] 89 11 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SV_2147732968_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SV!bit"
        threat_id = "2147732968"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff ff ff 24 03 00 00 73 52 8b ?? ?? ff ff ff 8b ?? ?? ?? ?? 41 00 89 ?? ?? ff ff ff 8b ?? ?? ff ff ff 2b ?? ?? ff ff ff 89 ?? ?? ff ff ff c1 85 ?? ff ff ff 0f 8b ?? ?? ff ff ff 33 ?? ?? ?? 41 00 89 ?? ?? ff ff ff 8b ?? ?? ff ff ff 8b ?? ?? 8b ?? ?? ff ff ff 89 ?? ?? eb 93}  //weight: 2, accuracy: Low
        $x_2_2 = {24 03 00 00 73 33 8b 45 ?? 8b 4d ?? 8b 14 81 89 55 ?? 8b 45 ?? 2b 45 ?? 89 45 ?? c1 45 ?? 0f 8b 4d ?? 33 0d ?? ?? ?? ?? 89 4d ?? 8b 55 ?? 8b 45 ?? 8b 4d ?? 89 0c 90 eb bb}  //weight: 2, accuracy: Low
        $x_1_3 = {68 b8 88 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_ZG_2147732980_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ZG!bit"
        threat_id = "2147732980"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 56 6a 00 ff 54 ?? ?? 8b 94 ?? ?? 00 00 00 a1 ?? ?? ?? ?? 52 50 ff 15 ?? ?? ?? ?? 6a 04 68 00 10 00 00 6a 04 6a 00 89 44 ?? ?? c7 44 ?? ?? ?? ?? 00 00 ff 54}  //weight: 1, accuracy: Low
        $x_2_2 = {8b c1 99 bb ?? ?? ?? 00 f7 fb 8b 44 ?? ?? 8a 1c 0f 8a 14 02 32 da 88 1c 0f 41 81 f9 ?? ?? ?? 00 7c de 0f bf 0d ?? ?? ?? 10 a1 3c a0 00 ?? 81 f1 ?? 00 00 00 3b c1 7d 0a}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 48 14 52 8b 50 0c 8b 44 ?? ?? 03 cf 51 03 54 ?? ?? 52 50 83 ee 28 ff d3 85 f6 7d bc}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 56 6a 00 6a 00 6a 04 6a 06 52 ff d7 8b 44 ?? ?? 50 ff ?? ?? ?? 6a 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AAJ_2147732998_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAJ!bit"
        threat_id = "2147732998"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 14 bf 8b 8c 24 ?? ?? ?? 00 0f af cb 0f af 8c 24 ?? ?? ?? 00 03 d1 8b 84 24 ?? ?? ?? 00 33 c7 0f af fa 88 06}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 06 89 84 24 ?? ?? ?? 00 89 8c 24 ?? ?? ?? 00 8d 84 1f 8a 00 00 00 0f af c2 89 84 24 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAK_2147732999_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAK!bit"
        threat_id = "2147732999"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 10 f7 da 8b 45 ?? 0f b6 0c 08 2b ca 8b 55 ?? 03 55 ?? 03 55 ?? 8b 45 ?? 88 0c 10 15 00 8b 4d ?? 03 4d ?? 03 4d ?? 8b 55 ?? 03 55 ?? 03 55 ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff 8b ca a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b ff 01 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAK_2147732999_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAK!bit"
        threat_id = "2147732999"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WINEXISTS ( \"tzF5ib2YkvH7BlAHf6Xr\" )" wide //weight: 1
        $x_1_2 = "FUNC RKVPJIUEUJ ( $STR , $DAMNPARAMETER , $NIQUETAMERE )" wide //weight: 1
        $x_1_3 = "GUICREATE ( \"toesunp\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AED_2147733011_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AED!bit"
        threat_id = "2147733011"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 51 6a 00 ff d7 a3 ?? ?? ?? 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {88 14 30 81 fe 77 0a 00 00 12 00 8b 0d ?? ?? ?? ?? 8a 94 31 ?? ?? ?? 00 a1 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 14 3e 46 3b f3 7c 06 00 8a 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OU_2147733023_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OU!bit"
        threat_id = "2147733023"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 8a 02 32 45 ?? 8b 4d 08 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8a c1 3c 61 7c 06 3c 7a 7f 02 24 df}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 f8 8b 45 e8 03 42 1c 8b 4d fc 8b 55 e8 03 14 88 8b c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OV_2147733024_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OV!bit"
        threat_id = "2147733024"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 30 0f b7 05 ?? ?? ?? ?? 33 45 ?? 35 ?? ?? ?? ?? 0f b7 0d ?? ?? ?? ?? 33 4d ?? 81 f1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 88 04 0a eb be}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 46 0f b7 05 ?? ?? ?? ?? 83 c0 ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 ?? 88 10 eb 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OW_2147733025_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OW!bit"
        threat_id = "2147733025"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f0 33 d6 03 ca 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 88 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 6a 04 68 00 10 00 00 e8 41 cd ff ff 50 6a 00 ff 15 04 70 42 00 a3 e8 ad 42 00 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OY_2147733026_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OY!bit"
        threat_id = "2147733026"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 30 10 40 4e 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {8a 1f 49 88 1a 42 47 85 c9 75 f5}  //weight: 1, accuracy: High
        $x_1_3 = {8a 14 16 8b ce 83 e1 ?? 8b c6 d2 e2 c1 f8 ?? 03 c7 08 10 46 3b 74 24 ?? 7c e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_OZ_2147733027_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.OZ!bit"
        threat_id = "2147733027"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f1 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f8 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 02 33 f7 2b ce 81 c2 ?? ?? ?? ?? ff 4d ?? 75 b7}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 2b cb 8a 14 01 88 10 47 40 3b 7d ?? 72 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_PB_2147733028_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.PB!bit"
        threat_id = "2147733028"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 8a 98 ?? ?? ?? ?? 03 d0 30 1a 40 3b c6 7c ee}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b c1 5b f7 f3 85 d2 75 12 8b 45 ?? 2b c1 bb ?? ?? ?? ?? f7 f3 30 91 ?? ?? ?? ?? 41 3b ce 72 dc}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c8 8b c2 33 d2 f7 f1 8a 82 ?? ?? ?? ?? 30 03 ff 45 ?? 39 75 ?? 72 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_PD_2147733029_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.PD!bit"
        threat_id = "2147733029"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 83 c6 ?? 03 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? c1 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c1 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c1 c0 ?? 2b 05 ?? ?? ?? ?? c1 c0 ?? c1 0d ?? ?? ?? ?? ?? ab 81 fe ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_PF_2147733030_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.PF!bit"
        threat_id = "2147733030"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1f 49 88 1a 42 47 85 c9 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = {83 c1 08 51 ff 75 ?? a3 ?? ?? ?? ?? ff d0 0d 00 8d 4d ?? 51 6a 04 8d 4d ?? 51 8b 4d}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 10 8d 0c 30 8a 04 33 30 01 8a 01 30 04 33 8a 04 33 30 01 4b ff 45 10 8b c3 2b 45 10 83 f8 01 7d d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_PG_2147733031_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.PG!bit"
        threat_id = "2147733031"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 01 66 3d 4d 5a 75 f1 8b 59 3c 03 d9 66 8b 03 66 3d 50 45 75 e3}  //weight: 1, accuracy: High
        $x_1_2 = {c7 00 56 69 72 74 c7 40 04 75 61 6c 41 c7 40 08 6c 6c 6f 63}  //weight: 1, accuracy: High
        $x_1_3 = {03 d8 83 c3 ?? 0f b7 40 ?? 8b d0 c1 e2 ?? 8d 14 92 03 da 83 c3 ?? 8b 4b ?? 03 4d ?? 83 c1 ?? 8b 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_PG_2147733031_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.PG!bit"
        threat_id = "2147733031"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 05 ?? ?? ?? ?? 8b fa c1 e7 ?? 03 3d ?? ?? ?? ?? 33 c7 8d 3c 16 33 c7 2b c8 8b c1 c1 e8 ?? 03 05 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 c7 8d 3c 0e 2b 75 f8 33 c7 2b d0 ff 4d fc 75}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 be 20 37 ef c6 e8 ?? ?? ?? ?? 89 45 f8 c7 45 fc 20 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 15 0c c0 ?? 01 8a 86 ?? ?? ?? ?? 88 04 1e ff 15 08 c0 ?? 01 83 fe 0a 75 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_PI_2147733032_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.PI!bit"
        threat_id = "2147733032"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 05 ?? ?? ?? ?? 8b fa c1 e7 ?? 03 3d ?? ?? ?? ?? 33 c7 8d 3c 16 33 c7 2b c8 8b c1 c1 e8 ?? 03 05 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 c7 8d 3c 0e 2b 75 f8 33 c7 2b d0 ff 4d fc 75}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 8b f1 8b f8 56 e8 ?? ff ff ff 83 c6 08 4f 75 f4}  //weight: 1, accuracy: Low
        $x_1_3 = {56 57 be 20 37 ef c6 e8 ?? ?? ?? ?? 89 45 f8 c7 45 fc 20 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RU_2147733033_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RU!bit"
        threat_id = "2147733033"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 b8 00 00 10 00 50 e8 ?? ?? ?? ?? (85 c0|83) 0f 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? b8 00 00 00 00 50 b8 00 00 10 00 50 e8 ?? ?? ?? ?? (85 c0|83) 0f 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? b8 00 00 00 00 50 b8 00 00 10 00 50 e8 ?? ?? ?? ?? (85 c0|83) 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RU_2147733033_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RU!bit"
        threat_id = "2147733033"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 52 8b 85 ?? ?? ?? ?? 8b 0c 85 ?? ?? ?? ?? 89 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 2b 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? c1 85 ?? ?? ?? ?? 0f 8b 85 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8b 55 ?? 8b 85 ?? ?? ?? ?? 89 04 8a eb 93}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e1 06 51 8b 15 ?? ?? ?? ?? 52 a1 ?? ?? ?? ?? 50 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RV_2147733034_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RV!bit"
        threat_id = "2147733034"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 fc 0f 1f 84 00 00 00 00 00 55 89 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RV_2147733034_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RV!bit"
        threat_id = "2147733034"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 8b 45 ?? 03 45 ?? 0f b6 08 03 d1 81 e2 ?? ?? ?? ?? 79 09 00 83 c4 ?? 8b 4d ?? 03 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 ?? ?? ?? ?? 83 f9 ?? 0f 82 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 73 13 0f ba 25 ?? ?? ?? ?? 01 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ?? 0f ba 25 ?? ?? ?? ?? 01 73 09 f3 a4}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 06 03 d0 83 f0 ?? 33 c2 8b 16 83 c6 04 a9 ?? ?? ?? ?? 74 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SD_2147733035_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SD!bit"
        threat_id = "2147733035"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0f 8b c1 33 d2 5f f7 f7 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 3b ce 72 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {73 09 8b 4d fc 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 18 30 1c 31 03 ce 47 40 46 4a 75}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 4c 24 04 8b c1 03 c9 c1 e8 ?? 6b c0 ?? 33 c1 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {57 32 d8 e8 ?? ?? ?? ?? 32 d8 a1 ?? ?? ?? ?? 32 5d ?? 83 c4 20 32 5d ?? 32 5d ?? 88 1c 06 8b 45 ?? 80 b8 ?? ?? ?? ?? 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SP_2147733037_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SP!bit"
        threat_id = "2147733037"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe d8 a6 08 00 7f 14 81 fe 50 f5 00 00 7d 09 50 ff d7 6a 00 ff d3 33 c0 46 eb e4}  //weight: 1, accuracy: High
        $x_1_2 = {8b cb c1 e9 10 88 0e 46 8b c3 c1 e8 08 88 06 46 88 1e 46 33 db 88 5d 0b}  //weight: 1, accuracy: High
        $x_1_3 = {8b 75 08 57 8b 7d 0c e8 ?? ?? ?? ?? 30 04 3e 5f 5e 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SQ_2147733038_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SQ!bit"
        threat_id = "2147733038"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 10 30 04 3a 42 3b 55 ?? 7c 0c 00 69 c9 ?? ?? ?? ?? 81 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {77 3f 2b f8 b8 ?? ?? ?? ?? f7 ef c1 fa 02 8b fa c1 ef 1f 03 fa 3b 4e 08 75}  //weight: 1, accuracy: Low
        $x_1_3 = {72 3b 2b 0b b8 ?? ?? ?? ?? f7 e9 33 c9 47 c1 fa 02 8b f2 c1 ee 1f 03 f2 ba ?? ?? ?? ?? 8b c6 d1 e8 2b d0 03 c6 3b d6 0f 43 c8 3b cf 0f 43 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SR_2147733039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SR!bit"
        threat_id = "2147733039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 50 ff 75 ?? ff 75 ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01}  //weight: 1, accuracy: High
        $x_1_3 = {8b ca 33 c1 8b d2 c7 45 fc 00 00 00 00 8b d2 01 45 fc 8b d2 8b 0d ?? ?? ?? ?? 8b 55 fc 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SU_2147733040_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SU!bit"
        threat_id = "2147733040"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4e 08 b8 ?? ?? ?? ?? 8b 1e 2b cb f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 c1 e8 ?? 30 04 1a 42 3b 55 10 7c 0c 00 69 c9 ?? ?? ?? ?? 81 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SU_2147733040_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SU!bit"
        threat_id = "2147733040"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8b 45 fc e8 ?? ?? ?? ?? 50 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b e8 8d b5 ?? ?? ?? ?? 4e 83 c6 04 81 e6 ?? ?? ?? ?? 6a 04 68 ?? ?? ?? ?? 56 6a 00 e8 ?? ?? ?? ?? 8b d8 85 db}  //weight: 1, accuracy: Low
        $x_1_3 = {8b de 66 81 3b 4d 5a 0f 85 ?? ?? ?? ?? 8b c6 33 d2 52 50 8b 43 3c 99 03 04 24 13 54 24 04 83 c4 08 8b f8 81 3f 50 45 00 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_4 = {50 8b 47 50 50 56 8b 45 ?? 50 8b 45 ?? 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_SW_2147733041_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.SW!bit"
        threat_id = "2147733041"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 8b 45 ?? 8b 08 51 6a 00 ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {52 6a 04 8d 85 ?? ?? ?? ?? 50 8b 8d ?? ?? ?? ?? 83 c1 08 51 8b 95 ?? ?? ?? ?? 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {56 57 ff d0 5f 5e 8b dd 5d 8b 4d 10 55 8b eb 81 f9 00 01 00 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_RA_2147733042_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.RA!bit"
        threat_id = "2147733042"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 07 47 0f af c1 ba ?? ?? ?? ?? ff 4d 0c 03 c2 40 83 7d 0c 00 77}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 50 08 8b 48 20 8b 00 81 79 0c ?? ?? ?? ?? 75 ef}  //weight: 1, accuracy: Low
        $x_1_3 = {8a c8 c0 f9 ?? 80 e1 ?? c0 e2 ?? c0 e0 ?? 02 45 ?? 32 ca 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TB_2147733043_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TB!bit"
        threat_id = "2147733043"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 5f 6a 40 68 00 30 00 00 68 00 64 01 00 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b df b9 e4 02 00 00 ba cf 00 00 00 e9 ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? ff d3 90 81 c4 e4 02 00 00 e9 ?? ?? ?? ?? 8a 06 32 c2 88 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TH_2147733044_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TH!bit"
        threat_id = "2147733044"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e9 21 e3 64 98 51 b8 ?? ?? ?? ?? ff 10}  //weight: 1, accuracy: Low
        $x_1_2 = {41 6a 00 6a 00 51 8d 05 ?? ?? ?? ?? ff 10 14 00 c6 05 ?? ?? ?? ?? 67 c6 05 ?? ?? ?? ?? 71 8d 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {41 6a 00 6a 00 51 8d 05 ?? ?? ?? ?? ff 10 0f 00 66 c7 05 ?? ?? ?? 00 6e 63 8d 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {5b 03 5b 3c 81 c3 a0 00 00 00 89 1d ?? ?? ?? ?? 8d 1d ?? ?? ?? ?? 81 c3 bf cd a2 89 89 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 4d c6 05 ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
        $x_1_5 = {31 f6 57 8b 13 f8 83 d3 04 f7 d2 f8 83 da 22 8d 52 ff 29 ca 31 c9 29 d1 f7 d9 52 8f 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_CeeInject_TG_2147733045_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TG!bit"
        threat_id = "2147733045"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 18 8b c8 c1 f9 03 8d 34 29 8b c8 83 e1 07 d2 e2 40 08 16 3b c7 7c e7}  //weight: 2, accuracy: High
        $x_1_2 = {50 51 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 6a 00 ff d7 8b 54 24 ?? 50 52 ff 54 24 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d5 50 ff d6 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 44 24 ?? ff d5 50 ff d6}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 88 9c 24 ?? ?? 00 00 c6 84 24 ?? ?? 00 00 55 88 94 24 ?? ?? 00 00 c6 84 24 ?? ?? 00 00 6d c6 84 24 ?? ?? 00 00 61 c6 84 24 ?? ?? 00 00 70 c6 84 24 ?? ?? 00 00 56 c6 84 24 ?? ?? 00 00 69 88 8c 24 ?? ?? 00 00 c6 84 24 ?? ?? 00 00 77 c6 84 24 ?? ?? 00 00 4f c6 84 24 ?? ?? 00 00 66 c6 84 24 ?? ?? 00 00 53 88 8c 24 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {27 c6 44 24 ?? 76 c6 44 24 ?? 63 c6 44 24 ?? 68 c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 2e 88 4c 24 ?? c6 44 24 ?? 78 88 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_TE_2147733046_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TE!bit"
        threat_id = "2147733046"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 50 8b 85 ?? ?? ?? ?? 99 03 04 24 13 54 24 04 83 c4 08 05 ?? ?? ?? ?? 83 d2 00 52 50 8b c6 c1 e0 03 8d 04 80 33 d2 03 04 24 13 54 24 ?? 83 c4 08 56 57 8b f0 8d bd ?? ?? ?? ?? b9 ?? ?? ?? ?? f3 a5}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 00 c1 e8 0c 83 f8 03 75 28 8b 85 ?? ?? ?? ?? 8b 00 8b 7d ?? 03 c7 8b 95 ?? ?? ?? ?? 66 8b 12 66 81 e2 ?? ?? 0f b7 d2 03 c2 2b bd ?? ?? ?? ?? 01 38}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f2 8b c1 8b 55 ?? 8b 14 b2 8b 4d ?? 89 14 99 8b 55 ?? 89 04 b2 8b 45 ?? 8b 04 98 8b 55 ?? 03 04 b2 b9 ?? ?? ?? ?? 99 f7 f9 8b 45 ?? 8b 14 90 8b 45 ?? 8b 4d ?? 0f b6 44 08 ff 33 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TR_2147733047_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TR!bit"
        threat_id = "2147733047"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 f7 fb 8b f9 c1 e7 18 0f b6 92 ?? ?? ?? ?? c1 e2 1b 33 d7 c1 ea 18 88 14 31 41 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 e9 8b f9 c1 ff ?? c1 fa ?? 2b d7 69 d2 ?? ?? ?? ?? f7 da 03 d1 0f b6 14 32 30 13 43 41}  //weight: 1, accuracy: Low
        $x_1_3 = {f7 ee 8b fe c1 ff ?? 03 d6 c1 fa ?? 2b d7 69 c2 ?? ?? ?? ?? f7 d8 03 c6 0f b6 84 18 ?? ?? ?? ?? 30 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_TR_2147733047_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.TR!bit"
        threat_id = "2147733047"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 72 0c 89 4a 04 c7 42 08 00 10 00 00 c7 02 00 00 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {74 d9 8b 44 24 ?? 8b 4c 24 ?? 83 f1 ?? 8b 54 24 ?? 8a 1c 02 89 4c 24 ?? 8b 4c 24 ?? 88 1c 01 83 c0 01 89 44 24 ?? 8b 74 24 ?? 39 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {89 fa f7 f1 8b 4c 24 ?? 8b 7c 24 ?? 89 7c 24 ?? 8b 7c 24 ?? 29 cf 8a 1c 15 ?? ?? ?? ?? 8b 4c 24 ?? 8a 3c 31 28 df 8b 54 24 ?? 88 3c 32 01 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UD_2147733049_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UD!bit"
        threat_id = "2147733049"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d1 89 55 ?? 8b 45 ?? 8b 0c 85 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? 89 0c 90}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 04 8a 33 05 ?? ?? ?? ?? 8b 4d ?? 8b 55 ?? 89 04 8a}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c2 3e 52 a1 ?? ?? ?? ?? 50 8b 4d ?? 51 8b 15 ?? ?? ?? ?? 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UE_2147733050_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UE!bit"
        threat_id = "2147733050"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 0f b6 d8 8a 54 1c ?? 0f b6 c2 03 c6 0f b6 f0 8a 44 34 ?? 88 44 1c ?? 88 54 34 ?? 0f b6 4c 1c ?? 0f b6 c2 03 c8 81 e1 ?? ?? ?? ?? 79 08 49 81 c9 ?? ?? ?? ?? 41 8a 4c 0c ?? 30 4d 00 45 85 ff 75}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 00 8b 40 10}  //weight: 1, accuracy: High
        $x_1_3 = {33 d2 8a 5c 3c ?? 8b c7 f7 f6 0f b6 04 0a 03 c5 0f b6 cb 03 c8 0f b6 e9 8b 4c 24 ?? 8a 44 2c ?? 88 44 3c ?? 47 88 5c 2c ?? 81 ff 00 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UF_2147733051_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UF!bit"
        threat_id = "2147733051"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b 06 8b fb 8a 11 4f 88 10 40 41 85 ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b c8 c1 f9 03 8d 34 39 8b c8 83 e1 07 d2 e2 08 16 40 83 f8 40 7c e3}  //weight: 1, accuracy: High
        $x_1_3 = {8b 06 03 85 ?? ?? ?? ?? 53 ff 76 fc 50 8b 46 f8 03 85 ?? ?? ?? ?? 50 ff b5 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 0f b7 47 06 ff 85 ?? ?? ?? ?? 83 c6 28 39 85 ?? ?? ?? ?? 7c c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UG_2147733052_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UG!bit"
        threat_id = "2147733052"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 33 ed 55 a3 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 9b 00 00 00 00 8b 15 ?? ?? ?? ?? 8a 8c 02 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 0c 02 40 3b 05 ?? ?? ?? ?? 72 e1}  //weight: 1, accuracy: Low
        $x_1_3 = {8b cf c1 e9 05 03 4b 0c 8b d7 c1 e2 04 03 53 08 50 33 ca 8d 14 38 33 ca 2b f1 8b ce c1 e9 05 03 4b 04 8b d6 c1 e2 04 03 13 33 ca 8d 14 30 33 ca 2b f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UI_2147733053_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UI!bit"
        threat_id = "2147733053"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 17 8d 52 01 80 f1 8b 80 c1 5a 80 f1 11 80 e9 15 88 4a ff 4e 75 e8}  //weight: 1, accuracy: High
        $x_1_2 = {75 b8 6a 00 68 ?? ?? ?? ?? 89 55 ?? 89 4d ?? ff 15 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {05 e0 33 00 00 50 56 ff 15 ?? ?? ?? ?? 5f 8d 46 01 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UL_2147733054_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UL!bit"
        threat_id = "2147733054"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8a 9e ?? ?? ?? ?? 8b c6 f7 f5 0f be 04 0a 03 c7 0f b6 cb 03 c8 0f b6 f9 8b 4c 24 ?? 89 3d ?? ?? ?? ?? 8a 87 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 46 88 9f ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 75 bb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 0c 8b d0 e8 ?? ?? ?? ?? eb 08 e8 ?? ?? ?? ?? 30 04 37 83 ee 01 79 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UL_2147733054_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UL!bit"
        threat_id = "2147733054"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 8a 45 10 88 45 ?? 8b 4d 08 03 4d 0c 8a 55 ?? 88 11 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 08 03 45 0c 8b 4d 10 8a 10 88 11 5d}  //weight: 1, accuracy: High
        $x_1_3 = {2b d8 88 5d 08 00 8b 54 85 ?? 8d 44 16}  //weight: 1, accuracy: Low
        $x_1_4 = {51 6a 00 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 45 ?? 8b 5d ?? ff 75 ?? ff 75 ?? 68 ?? ?? ?? ?? 6a 00 6a ff 5a ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UV_2147733055_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UV!bit"
        threat_id = "2147733055"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 50 ff 75 ?? ff 75 ?? ff 35 ?? ?? ?? ?? 59 ff d1}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 01 00 8b 55 ?? 03 55 ?? 0f b6 02 8b 4d ?? 03 4d ?? 0f b6 11 8d 84 02 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01 8b 55 ?? 03 55 ?? 0f b6 02 2d ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_UW_2147733056_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.UW!bit"
        threat_id = "2147733056"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0a 6a 40 68 00 30 00 00 56 eb 09 6a 02 6a 00 68 00 10 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_2_2 = {85 ff 74 08 8a 4c 24 ?? 02 c8 eb 06 8d 0c 06 8a 0c 11 85 db 75 03 88 0c 10 40 3b c5 7c e2}  //weight: 2, accuracy: Low
        $x_1_3 = {8a 44 24 68 32 c3 [0-16] 88 44 24 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_AAF_2147733057_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAF!bit"
        threat_id = "2147733057"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d7 8a 4d ?? 88 0e 46 88 5d ?? 3b f5 74 05 4d 3b f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAF_2147733057_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAF!bit"
        threat_id = "2147733057"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 04 c1 ea 05 03 54 24 08 33 c2 33 c1 c3}  //weight: 1, accuracy: High
        $x_1_2 = {51 55 8b d0 8b cb e8 ?? ?? ?? ?? 2b f8 59 59 8b cf 8b c7 c1 e9 05 03 4c 24 ?? c1 e0 04 03 44 24 ?? 33 c8 8d 04 2f 33 c8 8b 44 24 ?? 2b d9 6a f7 59 2b c8 8b 44 24 ?? 03 e9 8b 4c 24}  //weight: 1, accuracy: Low
        $x_1_3 = {03 c0 50 57 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAH_2147733058_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAH!bit"
        threat_id = "2147733058"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 3e 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {85 ff 75 3d 68 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 6b 65 72 6e c6 05 ?? ?? ?? ?? 65 88 1d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 33 32 2e 64 88 1d ?? ?? ?? ?? 88 1d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 00 ff d6 8b f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAL_2147733059_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAL!bit"
        threat_id = "2147733059"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 33 32 46 c7 05 ?? ?? ?? ?? 69 72 73 74 66 c7 ?? ?? ?? ?? 00 57 00 c7 05 ?? ?? ?? ?? 4d 6f 64 75 c6 05 ?? ?? ?? ?? 6c ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {73 25 8b 45 ?? 89 85 ?? ?? ?? ?? 8b 45 ?? 03 85 ?? ?? ?? ?? 8b 4d ?? 03 8d ?? ?? ?? ?? 8a 89 ?? ?? ?? ?? 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAO_2147733063_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAO!bit"
        threat_id = "2147733063"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 37 6b f9 ?? 01 f8 33 10 89 d8 03 44 24 ?? 89 e7 89 57 08 89 77 04 89 07 89 54 24 ?? 89 4c 24 ?? 89 5c 24 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BAG_2147733064_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BAG!bit"
        threat_id = "2147733064"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8a 9d ?? ?? ?? 00 8b c5 0f b6 cb f7 f7 0f be 82 ?? ?? ?? 00 03 c6 03 c8 0f b6 f1 8a 86 ?? ?? ?? 00 88 85 ?? ?? ?? 00 45 88 9e ?? ?? ?? 00 81 fd 00 01 00 00 75 c8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 ff 35 78 ef 42 00 56 ff 15 08 e0 41 00 a3 ?? ?? ?? 00 8b fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AFS_2147733094_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AFS!bit"
        threat_id = "2147733094"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\dahkService\\dahkService.exe" ascii //weight: 1
        $x_1_2 = "client_id=%.8x&connected=%d&server_port=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BAD_2147733118_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BAD!bit"
        threat_id = "2147733118"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 10 33 c1 8b ?? 08 c1 ?? 05 03 ?? 14 33 ?? 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 14 33 c1 8b ?? 08 c1 ?? 05 03 ?? 10 33}  //weight: 1, accuracy: Low
        $x_1_3 = {89 55 fc 8b 45 fc c1 e0 04 03 45 e4 8b 4d fc 03 4d f4 33 c1 8b 55 fc c1 ea 05 03 55 e0 33 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_BCA_2147733140_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BCA!bit"
        threat_id = "2147733140"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 73 b2 5c b1 65}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 1e 74 88 4c 24 1f c6 44 24 20 6d c6 44 24 21 33 c6 44 24 22 32 88 54 24 23 88 44 24 24 c6 44 24 25 76 c6 44 24 26 63 c6 44 24 27 68 c6 44 24 28 6f 88 44 24 29 c6 44 24 2a 74 c6 44 24 2b 2e 88 4c 24 2c c6 44 24 2d 78 88 4c 24 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KXD_2147733153_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.KXD!bit"
        threat_id = "2147733153"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f9 72 05 75 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? eb 06 ?? ?? ?? ?? ?? ?? 33 05 ?? ?? ?? ?? f8 73 06 74 e9 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? eb 05 74 e9 74 75 ?? 89 07 8d 7f 04 8b ce}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 15 61 19 43 00 ff 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KXE_2147733154_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.KXE!bit"
        threat_id = "2147733154"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7c c5 53 8b 5d ?? 6a 04 8d 46 ?? 50 8b 83 ?? ?? ?? ?? 83 c0 08 50 ff 75 ec ff d7 8b 46 28 03 45 08 53 89 83 ?? ?? ?? ?? ff 75 f0 ff 15 ?? ?? ?? ?? ff 75 f0 ff 15 ?? ?? ?? ?? 8b 45 f4 eb 03}  //weight: 1, accuracy: Low
        $x_1_2 = {99 59 f7 f9 39 55 ?? 77 0a 68 4c b4 42 00 e8 ?? ?? ?? ?? 83 7d ?? 10 8b 45 ?? 73 03 8d 45 ?? 8b 4e ?? 8a 04 10 88 45 ?? 83 f9 ?? 72 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ABT_2147733189_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABT!bit"
        threat_id = "2147733189"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 6a 00 ff 15 15 00 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 35}  //weight: 1, accuracy: Low
        $x_1_2 = {03 45 fc 83 65 f4 00 a3 ?? ?? ?? ?? 81 f3 ?? ?? ?? ?? 81 6d f4 ?? ?? ?? ?? 81 45 f4 ?? ?? ?? ?? 8b 4d f4 d3 e8 5b 25}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 14 06 e8 ?? ?? ?? ?? 30 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAQ_2147733190_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAQ!bit"
        threat_id = "2147733190"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 ff 75 ?? c1 e8 05 03 45 ?? 8b cf c1 e1 04 03 4d ?? 8b d6 33 c1 8d 0c 3e 33 c1 29 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 01 45 fc 8b c1 c1 e0 04 03 45 08 03 ca 33 c1 33 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BCB_2147733498_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BCB!bit"
        threat_id = "2147733498"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 14 33 c1 8b 4d 08 c1 e9 05 03 4d 10 33 c1 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 10 33 c1 8b 4d 08 c1 e9 05 03 4d 14 33 c1 5d}  //weight: 1, accuracy: High
        $x_1_3 = {6a 6b 58 8b 4d cc 66 89 04 4d ?? ?? ?? ?? 8b 45 cc 40 89 45 cc 6a 65 58 8b 4d cc 66 89 04 4d ?? ?? ?? ?? 8b 45 cc 40 89 45 cc 6a 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAN_2147733504_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAN!bit"
        threat_id = "2147733504"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 03 d9 03 c8 8a 1c 03 88 1c 39 8b 0d ?? ?? ?? ?? 03 c8 03 cf 8a 19 32 da 40 3d da 04 00 00 88 19 0d 00 8b 0d ?? ?? ?? ?? 8a 16 bb}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 4e e6 40 bb}  //weight: 1, accuracy: High
        $x_1_3 = "SUUS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BCE_2147733533_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BCE!bit"
        threat_id = "2147733533"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f0 73 c6 45 f1 76 c6 45 f2 63 c6 45 f3 68 c6 45 f4 6f c6 45 f5 73 c6 45 f6 74 c6 45 f7 2e c6 45 f8 65 c6 45 f9 78}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 ec 53 c6 45 ed 51 c6 45 ee 4c c6 45 ef 00 c6 45 c8 5a c6 45 c9 4b c6 45 ca 46 c6 45 cb 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 03 45 e4 0f b6 08 8b 55 0c 03 55 e4 0f b6 02 33 c8 8b 55 08 03 55 e4 88 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_AAP_2147733548_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAP!bit"
        threat_id = "2147733548"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 2b 55 14 89 45 14 03 d0 ff e2 07 00 b9 ?? ?? ?? ?? f3 a4}  //weight: 1, accuracy: Low
        $x_1_2 = {3b f1 72 17 87 06 33 45 20 03 45 24 87 06 83 ee 04 eb ed}  //weight: 1, accuracy: High
        $x_1_3 = {66 81 3e 4d 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BCF_2147733632_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BCF!bit"
        threat_id = "2147733632"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0b 81 f9 43 54 53 0a 75 06 2b 43 04 83 e8 18}  //weight: 1, accuracy: High
        $x_1_2 = {d1 e8 35 20 83 b8 ed eb 02}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 04 39 33 c6 25 ff 00 00 00 c1 ee 08 33 b4 85 00 fc ff ff 41 3b ca 72 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BCG_2147733769_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BCG!bit"
        threat_id = "2147733769"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec ff 75 0c [0-16] 8a 45 08 [0-16] 59 [0-16] 30 01 [0-16] 5d c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {56 6a 40 52 53 6a ff e8 ?? ?? ?? ff [0-16] 33 c0 89 06 [0-16] 8b 06 03 c3 73 05 e8 ?? ?? ?? ff 50 68 ?? ?? ?? ?? ff 15 [0-16] ff 06 81 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_AAY_2147733845_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.AAY!bit"
        threat_id = "2147733845"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 04 8b c2 c1 e0 04 8b ca 03 44 24 08 c1 e9 05 03 4c 24 10 33 c1 8b 4c 24 0c 03 ca 33 c1}  //weight: 1, accuracy: High
        $x_1_2 = {8b cf 8b c7 c1 e9 05 03 4c 24 ?? c1 e0 04 03 44 24 ?? 33 c8 8d 04 2f 33 c8 8b 44 24 ?? 2b d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDA_2147733902_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDA!bit"
        threat_id = "2147733902"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4c 24 04 83 44 24 04 06 8b 4c 24 0c 8a d0 d2 e2 80 e2 c0 08 55 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 10 01 44 24 04 8b d1 03 4c 24 14 c1 e2 04 03 54 24 0c 89 4c 24 0c 89 14 24 8b 44 24 0c 31 04 24 8b 04 24 33 44 24 04}  //weight: 1, accuracy: High
        $x_1_3 = {8b d6 c1 ea 05 03 54 24 10 8b c6 c1 e0 04 03 44 24 14 8d 0c 37 33 d0 8b 44 24 1c 33 d1 2b ea 8b 54 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KXA_2147733911_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.KXA!bit"
        threat_id = "2147733911"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 8b 4d fc 55 5c 83 f8 7b 74 2c e8 ?? ?? ?? ?? 55 6a 79 51 ff 55 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 e2 8b 7c 24 ?? 69 df ?? ?? ?? ?? 01 da 8b 5c 24 ?? 8a 1c 0b 89 54 24 ?? 89 44 24 ?? 8b 44 24 ?? 8a 3c 08 88 7c 24 ?? 3a 5c 24 ?? 0f 94 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDB_2147733913_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDB!bit"
        threat_id = "2147733913"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4c 24 08 8b c1 c1 e0 04 89 04 24 8b 44 24 0c 01 04 24 8b d1 c1 ea 05 89 54 24 08 8b 44 24 14 01 44 24 08 8b 44 24 10 03 c1 33 44 24 08 33 04 24}  //weight: 10, accuracy: High
        $x_1_2 = {8b d6 c1 e2 04 89 54 24 30 8b 44 24 20 01 44 24 30 89 74 24 34 c1 6c 24 34 05 8b 44 24 24 01 44 24 34 8d 04 37 33 44 24 34 b9 f7 ff ff ff 33 44 24 30 2b 4c 24 28 43 2b e8 03 f9 83 fb 20}  //weight: 1, accuracy: High
        $x_1_3 = {8b d6 c1 e2 04 89 54 24 10 8b 44 24 1c 01 44 24 10 89 74 24 38 c1 6c 24 38 05 8b 44 24 20 01 44 24 38 8d 04 37 33 44 24 38 b9 f7 ff ff ff 33 44 24 10 2b 4c 24 24 43 2b e8 03 f9 83 fb 20}  //weight: 1, accuracy: High
        $x_1_4 = {8b c6 c1 e0 04 89 44 24 10 8b 44 24 1c 01 44 24 10 89 74 24 38 c1 6c 24 38 05 8b 44 24 20 01 44 24 38 8d 0c 37 33 4c 24 38 ba f7 ff ff ff 33 4c 24 10 2b 54 24 24 43 2b e9 03 fa 83 fb 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_BDC_2147733955_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDC!bit"
        threat_id = "2147733955"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d e0 66 c7 03 55 89}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d e0 66 c7 81 be 03 00 00 83 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 5d e0 66 c7 83 c0 03 00 00 04 31}  //weight: 1, accuracy: High
        $x_1_4 = {8b 5d e0 66 c7 83 c2 03 00 00 37 83}  //weight: 1, accuracy: High
        $x_1_5 = {8b 55 e0 66 c7 82 c4 03 00 00 c7 04}  //weight: 1, accuracy: High
        $x_1_6 = {8b 55 e0 66 c7 82 c6 03 00 00 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDE_2147734293_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDE!bit"
        threat_id = "2147734293"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 5c 00 00 00 ?? ?? ?? ?? b8 4c 00 00 00 ?? ?? ?? ?? b9 69 00 00 00 ?? ?? ?? ?? ba 65 00 00 00 ?? ?? ?? ?? b8 62 00 00 00 ?? ?? ?? ?? b9 65 00 00 00 ?? ?? ?? ?? ba 72 00 00 00 ?? ?? ?? ?? b8 74 00 00 00 ?? ?? ?? ?? b9 2e 00 00 00 ?? ?? ?? ?? ba 62 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d f8 83 c1 01 89 4d f8 eb e3 81 7d f8 ef be ad ba 74 04 33 c0 eb 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDF_2147734333_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDF!bit"
        threat_id = "2147734333"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 89 45 fc ff 75 fc 81 04 24 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {54 6a 40 68 e2 59 00 00 57 e8 ?? ?? ?? ff [0-16] 33 d2 [0-16] 33 c0 89 04 24 b8 ?? ?? 47 00 [0-16] 8b f7 03 f2 [0-16] 8a 08 [0-16] 80 f1 [0-16] 88 0e [0-16] 42 [0-16] ff 04 24 40 81 3c 24 ?? ?? ?? ?? 75 [0-16] 8b c7 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ff 8b f8 [0-16] 33 c0 89 04 24 be 2f 5c 00 00 bb 44 b4 46 00 [0-16] 8b d7 03 14 24 [0-16] 8a 03 [0-16] 34 c0 [0-16] 88 02 [0-16] 8b c4 e8 ?? ?? ?? ff [0-16] 43 4e 75 [0-16] 8b c7 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CeeInject_BDG_2147734358_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDG!bit"
        threat_id = "2147734358"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 fc ff 55 fc 0d 00 81 c6 ?? ?? ?? ?? 73 05 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 fc 50 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ff 33 c9 33 db 8b c6 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 71 05 e8 ?? ?? ?? ff 83 c4 08 81 f9 ?? ?? ?? ?? 76 05 e8 ?? ?? ?? ff 8a 91 ?? ?? ?? ?? 80 ?? ?? 88 10 [0-16] 83 c1 01 73 05 e8 ?? ?? ?? ff 83 c1 01 73 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDH_2147734393_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDH!bit"
        threat_id = "2147734393"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 89 45 fc 8b 5d fc [0-16] 81 c3 [0-16] ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ff [0-16] 33 c0 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 45 f8 43 f0 00 8a 03 [0-16] 34 ?? [0-16] 92 e8 ?? ?? ?? ff [0-16] 8b 4d fc [0-16] 83 c1 01 [0-16] 89 4d fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KXB_2147734508_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.KXB!bit"
        threat_id = "2147734508"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c8 80 e1 fc c0 e1 ?? 08 0f 8b 4c 24 04 d2 e0 5d 24 c0 08 06 59 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {89 0c 24 c1 24 24 ?? 8b 44 24 0c 01 04 24 89 4c 24 04 c1 6c 24 04 ?? 8b 44 24 14 01 44 24 04 03 4c 24 10 89 4c 24 10 8b 44 24 10 31 04 24 8b 44 24 04 31 04 24 8b 04 24 83 c4 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDI_2147734872_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDI!bit"
        threat_id = "2147734872"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d4 c1 e0 04 03 45 e4 8b 4d d4 03 4d ec 33 c1 8b 55 d4 c1 ea 05 03 55 e8 33 c2 8b 4d f4 2b c8 89 4d f4 8b 55 f4 c1 e2 04 03 55 f8 8b 45 f4 03 45 ec 33 d0 8b 4d f4 c1 e9 05 03 4d d8 33 d1 8b 45 d4 2b c2 89 45 d4}  //weight: 1, accuracy: High
        $x_1_2 = {ff 56 c6 85 ?? ?? ?? ff 74 c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 6f c6 85 ?? ?? ?? ff 72 c6 85 ?? ?? ?? ff 63 c6 85 ?? ?? ?? ff 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDJ_2147734874_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDJ!bit"
        threat_id = "2147734874"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 4c c6 85 ?? ?? ?? ff 6f c6 85 ?? ?? ?? ff 63 c6 85 ?? ?? ?? ff 6c c6 85 ?? ?? ?? ff 6c c6 85 ?? ?? ?? ff 61 c6 85 ?? ?? ?? ff 41 c6 85 ?? ?? ?? ff 6f c6 85 ?? ?? ?? ff 63}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d7 c1 ea 05 03 54 24 20 8b c7 c1 e0 04 03 c1 33 d0 8d 04 3b 33 d0 2b f2 8b d6 c1 ea 05 03 54 24 18 8b c6 c1 e0 04 03 c5 33 d0 8d 04 33 33 d0 2b fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDK_2147735110_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDK!bit"
        threat_id = "2147735110"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 [0-16] 8b c2 03 c3 [0-16] c6 00 ?? [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f8 50 6a 40 68 af 5b 00 00 56 e8 [0-16] 33 c0 89 45 fc [0-16] 33 c0 89 45 f8 bb [0-16] 8b c6 03 45 fc [0-16] 8b d0 8a 03 e8 ?? ?? ?? ff [0-16] 8b 55 fc [0-16] 83 c2 01 [0-16] [0-16] 89 55 fc [0-16] ff 45 f8 43 81 7d f8 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KXC_2147735111_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.KXC!bit"
        threat_id = "2147735111"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 4c 37 03 8a c1 8a d9 80 e1 f0 24 fc 02 c9 c0 e0 04 0a 44 37 01 c0 e3 06 0a 5c 37 02 02 c9 0a 0c 37 8b 7d fc 88 0c 3a 42 88 04 3a 42 88 1c 3a 83 c6 04 42 3b 35}  //weight: 2, accuracy: High
        $x_1_2 = {53 56 57 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8b f0 a3 ?? ?? ?? ?? b0 ?? 88 44 24 ?? 88 44 24 ?? 8d 44 24 ?? b2 ?? b3 ?? b1 ?? 50 56}  //weight: 1, accuracy: Low
        $x_1_3 = {53 56 57 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8b f0 a3 ?? ?? ?? ?? b0 ?? 88 84 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? b2 ?? b1 ?? b3 ?? 50 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CeeInject_BDL_2147735113_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDL!bit"
        threat_id = "2147735113"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f8 50 6a 40 68 23 52 00 00 8b 45 08 50 ff 55 f4 [0-16] 33 c0 89 45 f0 8b 45 f0 89 45 f8 8b 45 08 03 45 f8 8a 00 88 45 ef [0-16] 8a 45 ef 34 ?? 8b 55 08 03 55 f8 88 02 ff 45 f0 81 7d f0 ?? ?? ?? ?? 75 ?? 8b 45 08 05 94 05 00 00 89 45 fc ff 65 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDM_2147735189_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDM!bit"
        threat_id = "2147735189"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 54 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ff 33 ff [0-16] 33 db b2 2b 8b c3 03 c6 [0-16] 8a 8f ?? ?? ?? ?? 88 4c 24 04 [0-16] 32 54 24 04 88 10 [0-16] 8d 47 02 8b f8 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 fc 8b 75 fc 68 ?? ?? ?? ?? 01 34 24 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDN_2147735200_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDN!bit"
        threat_id = "2147735200"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 8d 45 fc 50 6a 40 68 0d 58 00 00 56 e8 ?? ?? ?? ff 33 c0 33 db [0-16] 89 5d f8 [0-16] 8a [0-16] 80 f2 9b ?? ce 03 4d f8 88 11 40 40}  //weight: 1, accuracy: Low
        $x_1_2 = {89 75 fc ff 55 fc 30 00 43 81 fb 0d 58 00 00 75 dd [0-16] 81 c6 44 1c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDO_2147735272_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDO!bit"
        threat_id = "2147735272"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 89 45 fc 8b 5d fc [0-16] 81 c3 [0-16] 53 20 00 34 ?? 88 02}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 89 45 fc 8b 4d fc [0-16] 81 c1 [0-16] 51 [0-16] c3 30 00 34 ?? 88 02}  //weight: 1, accuracy: Low
        $x_1_3 = {54 6a 40 68 ?? ?? ?? ?? 57 e8 ?? ?? ?? ff 20 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_ABF_2147735273_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABF!bit"
        threat_id = "2147735273"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 9c 8b 5c 24 ?? 8b c3 99 b9 47 01 00 00 f7 f9 8b 44 24 ?? 8b cd 8a 04 02 30 04 1f a1 ?? ?? ?? ?? 3b c5 7f 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {7f 51 66 81 3d ?? ?? ?? ?? c2 0d 7f 46 66 ff 05 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? 5f 01 00 00 66 03 15 ?? ?? ?? ?? 6a 54 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDP_2147735312_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDP!bit"
        threat_id = "2147735312"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 89 45 fc 8b 5d fc [0-16] 81 c3 33 36 00 00 [0-16] ff e3 20 00 34 ?? 88 02}  //weight: 1, accuracy: Low
        $x_1_2 = {54 6a 40 68 ?? ?? ?? ?? 57 e8 ?? ?? ?? ff 20 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_BDQ_2147735314_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDQ!bit"
        threat_id = "2147735314"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ff 80 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b f0}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 89 45 fc 8b 75 fc [0-16] 81 c6 [0-16] ff d6 30 00 34 ?? 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_BDR_2147735335_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDR!bit"
        threat_id = "2147735335"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 89 45 fc 8b 5d fc 68 ?? ?? ?? ?? 01 1c 24 c3 30 00 8a 45 08 59 [0-16] 30 01 [0-16] 5d c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 89 45 fc 8b 5d fc 68 ?? ?? ?? ?? 01 1c 24 c3 40 00 8a 45 08 [0-16] 5b 30 03 [0-16] 5d c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CeeInject_ABQ_2147735463_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ABQ!bit"
        threat_id = "2147735463"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 db 2b 1e f7 db f8 83 d6 04 f7 db 8d 5b f1 c1 cb 09 d1 c3 31 d3 4b 89 da c1 c2 09 d1 ca f7 da 53 8f 07}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 0f 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 5e 83 c6 10 31 d2 4a 81 e2 ?? ?? ?? ?? 8d 38 31 c0 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_KXF_2147735501_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.KXF!bit"
        threat_id = "2147735501"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 a9 00 00 00 04 74 0a [0-16] 81 ca 00 02 00 00 a9 00 00 00 20 74 63 [0-32] a9 00 00 00 40 74 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 34 0f b7 00 c1 e8 0c 83 f8 03 75 29 [0-16] 8b 44 24 04 8b 7d 00 8b d7 2b 50 34 8b 44 24 30 8b 00 03 c7 8b 4c 24 34 66 8b 09 66 81 e1 ?? ?? 0f b7 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDS_2147735818_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDS!bit"
        threat_id = "2147735818"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 dc 6f 73 6f 66}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 e0 74 20 48 76}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 b8 58 65 6e 56}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 bc 4d 4d 58 65}  //weight: 1, accuracy: High
        $x_1_5 = {c7 45 c0 6e 56 4d 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDT_2147735824_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDT!bit"
        threat_id = "2147735824"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 8b 45 fc 50 e8 ?? ?? ?? ff [0-16] 33 c0 89 06 [0-16] 33 c0 89 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 45 f8 43 81 7d f8 ?? ?? ?? ?? 75 b7 [0-16] 8b 4d fc [0-16] 81 c1 [0-16] ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDU_2147735911_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDU!bit"
        threat_id = "2147735911"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b da 03 d9 c6 03 ?? [0-16] 41 48 75 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 fc 8b 45 fc 68 ?? ?? ?? ?? 01 04 24 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {32 c2 8b 55 fc 88 02 [0-16] 8b 45 f8 89 45 fc c7 45 f8 01 00 00 00 8b 45 f8 01 45 fc 8b 45 f8 01 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDV_2147735916_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDV!bit"
        threat_id = "2147735916"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 03 cb c6 01 ?? 43 48 75}  //weight: 1, accuracy: Low
        $x_1_2 = {05 ed 38 00 00 ff d0 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 07 03 c3 a3 [0-16] a1 [0-16] 8a 80 ?? ?? ?? ?? 34 ?? ?? ?? ?? 47 00 [0-16] a1 [0-16] 8a 15 f4 6b 47 00 88 10 83 05 [0-16] 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDX_2147739706_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDX!bit"
        threat_id = "2147739706"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 83 e0 03 8a 44 05 f8 30 44 0d fc 41 83 f9 04 72 ed 80 7d fc e9 75 10 80 7d fd 40 75 0a 38 5d fe 75 05 38 5d ff 74 03}  //weight: 1, accuracy: High
        $x_1_2 = {8b c1 83 e0 03 8a 44 05 f8 30 81 ?? ?? ?? ?? 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDY_2147739788_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDY!bit"
        threat_id = "2147739788"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 00 50 ff 55 ec 89 45 90 8b 75 a8 8b 7d a8 8b 4d f8}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e9 02 8b 06 83 c6 04 8b 5d 90 31 d8 89 07 83 c7 04 e2 ef ff 65 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BDZ_2147739803_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BDZ!bit"
        threat_id = "2147739803"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 57 56 51 ff 4d 08 8b 4d 0c 03 c8 83 f8 00 72 14 83 f9 0a 76 0f 83 7d 08 00 76 09 50 ff 75 08 e8 d9 ff ff ff 3b c8 75 10 83 7d 08 00 76 0a 6a 64 ff 75 08 e8 c5 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BEA_2147739804_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BEA!bit"
        threat_id = "2147739804"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 ff d0 8b f0 ba 00 a0 00 10 8b ce 2b d6 bf ?? ?? ?? ?? 8b ff 8a 04 0a 34 ?? 88 01 41 83 ef 01 75 f3 8d 4c 24 20 51 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BEB_2147739880_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BEB!bit"
        threat_id = "2147739880"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 4d 08 ff 93 ?? ?? ?? ?? 8b 4d 0c 03 c8 83 f8 00 72 14 83 f9 0a 76 0f 83 7d 08 00 76 09 50 ff 75 08 e8 d3 ff ff ff 3b c8 75 10 83 7d 08 00 76 0a 6a 64 ff 75 08 e8 bf ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ACC_2147740280_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ACC!bit"
        threat_id = "2147740280"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 b9 04 00 00 00 f7 f1 8b 45 ?? 0f be 0c 10 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d ?? 88 81}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 0f b6 08 89 4d ?? 8b 55 ?? 89 55 ?? 8b 45 08 83 c0 01 89 45 08 83 7d ?? 00 74 11 8b 4d ?? c1 e1 05 03 4d ?? 03 4d ?? 89 4d}  //weight: 1, accuracy: Low
        $x_1_3 = {3b 45 0c 75 15 8b 55 ?? 8b 45 ?? 0f b7 0c 50 8b 55 ?? 8b 45 08 03 04 8a eb 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BEC_2147740287_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BEC!bit"
        threat_id = "2147740287"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 1b 46 17 2c 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f4 83 c2 01 89 55 f4 83 7d f4 04 73 26 8b 45 f4 33 d2 b9 04 00 00 00 f7 f1 8b 45 dc 0f be 0c 10 8b 55 f4 0f b6 44 15 e8 33 c1 8b 4d f4 88 44 0d e8 eb cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BED_2147740311_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BED!bit"
        threat_id = "2147740311"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 a4 83 c4 04 8b 55 a4 8b 12 8d bd 1c fd ff ff 8b 75 a4 83 c6 04 b9 39 00 00 00 8b 1e 31 d3 89 1f 83 c6 04 83 c7 04 83 e9 01 89 c8 85 c1 75 eb 8b 45 a4 66 31 c0 66 bb 4d 5a}  //weight: 1, accuracy: High
        $x_1_2 = {89 4d 90 8b 75 a8 8b 7d a8 8b 4d f8 c1 e9 02 8b 06 83 c6 04 8b 5d 90 31 d8 89 07 83 c7 04 e2 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_BEE_2147740312_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.BEE!bit"
        threat_id = "2147740312"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 ff d0 be ?? ?? 00 10 8b c8 2b f0 bf a1 05 00 00 5b 8d 64 24 00 8a 14 0e 80 f2 ?? 88 11 41 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CeeInject_ACE_2147921662_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CeeInject.ACE!MTB"
        threat_id = "2147921662"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CeeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8b 94 8d fc fb ff ff 03 fa 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff 47 8b b4 bd fc fb ff ff 0f b6 d2 89 b4 8d fc fb ff ff 89 94 bd fc fb ff ff 8b b4 8d fc fb ff ff 03 f2 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 0f b6 94 b5 fc fb ff ff 8b b5 f4 fb ff ff 30 14 06 40 3b c3}  //weight: 2, accuracy: High
        $x_1_2 = {47 8a 84 8d 04 fc ff ff 8b 94 bd fc fb ff ff 0f b6 c0 89 94 8d 04 fc ff ff 89 84 bd fc fb ff ff 33 d2 8d 46 01 f7 b5 f8 fb ff ff 0f b6 14 1a 03 94 8d 08 fc ff ff 03 fa 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff 47 8a 84 8d 08 fc ff ff 8b 94 bd fc fb ff ff 89 94 8d 08 fc ff ff 0f b6 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

