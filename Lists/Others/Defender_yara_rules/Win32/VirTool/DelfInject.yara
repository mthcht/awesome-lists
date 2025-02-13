rule VirTool_Win32_DelfInject_D_2147597437_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!D"
        threat_id = "2147597437"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RtlDecompressBuffer" ascii //weight: 1
        $x_1_2 = {89 45 e4 c7 45 f0 01 00 00 00 8b 45 fc 8b 55 f0 0f b6 44 10 ff}  //weight: 1, accuracy: High
        $x_3_3 = {64 ff 30 64 89 20 52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b 59 5a 33 c0 5a 59 59 64 89 10}  //weight: 3, accuracy: High
        $x_3_4 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b 36 8b 04 24 64 89 05 00 00 00 00 83 c4 08 85 db 0f 94 c0 36 8d 65 fc 36 8b 1c 24 36 8b 6c 24 04 83 c4 08 c3 8b 4c 24 0c c7 81 a4 00 00 00 ff ff ff ff 83 81}  //weight: 3, accuracy: High
        $x_5_5 = {ff ff ff ff 07 00 00 00 73 61 6e 64 62 6f 78 00 ff ff ff ff 05 00 00 00 68 6f 6e 65 79 00 00 00 ff ff ff ff 06 00 00 00 76 6d 77 61 72 65 00 00 ff ff ff ff 0b 00 00 00 63 75 72 72 65 6e 74 75 73 65 72 00 ff ff ff ff 09 00 00 00 6e 65 70 65 6e 74 68 65 73}  //weight: 5, accuracy: High
        $x_1_6 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_7 = "VirtualProtectEx" ascii //weight: 1
        $n_100_8 = "/s \"C:\\SMGCatcher.dll\"" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_M_2147597439_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!M"
        threat_id = "2147597439"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 04 68 00 30 00 00 8b 45 ?? 8b 40 50 50 8b 45 ?? 8b 40 34 50 8b 45 ?? 50 a1 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 3, accuracy: Low
        $x_2_2 = {8b d0 83 c2 15 8d 44 24 08 88 50 01 c6 00 01 8d 54 24 08 8d 44 24 10 b1 04 e8}  //weight: 2, accuracy: High
        $x_1_3 = {8d 34 9b 8b 45 e0 8b 44 f0 10 50 8b 45 e0 8b 44 f0 14 03 c7 50 8b 45 e0 8b 44 f0 0c 03 45 f4}  //weight: 1, accuracy: High
        $x_2_4 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 ?? ?? ff ff 8b 55 ?? 30 04 3a 47 ff 4d ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_I_2147597440_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!I"
        threat_id = "2147597440"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 75 84 60 82 7f 73 51 74 74 82 75 83 83}  //weight: 1, accuracy: High
        $x_1_2 = {56 82 75 75 5c 79 72 82 71 82 89}  //weight: 1, accuracy: High
        $x_1_3 = {56 82 75 75 62 75 83 7f 85 82 73 75}  //weight: 1, accuracy: High
        $x_1_4 = {53 7c 7f 83 75 58 71 7e 74 7c 75}  //weight: 1, accuracy: High
        $x_1_5 = {56 79 7e 74 62 75 83 7f 85 82 73 75 51}  //weight: 1, accuracy: High
        $x_1_6 = {63 79 8a 75 7f 76 62 75 83 7f 85 82 73 75}  //weight: 1, accuracy: High
        $x_1_7 = {5c 7f 71 74 62 75 83 7f 85 82 73 75}  //weight: 1, accuracy: High
        $x_1_8 = {5c 7f 73 7b 62 75 83 7f 85 82 73 75}  //weight: 1, accuracy: High
        $x_1_9 = "RtlDecompressBuffer" ascii //weight: 1
        $x_1_10 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_11 = {8b 45 fc 8a 44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 80 ea 10 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_N_2147597443_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!N"
        threat_id = "2147597443"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "FreeResource" ascii //weight: 10
        $x_10_2 = "GetModuleHandleA" ascii //weight: 10
        $x_10_3 = "SETTINGS" ascii //weight: 10
        $x_1_4 = {8b 45 fc 8a 5c 38 ff 80 e3 0f b8 ?? ?? ?? ?? 8a 44 30 ff 24 0f 32 d8 80 f3 0a 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 3a ff 80 e2 f0 02 d3 88 54 38 ff 46 83 fe 03 7e 05 be 01 00 00 00 47 ff 4d f4 75 bd}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 ?? 8a 54 32 ff 80 e2 0f 32 c2 88 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8a 54 1a ff 80 e2 f0 8a 4d ?? 02 d1 88 54 18 ff 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_O_2147597444_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!O"
        threat_id = "2147597444"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WriteProcessMemory" ascii //weight: 1
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
        $x_1_3 = "SetThreadContext" ascii //weight: 1
        $x_1_4 = "ResumeThread" ascii //weight: 1
        $x_1_5 = "ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "GetThreadContext" ascii //weight: 1
        $x_1_7 = "SetFilePointer" ascii //weight: 1
        $x_1_8 = "GetFileSize" ascii //weight: 1
        $x_1_9 = "CreateProcessA" ascii //weight: 1
        $x_1_10 = "ReadFile" ascii //weight: 1
        $x_1_11 = {6a 00 6a 00 68 ?? ?? 00 00 53 e8 ?? ?? ?? ?? 6a 00 53 e8 ?? ?? ?? ?? (8b f0|89 c6) 81 ee ?? ?? 00 00 8d 45 fc (8b d6|89 f2) e8 ?? ?? ?? ?? 6a 00 8d 45 f4 50 56 8d 45 fc e8 ?? ?? ?? ?? 50 53 e8}  //weight: 1, accuracy: Low
        $x_1_12 = {89 c3 83 fb ff 0f 84 ?? ?? 00 00 6a 00 53 e8 ?? ?? ?? ?? 89 c6 81 ee 00 5e 00 00 6a 00 6a 00 68 00 5e 00 00 53 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule VirTool_Win32_DelfInject_Q_2147597445_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!Q"
        threat_id = "2147597445"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RtlDecompressBuffer" ascii //weight: 1
        $x_1_2 = {4d 44 41 54 41 31 00 00 4d 44 41 54 41 32}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 fc 8a 44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 4a e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 dc}  //weight: 1, accuracy: Low
        $x_1_4 = {44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 80 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 da 04 00 8b 45 fc (8a|8b)}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b (85 ?? ??|45 ??) 50 (ff|e8)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_DelfInject_U_2147597622_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!U"
        threat_id = "2147597622"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "GetCurrentThreadId" ascii //weight: 10
        $x_10_2 = "TerminateProcess" ascii //weight: 10
        $x_10_3 = "VirtualProtectEx" ascii //weight: 10
        $x_1_4 = {8b 45 fc 8b 55 f4 8a 44 10 ff 88 45 f3 8d 45 e8 8a 55 f3 80 ea ?? e8 ?? ?? ?? ?? 8b 55 e8 8b 45 f8 e8 ?? ?? ?? ?? 8b 45 f8 ff 45 f4 ff 4d ec 75 cf}  //weight: 1, accuracy: Low
        $x_1_5 = {44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 80 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 da 04 00 8b 45 fc (8a|8b)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_2147597831_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject"
        threat_id = "2147597831"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 06 40 00 00 68 99 99 99 c5 68 9a 99 99 99 68 16 89 53 40 68 0c 02 2b 87 68 5c c7 6b 40 68 8f c2 f5 28 68 a9 c9 57 40 68 8b 6c e7 fb 68 3d ea 6c 40 68 0a d7 a3 70 68 c0 0a 5c 40 68 98 6e 12 83 33 d2 33 c0 e8 1e 02 00 00 e9 72 ff ff ff e9 d4 fd ff ff f8 fc 42 66 c1 c7 b0 0b db f5 e9 c5 fd ff ff 33 c0 5a 59 59 64 89 10 68 d1 29 40 00 8d 45 f4 ba 03 00 00 00 e8 33 eb ff ff c3 e9 d9 e8 ff ff eb eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_V_2147598208_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!V"
        threat_id = "2147598208"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 ff 30 64 89 20 52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b 59 5a 33 c0 5a 59 59 64 89 10}  //weight: 10, accuracy: High
        $x_10_2 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b 36 8b 04 24 64 89 05 00 00 00 00 83 c4 08 85 db 0f 94 c0 36 8d 65 fc 36 8b 1c 24 36 8b 6c 24 04 83 c4 08 c3 8b 4c 24 0c c7 81 a4 00 00 00 ff ff ff ff 83 81}  //weight: 10, accuracy: High
        $x_10_3 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b (85 ?? ??|45 ??) 50 (ff|e8)}  //weight: 10, accuracy: Low
        $x_1_4 = {8b 45 fc 33 db 8a 5c 38 ff 33 5d f8 8d 45 ec 8b d3 e8 ?? ?? ?? ?? 8b 55 ec 8d 45 f0 e8 ?? ?? ?? ?? 47 4e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_W_2147598209_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!W"
        threat_id = "2147598209"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 45 54 00 ff ff ff ff 02 00 00 00 43 46 00}  //weight: 10, accuracy: High
        $x_1_2 = {8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 0f b6 54 32 ff (33|32) d3 88 54 30 ff 43 46 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_K_2147598460_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!K"
        threat_id = "2147598460"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "FindResourceA" ascii //weight: 10
        $x_10_2 = "LoadResource" ascii //weight: 10
        $x_10_3 = "RtlDecompressBuffer" ascii //weight: 10
        $x_2_4 = {8b 45 fc 8b 55 f4 8a 44 10 ff 88 45 f3 8d 45 e8 8a 55 f3 80 ea ?? e8 ?? ?? ?? ?? 8b 55 e8 8b 45 f8 e8 ?? ?? ?? ?? 8b 45 f8 ff 45 f4 ff 4d ec 75 cf}  //weight: 2, accuracy: Low
        $x_2_5 = {44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 80 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 da 04 00 8b 45 fc (8a|8b)}  //weight: 2, accuracy: Low
        $x_1_6 = {8b c3 99 03 45 e0 13 55 e4 33 04 24 33 54 24 04 83 c4 08 5a 88 02 43 46 4f 75}  //weight: 1, accuracy: High
        $x_1_7 = {53 54 52 00 ff ff ff ff 01 00 00 00 5c 00 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_8 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b (85 ?? ??|45 ??) 50 (ff|e8)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_L_2147598461_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!L"
        threat_id = "2147598461"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "FindResourceA" ascii //weight: 10
        $x_10_2 = "LoadResource" ascii //weight: 10
        $x_10_3 = "CreateProcessA" ascii //weight: 10
        $x_10_4 = "WriteProcessMemory" ascii //weight: 10
        $x_1_5 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 ?? 8a 54 32 ff 80 e2 0f 32 c2 88 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8a 54 1a ff 80 e2 f0 8a 4d ?? 02 d1 88 54 18 ff 46}  //weight: 1, accuracy: Low
        $x_1_6 = {8b f8 8b f2 4e 85 f6 7c 1b 46 33 db a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 d2 8a 14 1f 33 c2 88 04 1f 43 4e 75 e8}  //weight: 1, accuracy: Low
        $x_1_7 = {eb 09 49 c0 04 39 ?? 80 34 39 ?? 0b c9 75 f3}  //weight: 1, accuracy: Low
        $x_1_8 = {8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 0f b6 54 32 ff 33 d3 88 54 30 ff 43 46 4f 75}  //weight: 1, accuracy: Low
        $n_1_9 = "Please visit www.vaysoft.com to get more detail" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_X_2147598557_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!X"
        threat_id = "2147598557"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = "Exun" ascii //weight: -100
        $n_100_2 = "Steuern 20" ascii //weight: -100
        $n_100_3 = ".smsactivator.com/" ascii //weight: -100
        $n_100_4 = "SkinSharp GUI Toolkit" wide //weight: -100
        $n_100_5 = "tica Sistemas Inteligentes" wide //weight: -100
        $n_100_6 = "This program is maDe by dtcser.thank" ascii //weight: -100
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "VirtualAllocEx" ascii //weight: 1
        $x_1_9 = "SizeofResource" ascii //weight: 1
        $x_1_10 = "SetThreadContext" ascii //weight: 1
        $x_1_11 = "ResumeThread" ascii //weight: 1
        $x_1_12 = "ReadProcessMemory" ascii //weight: 1
        $x_1_13 = "LockResource" ascii //weight: 1
        $x_1_14 = "LoadResource" ascii //weight: 1
        $x_1_15 = "GetThreadContext" ascii //weight: 1
        $x_1_16 = "GetModuleHandleA" ascii //weight: 1
        $x_1_17 = "FindResourceA" ascii //weight: 1
        $x_1_18 = "CreateProcessA" ascii //weight: 1
        $x_1_19 = {eb 47 6a 00 a1 ?? ?? ?? ?? 8b 40 04 33 c9 b2 01 e8 21 fe ff ff 84 c0 75 07 e8 c4 c6 ff ff eb 29}  //weight: 1, accuracy: Low
        $x_2_20 = {02 14 18 81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75}  //weight: 2, accuracy: High
        $x_5_21 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b (85 ?? ??|45 ??) 50 (ff|e8)}  //weight: 5, accuracy: Low
        $x_5_22 = {6a 04 68 00 30 00 00 8b 45 ?? 8b 40 50 50 8b 45 ?? 8b 40 34 50 8b (45 ??|85 ?? ??) 50 (ff|e8)}  //weight: 5, accuracy: Low
        $x_5_23 = {6a 28 8b 45 ?? 33 d2 52 50 8b ?? c1 e0 03 8d 04 80 99 03 04 24 13 54 24 04 83 c4 08 8b 55 ?? 8d 04 02 50}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((13 of ($x_1_*))) or
            ((1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_S_2147598597_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!S"
        threat_id = "2147598597"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RtlDecompressBuffer" ascii //weight: 1
        $x_1_2 = "SizeofResource" ascii //weight: 1
        $x_1_3 = "LockResource" ascii //weight: 1
        $x_1_4 = "LoadResource" ascii //weight: 1
        $x_1_5 = "FreeResource" ascii //weight: 1
        $x_1_6 = "FindResourceA" ascii //weight: 1
        $x_4_7 = "\\\\.\\NTICE" ascii //weight: 4
        $x_2_8 = "DAEMON" ascii //weight: 2
        $x_10_9 = {8d 44 30 ff 50 8b 45 fc 8a 44 30 ff 25 ff 00 00 00 33 d2 52 50 8b c3 99 03 45 e0 13 55 e4 33 04 24 33 54 24 04 83 c4 08 5a 88 02 43 46 4f 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_Z_2147599229_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!Z"
        threat_id = "2147599229"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WriteProcessMemory" ascii //weight: 1
        $x_1_2 = "ResumeThread" ascii //weight: 1
        $x_1_3 = "SetThreadContext" ascii //weight: 1
        $x_3_4 = "Undetector 1.1" ascii //weight: 3
        $x_5_5 = {8a 04 1f 24 0f 8b 55 ?? 8a 14 32 80 e2 0f 32 c2 8a 14 1f 80 e2 f0 02 d0 88 14 1f 46 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 3b f0 7e 05 be 01 00 00 00 43 ff 4d ?? 75 c2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AA_2147599272_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AA"
        threat_id = "2147599272"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 08 81 f9 ff 00 00 00 75 07 b9 01 00 00 00 eb 01 41 40 90 01 01 75 ea}  //weight: 1, accuracy: High
        $x_1_2 = {30 10 81 fa ff 00 00 00 75 07 ba 01 00 00 00 eb 01 42 40 90 01 01 75 ea}  //weight: 1, accuracy: High
        $x_1_3 = {30 18 81 fb ff 00 00 00 75 07 bb 01 00 00 00 eb 01 43 40 90 01 01 75 ea}  //weight: 1, accuracy: High
        $x_2_4 = {0f 01 4d fa 8a 45 ff 2c e8 74 04 2c 17 75 06 c6 45 f9 01 eb 04 c6 45 f9 00 8a 45 f9}  //weight: 2, accuracy: High
        $x_1_5 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b (85 ?? ??|45 ??) 50 (ff|e8)}  //weight: 1, accuracy: Low
        $x_5_6 = {8d 45 f8 8a 13 80 f2 ?? [0-3] 81 e2 ff 00 00 00 33 d6 e8 ?? ?? ?? ?? 8b 55 f8 8b 45 fc e8 ?? ?? ?? ?? 8b 45 fc 81 fe ff 00 00 00 75 07 be 01 00 00 00 eb 01 46 43 4f 75}  //weight: 5, accuracy: Low
        $x_5_7 = {8d 45 f4 8b 55 fc 8b 4d f8 0f b6 54 0a ff 33 d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8}  //weight: 5, accuracy: Low
        $x_5_8 = {8d 45 ec 8b 55 fc 8b 4d f4 0f b6 54 0a ff 33 d3 e8 ?? ?? ?? ?? 8b 55 ec 8b 45 f8 e8}  //weight: 5, accuracy: Low
        $x_5_9 = {8b 55 f4 8b 4d fc 8b 5d f4 0f b6 4c 19 ff 33 4d f0 88 4c 10 ff ff 45 f0 ff 45 f4 ff 4d ec 75}  //weight: 5, accuracy: High
        $x_5_10 = {8b 55 f0 8b 4d fc 8b 5d f0 0f b6 4c 19 ff 33 4d ec 88 4c 10 ff [0-4] ff 45 ec ff 45 f0 ff 4d e8 75}  //weight: 5, accuracy: Low
        $x_5_11 = {8b 45 f8 8b 55 f0 8a 04 10 33 d2 8a 55 ef 8b 4d fc 32 04 11 8b 55 f4 8b 4d f0 88 04 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AB_2147599273_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AB"
        threat_id = "2147599273"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 34 1f 32 8b c6 34 01 32 04 1f 34 00 34 01 34 32 88 04 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AC_2147599318_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AC"
        threat_id = "2147599318"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 35 32 37 34 2d 36 34 30 2d 32 36 37 33 30 36 34 2d 32 33 39 35 30 00}  //weight: 1, accuracy: High
        $x_1_2 = {37 36 34 38 37 2d 36 34 34 2d 33 31 37 37 30 33 37 2d 32 33 35 31 30 00}  //weight: 1, accuracy: High
        $x_1_3 = {37 36 34 38 37 2d 33 33 37 2d 38 34 32 39 39 35 35 2d 32 32 36 31 34 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 44 41 54 41 31 00 00 4d 44 41 54 41 32}  //weight: 1, accuracy: High
        $x_1_5 = {40 8a 84 85 ?? ?? ff ff 8b 55 ?? 30 04 3a 47 4b 0f 85}  //weight: 1, accuracy: Low
        $x_1_6 = {80 fb 01 74 15 8d 45 ?? 8b d3 e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? [0-4] 47 8a 1c 3e 84 db 75}  //weight: 1, accuracy: Low
        $x_1_7 = {25 ff 00 00 00 33 d2 52 50 8b c6 99 03 45 ?? 13 55 ?? 33 04 24 33 54 24 04 83 c4 08 5a 88 02 46 43 4f 75}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 55 f8 8b 4d fc 8b 09 8b 5d f8 0f b6 4c 19 ff 33 4d f4 88 4c 10 ff 83 7d f4 0f 75 09 c7 45 f4}  //weight: 1, accuracy: High
        $x_1_9 = {8b 45 fc 8b 00 8b 55 f8 0f b6 44 10 ff 89 45 e8 [0-12] 83 75 e8 (0a|0c) [0-12] 8b 45 fc e8 ?? ?? ?? ?? 8b 55 f8 8b 4d e8 33 4d f4 88 4c 10 ff}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 55 f8 8b 4d fc 8b 09 8b 5d f8 8a 4c 19 ff 80 f1 0a 80 f1 01 88 4c 10 ff}  //weight: 1, accuracy: High
        $x_1_11 = {8b 55 f4 8b 4d fc 8b 5d f4 0f b6 4c 19 ff 33 4d f0 88 4c 10 ff 83 7d f0 14 75 07}  //weight: 1, accuracy: High
        $x_1_12 = {8a 04 1f 24 0f 8b 55 ?? 8a 14 32 80 e2 0f 32 c2 8a 14 1f 80 e2 f0 02 d0 88 14 1f 46 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 3b f0 7e 05 be 01 00 00 00 43 ff 4d ?? 75 c2}  //weight: 1, accuracy: Low
        $x_1_13 = {02 14 18 81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75}  //weight: 1, accuracy: High
        $x_1_14 = {02 14 18 0f b6 d2 0f b6 14 10 32 16 88 11 41 46 ff 4d fc 75}  //weight: 1, accuracy: High
        $x_1_15 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 ?? 8a (54|14 32) 80 e2 0f 32 c2 88 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8a 54 1a ff 80 e2 f0 8a 4d ?? 02 d1 88 54 18 ff 46}  //weight: 1, accuracy: Low
        $x_1_16 = {8b 45 f8 8b 55 f0 8a 04 10 33 d2 8a 55 ef 8b 4d fc 32 04 11 8b 55 f4 8b 4d f0 88 04 0a}  //weight: 1, accuracy: High
        $x_1_17 = {8b 55 08 03 55 fc 0f be 02 (83 f0 ??|35 ?? 00) [0-6] 8b 4d 08 03 4d fc 88 01 eb}  //weight: 1, accuracy: Low
        $x_1_18 = {8b 4d 08 03 4d fc 0f be 11 (83 f2 ??|81 ?? ?? 00) [0-7] 8b 45 08 03 45 fc 88 10}  //weight: 1, accuracy: Low
        $x_1_19 = {8b 45 fc 8b 55 f4 8a 44 10 ff 88 45 f3 8d 45 e8 8a 55 f3 80 ea ?? e8 ?? ?? ?? ?? 8b 55 e8 8b 45 f8 e8 ?? ?? ?? ?? 8b 45 f8 ff 45 f4 ff 4d ec 75 cf}  //weight: 1, accuracy: Low
        $x_1_20 = {8b 07 8a 44 18 ff 34 ?? 34 ?? 8b f0 81 e6 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_21 = {8b 07 8a 5c 30 ff 80 f3 ?? 80 f3 ?? 81 e3 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_22 = {67 64 69 33 32 2e 64 6c 6c 00 00 00 53 65 74 54 65 78 74 43 6f 6c 6f 72 00 00 00 00 47 65 74 54 65 78 74 43 6f 6c 6f 72 00 00 75 73 65 72 33 32 2e 64 6c 6c 00 00 00 00 47 65 74 44 43 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_23 = {44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 80 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 da 04 00 8b 45 fc (8a|8b)}  //weight: 1, accuracy: Low
        $x_1_24 = {33 db 8d 45 ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 33 d2 8a 14 1f 33 c2 88 04 1f 43 4e 75 dc}  //weight: 1, accuracy: Low
        $x_1_25 = {8b c3 48 99 f7 7d ?? 8b 45 ?? 8a 04 10 88 45 ?? 8a 44 1e ff 3c 80 72 0d 8a 55 ?? 80 e2 7f 32 c2 88 45 ?? eb ?? 3c 40 72 ?? 8a 55 ?? 80 e2 3f 32 c2}  //weight: 1, accuracy: Low
        $x_100_26 = {6a 04 68 00 30 00 00 a1 ?? ?? ?? ?? 8b 40 50 50 a1 ?? ?? ?? ?? 8b 40 34 50 a1 ?? ?? ?? ?? 50 (ff|e8)}  //weight: 100, accuracy: Low
        $x_100_27 = {6a 04 68 00 30 00 00 8b 45 ?? 8b 40 50 50 8b 45 ?? 8b 40 34 50 8b (45 ??|85 ?? ??) 50 [0-7] (ff|e8)}  //weight: 100, accuracy: Low
        $x_100_28 = {6a 40 68 00 30 00 00 8b 45 ?? 8b 40 50 50 8b 45 ?? 8b 40 34 50 8b (45 ??|85 ?? ??) 50 [0-7] (ff|e8)}  //weight: 100, accuracy: Low
        $x_100_29 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b (85 ?? ??|45 ??) 50 (ff|e8)}  //weight: 100, accuracy: Low
        $x_100_30 = {6a 04 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b (45 ??|85 ?? ??) 50 a1 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 100, accuracy: Low
        $x_100_31 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b (45 ??|85 ?? ??) 50 a1 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 100, accuracy: Low
        $x_100_32 = {8b 40 34 89 45 ?? 8b 45 ?? 8b 40 50 89 45 ?? 6a 04 68 00 30 00 00}  //weight: 100, accuracy: Low
        $x_100_33 = {6a 04 68 00 30 00 00 8b (45|5d|4d|55) ?? 8b (43|41|42|58|59|5a|48|4b|4a|50|53|51) 50 (50|53|51|52) 8b (45|5d|4d|55) ?? 8b (43|41|42|58|59|5a|48|4b|4a|50|53|51) 34 (50|53|51|52) 8b (45|5d|4d|55) ?? (50|53|51|52) ff}  //weight: 100, accuracy: Low
        $x_100_34 = {8b 40 50 89 45 ?? 8b 45 ?? 8b 40 34 89 45 ?? 6a 04 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 50 8b 45 ?? 50}  //weight: 100, accuracy: Low
        $x_100_35 = {6a 04 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b 85 ?? ?? ff ff 50 ff}  //weight: 100, accuracy: Low
        $x_100_36 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 43 34 50 8b 45 ?? 50 ff}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AE_2147599539_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AE"
        threat_id = "2147599539"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CurrentUser" ascii //weight: 1
        $x_1_2 = "OLLYDBG" ascii //weight: 1
        $x_2_3 = "icu_dbg" ascii //weight: 2
        $x_1_4 = "OwlWindow" ascii //weight: 1
        $x_1_5 = "OWL_Window" ascii //weight: 1
        $x_1_6 = "TWelcomeForm" ascii //weight: 1
        $x_2_7 = "drivers\\vmxnet.sys" ascii //weight: 2
        $x_5_8 = {64 ff 30 64 89 20 52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b 59 5a 33 c0 5a 59 59 64 89 10}  //weight: 5, accuracy: High
        $x_5_9 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b 36 8b 04 24 64 89 05 00 00 00 00 83 c4 08 85 db 0f 94 c0 36 8d 65 fc 36 8b 1c 24 36 8b 6c 24 04 83 c4 08 c3 8b 4c 24 0c c7 81 a4 00 00 00 ff ff ff ff 83 81}  //weight: 5, accuracy: High
        $x_5_10 = {8b 45 fc 33 db 8a 5c 38 ff 33 5d f8 8d 45 ec 8b d3 e8 ?? ?? ?? ?? 8b 55 ec 8d 45 f0 e8 ?? ?? ?? ?? 47 4e 75}  //weight: 5, accuracy: Low
        $x_5_11 = {44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 80 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 da 04 00 8b 45 fc (8a|8b)}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AF_2147600449_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AF"
        threat_id = "2147600449"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {73 00 79 00 73 00 6b 00 65 00 79 00 2e 00 65 00 78 00 65 00 00 00 00 00 10 00 00 00 61 00 6e 00 73 00 69 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 50 61 72 61 6c 6c 65 6c 73 5c 50 61 72 61 6c 6c 65 6c 73 20 54 6f 6f 6c 73 00}  //weight: 3, accuracy: High
        $x_2_3 = "SbieDll.dll" ascii //weight: 2
        $x_1_4 = "SizeofResource" ascii //weight: 1
        $x_1_5 = "LockResource" ascii //weight: 1
        $x_1_6 = "LoadResource" ascii //weight: 1
        $x_1_7 = "FindResourceA" ascii //weight: 1
        $x_1_8 = "FreeResource" ascii //weight: 1
        $x_5_9 = {53 45 54 00 ff ff ff ff 02 00 00 00 43 46 00}  //weight: 5, accuracy: High
        $x_3_10 = {89 45 ec c7 45 f4 01 00 00 00 8b 45 fc 8b 55 f4 8a 44 10 ff}  //weight: 3, accuracy: High
        $x_5_11 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b 36 8b 04 24 64 89 05 00 00 00 00 83 c4 08 85 db 0f 94 c0 36 8d 65 fc 36 8b 1c 24 36 8b 6c 24 04 83 c4 08 c3 8b 4c 24 0c c7 81 a4 00 00 00 ff ff ff ff 83 81}  //weight: 5, accuracy: High
        $x_5_12 = {0f 01 4d fa 81 7d fc 00 00 00 f0 7e 0b 81 7d fc 00 00 00 ff 7f 11 eb 15 81 7d fc 00 00 00 d0 7e 0c c6 45 f9 01 eb 0a c6 45 f9 02 eb 04 c6 45 f9 00}  //weight: 5, accuracy: High
        $x_5_13 = {3c ff 74 04 3c e8 75 0b 0c 00 0f 01 0d ?? ?? ?? ?? a0}  //weight: 5, accuracy: Low
        $x_5_14 = {81 e2 ff 00 00 00 8a 54 10 01 32 16 81 e2 ff 00 00 00 88 11 41 46 ff 4d fc 75}  //weight: 5, accuracy: High
        $x_5_15 = {02 14 18 81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75}  //weight: 5, accuracy: High
        $x_5_16 = {8b 45 fc 8a 44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 4a e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 dc}  //weight: 5, accuracy: Low
        $x_5_17 = {e4 bb 01 00 00 00 8b 45 f8 0f b6 44 18 ff 99 f7 fb 33 f2 43 ff 4d ?? 75 ed 81 fe ff 00 00 00 7e}  //weight: 5, accuracy: Low
        $x_5_18 = {32 c1 8b 4d f8 8b 7d e4 0f b6 4c 39 ff 03 c9 c1 e9 02 32 c1 32 d0 88 55 ef}  //weight: 5, accuracy: High
        $x_5_19 = {8b 00 ff d0 85 c0 74 28 8d 45 e4 50 8b 44 fe 24 e8 ?? ?? ?? ?? 50 8b 44 fe 08 50 8b 44 fe 0c 03 45 f0 50 8b 45 c8 50 a1 ?? ?? ?? ?? 8b 00 ff d0 43 ff 4d d8 75 a5}  //weight: 5, accuracy: Low
        $x_7_20 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8b 45 ?? e8 ?? ?? ?? ?? 50 8b 45 ?? e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 7, accuracy: Low
        $x_5_21 = {0f 01 4d fa 8a 45 ff 2c e8 74 04 2c 17 75 04 b0 01 eb 02 33 c0}  //weight: 5, accuracy: High
        $x_5_22 = {0f 01 4d fa [0-4] 8a 45 ff 3c ff 75 ?? [0-16] 3c e8 75}  //weight: 5, accuracy: Low
        $x_5_23 = {6a 00 6a 00 6a 00 68 (ff ff|e0 ee) e8 ?? ?? ?? ?? 85 c0 (74|75)}  //weight: 5, accuracy: Low
        $x_5_24 = {3c 01 74 24 80 3d ?? ?? ?? ?? ff 74 1b 80 3d ?? ?? ?? ?? e8 74 12 e8 ?? ?? ?? ?? 3c 01 74 09}  //weight: 5, accuracy: Low
        $x_5_25 = {8b d8 68 f4 01 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 2b c3 3d f4 01 00 00 73}  //weight: 5, accuracy: Low
        $x_5_26 = {32 44 11 01 25 ff 00 00 00 89 45 ?? 8b 45 ?? 8b 55 ?? 8a 4d ?? 88 0c 10 ff 45 ?? ff 4d ?? 0f 85}  //weight: 5, accuracy: Low
        $n_15_27 = "Softplan\\Componentes\\MRU" ascii //weight: -15
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_7_*) and 3 of ($x_3_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_7_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AG_2147600586_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AG"
        threat_id = "2147600586"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CurrentUser" ascii //weight: 1
        $x_1_2 = {8d 45 fc 50 56 e8 ?? ?? ?? ?? 8d 45 f8 8b d6 e8 ?? ?? ?? ?? 8b 45 f8 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 02 b3 01}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 ?? 8a 54 32 ff 80 e2 0f 32 c2 88 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8a 54 1a ff 80 e2 f0 8a 4d ?? 02 d1 88 54 18 ff 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_H_2147601129_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!H"
        threat_id = "2147601129"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WriteProcessMemory" ascii //weight: 1
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
        $x_1_3 = "SizeofResource" ascii //weight: 1
        $x_1_4 = "SetThreadContext" ascii //weight: 1
        $x_1_5 = "ResumeThread" ascii //weight: 1
        $x_1_6 = "ReadProcessMemory" ascii //weight: 1
        $x_1_7 = "LockResource" ascii //weight: 1
        $x_1_8 = "LoadResource" ascii //weight: 1
        $x_1_9 = "GetThreadContext" ascii //weight: 1
        $x_1_10 = "GetModuleHandleA" ascii //weight: 1
        $x_1_11 = "FindResourceA" ascii //weight: 1
        $x_1_12 = "CreateProcessA" ascii //weight: 1
        $x_1_13 = {52 43 5f 44 41 54 41 00 4e 45 4f 4b 55 52 44 00}  //weight: 1, accuracy: Low
        $x_1_14 = "RtlDecompressBuffer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AH_2147602775_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AH"
        threat_id = "2147602775"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_2 = "RtlDecompressBuffer" ascii //weight: 1
        $x_1_3 = {06 00 00 00 53 45 52 56 45 52}  //weight: 1, accuracy: High
        $x_1_4 = {89 45 ec c7 45 f4 01 00 00 00 8b 45 fc 8b 55 f4 8a 44 10 ff}  //weight: 1, accuracy: High
        $x_5_5 = {6a 04 68 00 30 00 00 8b 45 ?? 8b 40 50 50 8b 45 ?? 8b 40 34 50 8b (45 ??|85 ?? ??) 50 (ff|e8)}  //weight: 5, accuracy: Low
        $x_5_6 = {6a 04 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b (45 ??|85 ?? ??) 50 a1 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 5, accuracy: Low
        $x_5_7 = {8b 40 34 89 45 ?? 8b 45 ?? 8b 40 50 89 45 ?? 6a 04 68 00 30 00 00}  //weight: 5, accuracy: Low
        $x_5_8 = {8b f8 8b f2 4e 85 f6 7c 1b 46 33 db a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 d2 8a 14 1f 33 c2 88 04 1f 43 4e 75 e8}  //weight: 5, accuracy: Low
        $x_5_9 = {0f 01 4d fa 81 7d fc 00 00 00 f0 7e 0b 81 7d fc 00 00 00 ff 7f 11 eb 15 81 7d fc 00 00 00 d0 7e 0c c6 45 f9 01 eb 0a c6 45 f9 02 eb 04 c6 45 f9 00}  //weight: 5, accuracy: High
        $x_5_10 = {81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75}  //weight: 5, accuracy: High
        $x_5_11 = {8b 45 f8 8b 55 f0 8a 04 10 33 d2 8a 55 ef 8b 4d fc 32 04 11 8b 55 f4 8b 4d f0 88 04 0a}  //weight: 5, accuracy: High
        $n_100_12 = "\\FIBC_Software\\" ascii //weight: -100
        $n_100_13 = "\\wPDF\\Source\\WPGenDC.pas" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AI_2147605392_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AI"
        threat_id = "2147605392"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lld.23lenrek" ascii //weight: 1
        $x_1_2 = "AemaNeliFeludoMteG" ascii //weight: 1
        $x_1_3 = "ecruoseRfoeziS" ascii //weight: 1
        $x_1_4 = "AecruoseRdniF" ascii //weight: 1
        $x_1_5 = "ecruoseRdaoL" ascii //weight: 1
        $x_1_6 = "ecruoseRkcoL" ascii //weight: 1
        $x_1_7 = "ecruoseReerF" ascii //weight: 1
        $x_1_8 = "1atad" ascii //weight: 1
        $x_1_9 = "startsteal" ascii //weight: 1
        $x_1_10 = "laetstrats" ascii //weight: 1
        $x_1_11 = "PBDATA" wide //weight: 1
        $x_1_12 = "DATA1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule VirTool_Win32_DelfInject_AJ_2147605421_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AJ"
        threat_id = "2147605421"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 ff d0 85 c0 74 28 8d 45 e4 50 8b 44 fe 24 e8 ?? ?? ?? ?? 50 8b 44 fe 08 50 8b 44 fe 0c 03 45 f0 50 8b 45 c8 50 a1 ?? ?? ?? ?? 8b 00 ff d0 43 ff 4d d8 75 a5}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc e8 ?? ?? ?? ?? 50 8b c3 5a 8b ca 99 f7 f9 8b 45 fc 8a 04 10 88 06 43 46 81 fb 00 01 00 00 75 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AJ_2147605854_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.AJ"
        threat_id = "2147605854"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Portions Copyright (c) 1999,2003 Avenger by NhT" ascii //weight: 1
        $x_1_2 = "newcrypt" ascii //weight: 1
        $x_1_3 = "WormUnhook" ascii //weight: 1
        $x_1_4 = "\\ntoskrnl.exe" ascii //weight: 1
        $x_1_5 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_6 = {89 45 fc 68 03 01 00 00 8b 45 fc 50 e8 ?? ?? ff ff 6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 90 ef ff ff 8b 55 fc e8 ?? ?? ff ff 8d 85 90 ef ff ff ba ?? ?? 00 10 e8 ?? ?? ff ff 8b 85 90 ef ff ff e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 8b d8 6a 00 6a 00 6a 00 53 e8 ?? ?? ff ff 6a 00 53 e8 ?? ?? ff ff 8b f0 8b c6 e8 ?? ?? ff ff 89 45 f4 6a 00 8d 45 f0 50 56 8b 7d f4 57 53}  //weight: 1, accuracy: Low
        $x_1_7 = {8b d8 4b 85 db 7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43}  //weight: 1, accuracy: High
        $x_1_8 = {8b 37 03 75 f8 68 ?? ?? 00 10 56 e8 ?? ?? ff ff 85 c0 75 1b 8b 45 e8 8b 40 1c 8b 55 e0 0f b7 12 c1 e2 02 03 c2 03 45 f8 8b 00 89 45 d0 eb 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AK_2147606198_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.AK"
        threat_id = "2147606198"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 ec 50 6a 01 8d 45 df 50 8b 45 e0 03 c0 03 45 98 50 8b 45 c0 50 ff 15 ?? ?? ?? ?? 39 ?? 39 ?? 39 ?? c7 85 f4 fe ff ff 07 00 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 43 34 50 8b 45 ?? 50 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AL_2147607575_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AL"
        threat_id = "2147607575"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 00 6a ff ff 15 ?? ?? ?? ?? 85 c0 74 08 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {66 b9 ff ff eb 06 66 b8 00 4c cd 21 e2 f6}  //weight: 2, accuracy: High
        $x_2_3 = {83 c0 01 89 45 ?? 33 c9 8a 0d ?? ?? ?? ?? 85 c9 74 eb 81 7d ?? 00 e1 f5 05 7d 08 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_4 = {81 e2 ff 00 00 00 81 fa e9 00 00 00 75 08 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AK_2147607931_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AK"
        threat_id = "2147607931"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 2e 97 58 4f e8 ?? ?? ?? ff a3 ?? ?? ?? ?? 8d 45 e8 50 6a 04 8d 45 e4 50 8b 45 b8 83 c0 08 50 8b 45 f8 50 ff 15 ?? ?? ?? ?? 8b 45 e4 89 43 34 8d 45 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AM_2147608687_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AM"
        threat_id = "2147608687"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 43 34 50 8b 45 ?? 50 ff}  //weight: 10, accuracy: Low
        $x_1_2 = {83 f8 02 74 05 83 f8 01 75 04 8a 0a 02 d9 40 42 3d ?? ?? 00 00 75 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AN_2147608880_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AN"
        threat_id = "2147608880"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 43 34 8d 45 e8 50 56 8b 45 10 50 8b 45 e4 50 8b 45 f8 50 e8 ?? ?? ?? ff 85 c0 74 47 c7 85 ?? ff ff ff 07 00 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 14 24 8b e8 33 db 68 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b f8 85 ff 74 23 68 ?? ?? ?? ?? 57 e8 ?? ?? ?? ff 8b f0 85 f6 74 0c 8b 04 24 50 55 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AP_2147610411_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AP"
        threat_id = "2147610411"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 9d bb ca aa bf b9 c1 99 c5 cb c4 ca 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {00 a9 c2 bb bb c6 00 00}  //weight: 5, accuracy: High
        $x_5_3 = {00 af c1 d0 b0 c4 ce c1 bd c0 9f cb ca d0 c1 d4 d0 00 00}  //weight: 5, accuracy: High
        $x_5_4 = {0f 31 8b c8 0f 31 2b c8 f7 d1 81 f9 00 00 01 00 7f}  //weight: 5, accuracy: High
        $x_5_5 = {00 00 89 45 e4 c7 45 f0 01 00 00 00 8b 45 fc 8b 55 f0 0f b6 44 10 ff 89 45 ec}  //weight: 5, accuracy: High
        $x_5_6 = {8d 45 e8 8a 55 ec 80 ea}  //weight: 5, accuracy: High
        $x_5_7 = {ff ff 8b 45 f8 ff 30 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 75 e8 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 8b 45 f8 ba 0e 00 00 00 e8 ?? ?? ?? ff 8b 45 f8 ff 30 6a 00 6a 00 6a 00 6a 00 6a 00 8b 45 f8 ba 06 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_DelfInject_AQ_2147616453_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AQ"
        threat_id = "2147616453"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 28 6d 01 00 e8 ?? ?? ff ff 84 c0 0f 84 ca 17 00 00 83 3d ac 8b 01 00 00 0f 84 88 17 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AS_2147623761_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AS"
        threat_id = "2147623761"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 26 8b 45 e0 8b 40 28 03 45 f0}  //weight: 1, accuracy: High
        $x_1_2 = {b8 68 58 4d 56 bb 12 f7 6c 3c b9 0a 00 00 00 66 ba 58 56 ed}  //weight: 1, accuracy: High
        $x_1_3 = {0f 3f 07 0b 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AT_2147624038_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AT"
        threat_id = "2147624038"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 84 70 02 00 00 55 68 86 45 40 00 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 8b cb 66 81 39 4d 5a 74 0a}  //weight: 1, accuracy: High
        $x_1_2 = {b8 10 69 40 00 e8 90 d5 ff ff 33 c0 a3 d0 a6 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AU_2147625858_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AU"
        threat_id = "2147625858"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 85 c0 74 31 8b 45 ?? 8b 50 28 8b 45 ?? e8 ?? ?? ff ff 89 85 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {32 c1 8b 4d f8 8b 7d e4 0f b6 4c 39 ff 03 c9 c1 e9 02 32 c1 32 d0 88 55 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AV_2147626089_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AV"
        threat_id = "2147626089"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 ff 2a 08 88 08 40 4a 75 f6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 52 14 03 c2 89 45 e8 8b 45 fc 0f b7 78 06 4f 85 ff 7c 6e}  //weight: 1, accuracy: High
        $x_1_3 = {69 70 74 6f 72 54 00 04 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AW_2147626494_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AW"
        threat_id = "2147626494"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 61 63 6b 65 64 20 77 69 74 68 20 62 6f 74 43 72 79 70 74 65 72 20 76 [0-16] 20 62 79 20 53 57 69 4d 00}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 04 68 00 30 00 00 8b 45 ?? 8b 40 50 50 8b 45 ?? 8b 40 34 50 8b 45 ?? 50 a1 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 2, accuracy: Low
        $x_1_3 = {0f b7 40 06 2b c7 2b c6 72 ?? 40 89 45 d8 8d 45 ec 50 8d 3c b6 8b 45 e0 8b 44 f8 10}  //weight: 1, accuracy: Low
        $x_1_4 = {e4 bb 01 00 00 00 8b 45 f8 0f b6 44 18 ff 99 f7 fb 33 f2 43 ff 4d ?? 75 ed 81 fe ff 00 00 00 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AX_2147627658_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AX"
        threat_id = "2147627658"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c e8 0f 84 ?? ?? 00 00 e8 ?? ?? ff ff 3c ff 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {32 c1 8b 4d f8 8b 7d ?? 0f b6 4c 39 ff 03 c9 c1 e9 02 32 c1 32 d0 88 55 ef}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 45 e4 8b 50 28 8b 45 f4 03 d0 8b c2 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AY_2147628542_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AY"
        threat_id = "2147628542"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {6a 04 68 00 30 00 00 8b 45 ?? 8b 40 ec 8b 40 50 50 8b 45 ?? 8b 40 ec 8b 40 34 50 8b 45 ?? 8b 40 f0 50 ff 15}  //weight: 7, accuracy: Low
        $x_5_2 = {80 e2 0f 32 c2 88 45 f7 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d f7 02 d1 88 54 18 ff 46 8b 45 f0 e8 52 d9 ff ff 3b f0}  //weight: 5, accuracy: Low
        $x_5_3 = {8a 19 02 5c 24 09 02 5c 24 0a 02 c3 8a 19 88 5c 24 08 33 db 8a d8 8a 1c 1f 88 19}  //weight: 5, accuracy: High
        $x_5_4 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b 36 8b 04 24 64 89 05 00 00 00 00 83 c4 08 85 db 0f 94 c0 36 8d 65 fc 36 8b 1c 24 36 8b 6c 24 04 83 c4 08 c3 8b 4c 24 0c c7 81 a4 00 00 00 ff ff ff ff 83 81}  //weight: 5, accuracy: High
        $x_1_5 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "CreateRemoteThread" ascii //weight: 1
        $x_1_9 = "SetThreadContext" ascii //weight: 1
        $x_1_10 = "ResumeThread" ascii //weight: 1
        $x_1_11 = "76487-337-8429955-22614" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_7_*) and 5 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AZ_2147629013_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!AZ"
        threat_id = "2147629013"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 02 74 0e fc 8b 07 31 06 83 c6 04 83 c7 04 49 75 f3 59 83 e1 03 74 09 8a 07 30 06 46 47 49 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 0c 8b 8b 0c 8d ?? ?? ?? ?? 8d 70 01 81 e6 03 00 00 80 79 05}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 04 b6 8b 44 c7 14 3b e8 76 02 8b e8 46 4b 75 ef}  //weight: 1, accuracy: High
        $x_1_4 = {7d 11 6a 01 8b 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? eb 75 6a 40 68 00 30 00 00 56 8b 45 f8 50 8b 85 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_BA_2147629364_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BA"
        threat_id = "2147629364"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c e8 0f 84 ?? ?? 00 00 e8 ?? ?? ff ff 3c ff 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {32 c1 8b 4d f8 8b 7d ?? 0f b6 4c 39 ff 03 c9 c1 e9 02 32 c1 32 d0 88 55 ef}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 50 28 8b 45 ?? 03 d0 8b c2 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_BB_2147629620_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BB"
        threat_id = "2147629620"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b 85 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 10, accuracy: Low
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "SetThreadContext" ascii //weight: 1
        $x_1_4 = "ResumeThread" ascii //weight: 1
        $x_1_5 = "EnumResourceNamesA" ascii //weight: 1
        $x_1_6 = "CreateProcessA" ascii //weight: 1
        $x_1_7 = "VirtualAllocEx" ascii //weight: 1
        $x_1_8 = "ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_BC_2147629890_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BC"
        threat_id = "2147629890"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_3 = "RtlDecompressBuffer" ascii //weight: 1
        $x_1_4 = {03 45 fc 50 8b 45 e8 8d 04 80 8b 55 dc 8b 44 c2 0c 03 45 f4 50 8b 45 c8 50 ff 15 ?? ?? 40 00 ff 45 e8 ff 4d d8 75}  //weight: 1, accuracy: Low
        $x_1_5 = {3c e8 0f 84 ?? ?? 00 00 e8 ?? ?? ff ff 3c ff 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_BD_2147629933_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BD"
        threat_id = "2147629933"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_2_4 = {30 04 0a ff 45 ?? ff 4d ?? 0f 85}  //weight: 2, accuracy: Low
        $x_2_5 = {8b 40 54 50 8b 45 ?? 50 8b 45 ?? 50 8b 45 ?? 50 10 00 40 00 8b 40 3c 03 45}  //weight: 2, accuracy: Low
        $n_10_6 = "\\IMI Warehouse\\" ascii //weight: -10
        $n_10_7 = "ProperSoft (ProperSoft.net)" wide //weight: -10
        $n_10_8 = "TFHOWNOWMAIN" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_BE_2147630114_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BE"
        threat_id = "2147630114"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c e8 0f 84 ?? ?? 00 00 e8 ?? ?? ff ff 3c ff 0f 84}  //weight: 1, accuracy: Low
        $x_2_2 = {8b 40 50 50 8b 45 ?? e8 1a 00 8b ?? 3c 03 ?? [0-1] 89 45 ?? 6a 04 68 00 30 00 00 8b 45}  //weight: 2, accuracy: Low
        $x_1_3 = {25 ff 00 00 00 89 84 9d ?? ?? ff ff 8b 84 b5 00 ff ff 03 84 9d 00 ff ff 25 ff 00 00 00 8a 84 85 00 ff ff 8b 55 ?? 30 04 3a 47 ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_2_4 = {0f b7 78 06 4f 85 ff 72 ?? 47 33 db 8d 45 e8 50 8d 34 9b 8b 45 dc 8b 44 f0 10 50 8b 45 dc 8b 44 f0 14 03 45 fc 50}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_BG_2147630812_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BG"
        threat_id = "2147630812"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 47 28 03 45 f0 89 85 7c ff ff ff 8d 85 cc fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 0f b6 54 1a ff 80 e2 f0 0f b6 4d f3 02 d1 88 54 18 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_BH_2147631310_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BH"
        threat_id = "2147631310"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 34 9b 8b 45 ?? 8b 44 f0 10 50 8b 45 ?? 8b 44 f0 14 03 c7 50 8b 45 ?? 8b 44 f0 0c 03 45}  //weight: 1, accuracy: Low
        $x_1_2 = {25 ff 00 00 00 89 84 9d ?? ?? ff ff 8b 84 b5 00 ff ff 03 84 9d 00 ff ff 25 ff 00 00 00 8a 84 85 00 ff ff 8b 55 ?? 30 04 3a 47 ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 47 3c 03 c7 89 45 ?? 8b 45 00 8b ?? 50 6a 04 68 00 30 00 00 ?? 8b 45 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_BJ_2147632317_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BJ"
        threat_id = "2147632317"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 01 4d fa 8a 45 ff 3c e8 74 04 3c ff}  //weight: 1, accuracy: High
        $x_1_2 = {0f 01 4d f5 0f b6 45 fa 3c e8 74 04 3c ff}  //weight: 1, accuracy: High
        $x_1_3 = {8b c3 99 f7 7d ?? 8b c6 32 d0}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 44 18 ff 99 f7 fb 33 f2 43}  //weight: 1, accuracy: High
        $x_1_5 = {8d 34 9b 8b 45 ?? 8b 44 f0 10 50 8b 45 ?? 8b 44 f0 14 03 45 ?? 50 8b 45 ?? 8b 44 f0 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_DelfInject_BP_2147633096_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BP"
        threat_id = "2147633096"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3a 47 4b 0f 85 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 8b d8 4b 85 db 7c 29}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c7 f8 00 00 00 0f b7 9d ?? ?? ff ff 4b 85 db 0f 8c}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f0 03 85 d8 fe ff ff 89 85 18 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_BQ_2147633712_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BQ"
        threat_id = "2147633712"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 47 28 03 45 ?? 89 45}  //weight: 2, accuracy: Low
        $x_2_2 = {0f 01 4d f5 0f b6 45 fa 3c e8 74 04 3c ff 75 02}  //weight: 2, accuracy: High
        $x_1_3 = {66 81 3b 4d 5a 0f 85}  //weight: 1, accuracy: High
        $x_1_4 = {81 3f 50 45 00 00 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_BR_2147633866_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BR"
        threat_id = "2147633866"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 68 00 04 00 00 53 e8 ?? ?? ff ff 6a 00 8d 45 f8 50 6a 01 8d 45 f7 50 53 e8 ?? ?? ff ff 6a 00 6a 00 68 01 04 00 00 53 e8 ?? ?? ff ff 6a 00 8d 45 f8 50 6a 04}  //weight: 2, accuracy: Low
        $x_1_2 = {d3 e0 8b c8 8b 45 f0 33 d2 f7 f1 89 55 f0 b9 00 01 00 00 8b c3 99 f7 f9}  //weight: 1, accuracy: High
        $x_1_3 = {8b de 66 81 3b 4d 5a 0f 85 ?? ?? 00 00 [0-32] 8b c6 33 d2 52 50 8b 43 3c 99}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_BT_2147634033_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BT"
        threat_id = "2147634033"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 10 c1 e3 10 8b 45 fc 0f b6 04 30 c1 e0 18 03 d8 8d 46 02 33 d2 f7 75 f8 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {81 3b 50 45 00 00 0f 85 ?? ?? 00 00 66 8b 43 16 f6 c4 20 0f 85 ?? ?? 00 00 a8 02 0f 84 ?? ?? 00 00 0f b7 43 14 3d e0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 03 57 c6 43 01 72 c6 43 02 69 c6 43 03 74 c6 43 04 65 c6 43 05 50 c6 43 06 72 c6 43 07 6f c6 43 08 63 c6 43 09 65 c6 43 0a 73 c6 43 0b 73 c6 43 0c 4d c6 43 0d 65 c6 43 0e 6d c6 43 0f 6f c6 43 10 72 c6 43 11 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_BU_2147634243_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BU"
        threat_id = "2147634243"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 01 4d f5 8a 45 fa 3c e8 74 04 3c ff}  //weight: 1, accuracy: High
        $x_1_2 = {6a 04 8d 45 f0 50 53 e8 ?? ?? ?? ?? 8d 45 f4 8b 55 f0 e8 ?? ?? ?? ?? 6a 00 6a 00 68 05 04 00 00 53 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 34 9b 8b 45 ?? 8b 44 f0 10 50 8b 45 ?? 8b 44 f0 14 03 45 ?? 50 8b 45 ?? 8b 44 f0 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_BV_2147635808_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BV"
        threat_id = "2147635808"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 04 68 00 30 00 00 8b 45 ?? 8b 40 50 50 8b 45 00 8b 40 34}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 40 34 89 45 ?? 6a 04 68 00 30 00 00 8b 45 ?? 8b 40 50 50 8b 45 00}  //weight: 2, accuracy: Low
        $x_1_3 = {0f b7 40 06 48 85 c0 72}  //weight: 1, accuracy: High
        $x_1_4 = {3c e8 74 04 3c ff 75 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_BX_2147643196_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BX"
        threat_id = "2147643196"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "XuRunPE" ascii //weight: 3
        $x_4_2 = "ReaePrncdrsMdmosy" ascii //weight: 4
        $x_4_3 = "noitceSfOweiVpamnUtN" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_BY_2147643401_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!BY"
        threat_id = "2147643401"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 03 8d 04 80 99 03 04 24 13 54 24 04 83 c4 08 8b 55 ?? 03 d0 8d 85 ?? ?? ff ff b9 28 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 00 04 00 00 8d 85 ?? ?? ff ff e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c7 8b 55 f8 e8 ?? ?? ?? ?? 2b 75 f4 81 fe 00 (04|90 90) 00 00 7f bb}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 f8 00 00 00 e8 ?? ?? ?? ?? 81 bd ?? ?? ff ff 50 45 00 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CA_2147645355_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CA"
        threat_id = "2147645355"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 0b 0f b7 d1 c1 ea 0c 66 81 e1 ff 0f 0f b7 c9 83 fa 03 75 0a 8b 55 f8 03 d1 8b 4d 10 01 0a 83 c3 02 48 75 da}  //weight: 1, accuracy: High
        $x_1_2 = {32 c2 88 45 ?? eb [0-5] 40 72}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 4d 08 8b 55 0c 90 66 81 3a 4d 5a 90 75 ?? 90 03 52 3c 90 81 3a 50 45 00 00 90 75 ?? 8b 52 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_DelfInject_CB_2147647367_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CB"
        threat_id = "2147647367"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "g?_smkgksv_w}vwai61Xwdnth`\\5*`{a" ascii //weight: 4
        $x_3_2 = {55 8b ec 51 0f 00 45 fe 0f b7 45 fe 0d 00 00 ad de 59 5d c3}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CC_2147647438_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CC"
        threat_id = "2147647438"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 04 8d 45 ?? 50 8b 87 a4 00 00 00 83 c0 08 50 8b 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 03 43 28 89 87 b0 00 00 00 57 8b 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {50 33 c9 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 53 ff 16 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CD_2147648012_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CD"
        threat_id = "2147648012"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 03 8d 04 80 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 d0 8b c6 b9 28 00 00 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 02 89 45 f0 6a 04 68 00 30 00 00 ff 75 fc ff 75 f8 ff 75 f4 8b 45 f0 83 e8 02 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CE_2147648546_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CE"
        threat_id = "2147648546"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 29 be 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 32 ff 66 81 f2 9a 02}  //weight: 2, accuracy: High
        $x_1_2 = {8b 40 0c 03 c3 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 83 c0 03 8b 56 1c 03 d3 0f b7 c0 c1 e0 02 03 d0}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 30 00 00 6a 10 6a 00 53 ff 15 ?? ?? ?? ?? 8b f0 8d 45 f8 50 6a 10 8d 45 e4 50 56 53 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {a5 a5 68 e8 03 00 00 ff 55 f8 ff 75 fc ff 55 f0 83 f8 00 74 ed 6a 00 ff 55 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_CF_2147649112_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CF"
        threat_id = "2147649112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 33 c0 89 45 f8 8b f3 66 81 3e 4d 5a 0f 85 ?? ?? ?? ?? 8b fb 03 7e 3c 81 3f 50 45 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 f8 00 00 00 57 8b c3 03 46 3c 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CF_2147649112_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CF"
        threat_id = "2147649112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 02 00 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 ?? 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d ?? 02 d1 88 54 18 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b df 85 db 7c ?? 43 33 f6 a1 ?? ?? ?? ?? 8a 04 30 a2 ?? ?? ?? ?? a0 02 34}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 00 00 00 00 40 3d 00 e9 a4 35 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 e9}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 04 30 a2 ?? ?? ?? ?? a0 00 c0 c8 ?? a2 00 a1 ?? ?? ?? ?? 8a 15 00 88 14 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_DelfInject_CG_2147650169_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CG"
        threat_id = "2147650169"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c fb 75 03 b0 01 c3 3c fd 75 04 b0 03 eb 17 3c ff 75 04 b0 05 eb 0f 33 d2 8a d0 83 e2 01 83 fa 01 75 03 83 c0 06 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8d 53 04 8b ce 2b ca 8b 15 ?? ?? 00 01 88 04 0a 46 4f 75 df eb}  //weight: 1, accuracy: Low
        $x_2_3 = {8d 7d dd a5 a5 a5 66 a5 a4 b8 01 00 00 00 33 d2 8a 55 dd 42 88 55 dd 48}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_CH_2147650223_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CH"
        threat_id = "2147650223"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 47 50 50 8b 47 34 50 8b 45 d0 50}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 89 45 ?? 8b de 66 81 3b 4d 5a 0f 85 ?? ?? 00 00 8b fe 03 7b 3c 81 3f 50 45 00 00 0f 85 ?? ?? 00 00 8d 45 ?? 33 c9 ba 44 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CI_2147650328_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CI"
        threat_id = "2147650328"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 53 18 81 bd ?? ?? ?? ?? 50 45 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 42 4b 52 94 8b d3}  //weight: 1, accuracy: High
        $x_1_3 = {ff d5 50 ff 54 24 0c 83 c4 0c 5d 5f 5e 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_DelfInject_U_2147650456_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.U"
        threat_id = "2147650456"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 42 46 49 53 48 00 10 da 42 54 50 00}  //weight: 1, accuracy: High
        $x_2_2 = {74 3e bf 01 00 00 00 0f b6 03 3c 2d 75 06 83 cf ff 43}  //weight: 2, accuracy: High
        $x_2_3 = {83 c0 78 8b 10 89 55 e0 03 50 04 89 55 dc 8b 45 e0 03 c3 8b 48 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_W_2147650654_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.W"
        threat_id = "2147650654"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "cryptocode" ascii //weight: 5
        $x_5_2 = "CodersCrypt" ascii //weight: 5
        $x_10_3 = {43 33 ff a1 ?? ?? ?? 00 8a 04 38 a2 ?? ?? ?? 00 a0 ?? ?? ?? 00 c0 c8 ?? a2 ?? ?? ?? 00 a1 ?? ?? ?? 00 8a 15 ?? ?? ?? 00 88 14 38 47 4b 75}  //weight: 10, accuracy: Low
        $x_1_4 = {36 00 00 00 ff ff ff ff 01 00 00 00 37 00 00 00 ff ff ff ff 01 00 00 00 38 00 00 00 ff ff ff ff 01 00 00 00 39 00 00 00 ff ff ff ff 01 00 00 00 30 00 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_10_5 = {48 5a 8b ca 99 f7 f9 42 a1 ?? ?? ?? 00 8a 44 10 ff 8b 15 ?? ?? ?? 00 8a 14 3a 32 c2 8b 15 ?? ?? ?? 00 88 04 3a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_CJ_2147650664_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CJ"
        threat_id = "2147650664"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 00 01 00 06 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 a1 ?? ?? ?? ?? 8b 40 50 50 a1 ?? ?? ?? ?? 8b 40 34}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 28 03 05 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_X_2147650863_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.X"
        threat_id = "2147650863"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 6c fe ff ff 50 ff d7 46 4b 75 a0}  //weight: 1, accuracy: High
        $x_1_2 = {81 bd a4 fe ff ff 50 45 00 00 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {bf cc cc cc 0c 8a 1e 46 80 fb 20 74 f8 b5 00 80 fb 2d 74 62 80 fb 2b 74 5f 80 fb 24 74 5f 80 fb 78 74 5a 80 fb 58 74 55 80 fb 30 75 13 8a 1e 46 80 fb 78 74 48 80 fb 58 74 43 84 db 74 20 eb 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_Y_2147651574_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.Y"
        threat_id = "2147651574"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 85 f6 7e 1f bb 01 00 00 00 8d 45 ?? ?? ?? ?? ff ff 8b 55 ?? 0f b6 54 1a ff 33 d7 88 54 18 ff 43 4e 75 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 4b 83 fb 04 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ff 8b d8 a1 ?? ?? ?? ?? ?? ?? ?? ?? ff 50 b8 ?? ?? ?? ?? ?? ?? ?? ?? ff 50 ff d3 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CL_2147651788_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CL"
        threat_id = "2147651788"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 69 43 69 43 6f 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 72 79 70 74 6f 63 6f 64 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "i++t+e+P+r+o+ce++ssM+e+m+o+ry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_Z_2147651908_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.Z"
        threat_id = "2147651908"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0f 31 d2 8a 16 01 d3 48 8d 76 01 8d 3c 3b 7f f1}  //weight: 1, accuracy: High
        $x_1_2 = {7c 31 8d 6f ff 89 d8 c1 e8 02 83 e0 07 29 c5 8a 06 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CM_2147652016_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CM"
        threat_id = "2147652016"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 6a 00 ff 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 02 00 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 54 50 a1 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? f8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "cryptocode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AB_2147652415_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.AB"
        threat_id = "2147652415"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RunPE" ascii //weight: 1
        $x_1_2 = {07 00 01 00 06 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 54 1f ff 0f b7 ce c1 e9 08 32 d1 88 54 18 ff 33 c0 8a 44 1f ff 66 03 f0 66 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AP_2147653152_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.AP"
        threat_id = "2147653152"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7c 20 40 c7 03 00 00 00 00 8b 15 28 e4 4b 00 03 13 8a 12 8b 0d 24 e4 4b 00 03 0b 88 11 ff 03 48 75 e7}  //weight: 2, accuracy: High
        $x_2_2 = {c6 06 ff eb 17 84 d2 75 05 c6 06 00 eb 0e 8b 15 28 e4 4b 00 03 13 0f b6 12 4a 88 16 ff 03 48 75 d0}  //weight: 2, accuracy: High
        $x_1_3 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 21 e8}  //weight: 1, accuracy: High
        $x_2_4 = "\\WindowsUpdat_96793.exe" wide //weight: 2
        $x_1_5 = {7e 7a 57 7c 00 00 00 00 ?? 7a 48 00 0a 09}  //weight: 1, accuracy: Low
        $x_1_6 = {51 4c 04 05 15 00 00 00 09 00 [0-48] 2f 66 79 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_AD_2147654020_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.AD"
        threat_id = "2147654020"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BTMemoryLoadLibary" ascii //weight: 1
        $x_1_2 = {52 70 65 00 45 78 65 63 75 74 65 46 72 6f 6d 4d 65 6d 00 00 4d 65 74 61 6c}  //weight: 1, accuracy: High
        $x_1_3 = {ff 46 0c 8b 45 f8 8b 08 85 c9 74 12 8b c1 33 d2 52 50 8b 46 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CO_2147654264_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CO"
        threat_id = "2147654264"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 57 ff 47 ff 4d f8 0f 85 b2 f8 ff ff e9 93 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a ff ff d7 50 ff d3 eb 17}  //weight: 1, accuracy: High
        $x_1_3 = {8d 45 f8 50 6a 00 6a 00 68 78 8a 46 00 6a 00 6a 00 ff d3 e9 93 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CP_2147654810_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CP"
        threat_id = "2147654810"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 28 03 45 ?? 8b 55 ?? 89 82 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 8d 45 ?? 50 8b 45 ?? 8b 80 a4 00 00 00 83 c0 08}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 00 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 40 68 00 30 00 00 8b 45 ?? 8b 40 50 50 8b 45 ?? 8b 40 34}  //weight: 1, accuracy: Low
        $n_10_5 = "iperf v." ascii //weight: -10
        $n_10_6 = "\\gdm\\delphi\\math\\" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule VirTool_Win32_DelfInject_CQ_2147654925_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CQ"
        threat_id = "2147654925"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 6a 00 ff 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 02 00 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 24 e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 8b 40 10 50 a1 01 8b 40 0c 03 05 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 83 05 01 28 (43 3b 1d ?? ?? ?? ??|4b)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CR_2147656702_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CR"
        threat_id = "2147656702"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff d7 66 8b 75 ?? 66 83 c6 02 66 83 fe 3b 72 ?? 66 83 ee 3b eb ?? 8d 45 e8 50 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d3 8b f0 81 c6 ?? ?? 00 00 eb ?? ff d3 ff d3 3b f0 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CS_2147656757_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CS"
        threat_id = "2147656757"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 02 ff d3 ff d3 3b f0 77 f8}  //weight: 1, accuracy: High
        $x_1_2 = {80 3a 47 75 39 80 7a 03 50 75 33 80 7a 07 41 75 2d}  //weight: 1, accuracy: High
        $x_1_3 = {8a 13 30 10 40 43 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CU_2147657183_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CU"
        threat_id = "2147657183"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 52 3c 03 d0 83 c2 04 83 c2 14 8b 42 38 89 45 ?? 33 f6 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CV_2147658303_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CV"
        threat_id = "2147658303"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 03 ca 8a 09 e9 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {80 f1 95 eb ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f0 03 f2 88 0e e9 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {42 4b 0f 85 ?? ?? ff ff 5e 5b c3 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CX_2147662045_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CX"
        threat_id = "2147662045"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 02 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 80 a4 00 00 00 83 c0 08}  //weight: 1, accuracy: High
        $x_1_3 = {03 42 28 8b 15 ?? ?? ?? ?? 8b 12 89 82 b0 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_CZ_2147669024_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!CZ"
        threat_id = "2147669024"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 06 00 [0-4] c7}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 30 00 00 8b 85 ?? ?? ?? ?? 50 8b 85 ?? ?? ?? ?? 50 8b 85 ?? ?? ?? ?? 50 8b 45 ?? ff 50}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e0 03 8d 04 80 99 03 04 24 13 54 24 04 83 c4 08 8b 15 ?? ?? ?? ?? 03 d0 8d 85 ?? ?? ?? ?? b9 28 00 00 00 31 00 81 c7 f8 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AU_2147678968_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.AU"
        threat_id = "2147678968"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 84 95 ec fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 ec fb ff ff 8b 55 ec 30 04 32 46 4f 0f 85 79 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 30 ff 24 0f 32 d8 80 f3 0a 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 3a ff 80 e2 f0 02 d3 88 54 38 ff 46 83 fe 20 7e 05}  //weight: 1, accuracy: Low
        $x_1_3 = {2b f7 81 fe e8 03 00 00 7d 0b 2b c7 3d d0 07 00 00 7d 02 b3 01 8b c3}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 72 76 65 72 2e 65 78 65 00 09 25 41 70 70 44 61 74 61 25 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 6d 65 6c 74 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 75 6e 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {73 63 68 6d 69 64 74 69 0c 00 68 3a 5c 00}  //weight: 1, accuracy: Low
        $x_1_7 = {63 3a 5c 66 69 6c 65 2e 65 78 65 00 53}  //weight: 1, accuracy: High
        $x_1_8 = {44 69 73 61 62 6c 65 53 52 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 53 79 73 74 65 6d 52 65 73 74 6f 72 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule VirTool_Win32_DelfInject_DA_2147681914_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!DA"
        threat_id = "2147681914"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c e8 0f 84 ?? ?? 00 00 e8 ?? ?? ff ff 3c ff 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 3a 47 ff 4d e8 75 a5 8b 45 fc e8}  //weight: 1, accuracy: High
        $x_2_3 = {8b 40 3c 03 45 fc 89 45 ?? 8b 45 ?? 8b 58 50 6a 04 68 00 30 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_DelfInject_DB_2147682802_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!DB"
        threat_id = "2147682802"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 42 34 03 45 ?? 2d 00 10 00 00 05 00 02 00 00 89 45 ?? 6a 00 6a 01 6a 00 ff 55 01 [0-32] 8b 45 ?? 8b 40 1c 8b 55 ?? 2b 42 34 03 45 ?? 2d 00 10 00 00 05 00 02 00 00 89 45 ?? [0-32] 6a 00 6a 01 6a 00 ff 55 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 80 c0 00 00 00 03 45 ?? 2d 00 10 00 00 05 00 02 00 00 89 45 ?? 8b 45 ?? 8b 55 ec 2b 50 34 81 ea 00 10 00 00 81 c2 00 02 00 00 89 55 fc 8b 45 ?? 8b 40 18 03 45 fc 89 45 ?? 6a 00 6a 01 6a 00 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_DelfInject_DC_2147682841_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!DC"
        threat_id = "2147682841"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ef 1a 29 ff b8 2e 00 00 00 31 c0 83 ef 1a 29 ff b8 2e 00 00 00 31 c0 83 ef 1a 29 ff b8 2e 00 00 00 31 c0 83 ef 1a 29 ff b8 2e 00 00 00 31 c0 83 ef 1a 29 ff b8 2e 00 00 00 31 c0 4a 0f 85 0d fe ff ff 68 00 01 00 00 8d 85 f7 fd ff ff 50 6a 00 e8 ?? ?? ff ff 83 c0 10 83 f8 20 7f 09 6a 00 6a ff e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DD_2147682992_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!DD"
        threat_id = "2147682992"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a 81 ca 00 ff ff ff 42 32 84 95 ?? ?? ff ff 8b 55 fc 88 02}  //weight: 1, accuracy: Low
        $x_1_2 = {68 7c 66 00 00 8b 45 f8 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DE_2147682999_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!DE"
        threat_id = "2147682999"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 92 8b ca 99 f7 f9 8b d8 85 db 7c 0f 43 8d 45 f4 8b 55 f8 e8 ?? ?? ?? ?? 4b 75 f2 8b 45 fc e8 ?? ?? ?? ?? 8b d8 85 db 7e 36 be 01 00 00 00 90 90 90 90 90 8b 45 fc 8a 44 30 ff 8b 55 f4 8a 54 32 ff 32 c2 88 45 f3 8d 45 ec 8a 55 f3 e8 ?? ?? ?? ?? 8b 55 ec 8b c7 e8 ?? ?? ?? ?? 46 4b 75 cf}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e3 02 03 f3 8b 1e 03 d8 8b f3 8b 5d ec 8b 5b 1c 03 d8 c1 e2 02 03 da}  //weight: 1, accuracy: High
        $x_1_3 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_DelfInject_DI_2147694095_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!DI"
        threat_id = "2147694095"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7f 04 00 00 75 e2 6a 40 68 00 30 00 00 68 7f 04 00 00 6a 00 e8 18 00 a1 ?? ?? ?? ?? 80 b0 ?? ?? ?? ?? f9 ff 05 ?? ?? ?? ?? 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DJ_2147696971_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!DJ"
        threat_id = "2147696971"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 e8 03 00 00 1d 00 07 00 01 00 8d 85 ?? ?? ff ff 50 8b 45 ?? 50 ff 15 ?? ?? ?? 00 84 c0 0f 84 ?? 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 34 50 8b 45 d4 50 ff 15 ?? ?? ?? 00 85 c0 75 ?? b8 f4 01 00 00 e8 ?? ?? ff ff 6a 40 68 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DL_2147697778_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!DL"
        threat_id = "2147697778"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 07 00 01 00 89 08}  //weight: 1, accuracy: High
        $x_1_2 = {ff 53 60 6a 00 ff 75 ?? ff 93 88 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 d2 c7 f0 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DM_2147705541_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.DM"
        threat_id = "2147705541"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 68 00 40 06 00 6a 00 e8 ?? ?? ?? ff 89 45 f8 [0-48] 8d 45 f4 50 6a 00 68 e8 03 00 00 68 ?? ?? 40 00 6a 00 6a 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {56 89 c0 5e 4b 75 f9 05 00 bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_AY_2147706509_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.AY"
        threat_id = "2147706509"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 8a 84 9d ?? ?? ?? ?? 8b 94 bd ?? ?? ?? ?? 89 94 9d ?? ?? ?? ?? 25 ff 00 00 00 89 84 bd ?? ?? ?? ?? 8b 45 08 33 d2 52 50 8b 84 9d ?? ?? ?? ?? 03 84 bd ?? ?? ?? ?? 99 e8 ?? ?? ?? ?? 8a 84 85 ?? ?? ?? ?? 30 06 46 ff 4d f0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 01 00 00 b9 ?? ?? ?? ?? ba 20 00 00 00 b8 11 5a 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 95 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? 03 1d ?? ?? ?? ?? 89 5d fc ?? ?? ?? ?? ff 75 fc c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DN_2147709402_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.DN!bit"
        threat_id = "2147709402"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4d ec ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ec e8 ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
        $x_1_2 = {bf 01 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8b 55 fc 0f b6 54 3a ff 33 c2 50 8b 45 f8 e8 ?? ?? ?? ?? 8b 55 f8 0f b6 54 1a ff 33 c2 5a 33 d0 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 f0 e8 ?? ?? ?? ?? 43 8b 45 f8 e8 ?? ?? ?? ?? 3b d8 7e 05 bb 01 00 00 00 47 4e 75 af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DO_2147712471_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.DO!bit"
        threat_id = "2147712471"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bf 01 00 00 00 8b 45 fc e8 ?? ?? ?? ff 8b 55 fc 0f b6 54 3a ff 33 c2 50 8b 45 f8 e8 ?? ?? ?? ff 8b 55 f8 0f b6 54 1a ff 33 c2 5a 33 d0 8d 45 ec e8 ?? ?? ?? ff 8b 55 ec 8d 45 f0 e8 ?? ?? ?? ff 43 8b 45 f8 e8 ?? ?? ?? ff 3b d8 7e 05 bb 01 00 00 00 47 4e 75 af}  //weight: 2, accuracy: Low
        $x_1_2 = {8d 55 e8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 e8 8d 4d ec ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DP_2147719158_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.DP!bit"
        threat_id = "2147719158"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc e8 ?? ?? ?? ff 8b c8 8b 55 fc a1 ?? ?? ?? 00 e8 ?? ?? ?? ff 6a 40 68 00 30 00 00 53 6a 00 e8 ?? ?? ?? ff 8b f0 85 f6 74 70 8b cb 8b d6 8b 45 fc e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DM_2147732949_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.gen!DM"
        threat_id = "2147732949"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 84 85 f8 fb ff ff 30 04 32 ff 45 f8}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 e4 4b 56 4d 4b c7 45 e8 56 4d 4b 56}  //weight: 1, accuracy: High
        $x_1_3 = {6a 30 59 64 8b 01 80 78 02 00 0f 85 07 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DQ_2147732994_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.DQ!bit"
        threat_id = "2147732994"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 40 00 00 00 ba 9d 53 00 00 a1 ?? ?? 48 00 ff 15 ?? ?? 48 00 33 db a1 ?? ?? 48 00 03 c3 8a 00 90 34 a6 8b 15 60 ?? ?? 00 03 d3 88 02 90 43 81 fb ?? ?? ?? 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 3a 02 00 00 a1 ?? ?? 48 00 03 c3 a3 ?? ?? 48 00 90 90 90 ff 35 ?? ?? 48 00 c3}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_DelfInject_DR_2147733084_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DelfInject.DR!bit"
        threat_id = "2147733084"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 03 89 06 ?? a1 ?? ?? 48 00 03 06 8a 00 ?? ?? 34 ?? 8b ?? ?? ?? 48 00 03 16 88 02 ?? ff 03 81 ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {03 03 89 06 8b 06 89 03 ff ?? ?? ?? 48 00 5a ?? ff e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

