rule VirTool_Win64_CobaltStrike_A_2147767135_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.A"
        threat_id = "2147767135"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 8b 10 41 8b 40 04 4d 8d 40 08 85 d2 75 04}  //weight: 2, accuracy: High
        $x_2_2 = {45 8b 0a 41 8b 42 04 4d 8d 52 08 45 85 c9}  //weight: 2, accuracy: High
        $x_2_3 = {2b c1 4c 8b c1 44 8b c8 48 8b 0b 8a 43 10 42 30 04 01 49 ff c0 49 ff c9 75 ee}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win64_CobaltStrike_A_2147767135_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.A"
        threat_id = "2147767135"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f0 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a}  //weight: 1, accuracy: High
        $x_1_2 = {e9 4f ff ff ff 5d 6a 00 49 be 77 69 6e 69 6e 65 74 00 41 56 49 89 e6 4c 89 f1 41 ba 4c 77 26 07 ff d5 48 31 c9 48 31 d2 4d 31 c0 4d 31 c9 41 50 41 50 41 ba 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_A_2147767135_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.A"
        threat_id = "2147767135"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16}  //weight: 1, accuracy: High
        $x_1_3 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd}  //weight: 1, accuracy: High
        $x_1_5 = {48 b8 73 79 73 74 65 6d 33 32 48 83 cb ff 48 89 07 4c 8b c3 49 ff c0 42 80 7c 07 09 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_A_2147767135_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.A"
        threat_id = "2147767135"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 ?? ?? ?? ?? ff d3 41 b8 f0 b5 a2 56 68 04 00 00 00 5a 48 89 f9 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16}  //weight: 1, accuracy: High
        $x_1_4 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_B_2147773433_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.B"
        threat_id = "2147773433"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16}  //weight: 1, accuracy: High
        $x_1_3 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd}  //weight: 1, accuracy: High
        $x_1_5 = {41 8b c7 80 34 28 69 48 ff c0 48 3d 00 10 00 00 7c f1 48 8d 4c 24 20 41 b8 00 10 00 00 48 8b d5 e8}  //weight: 1, accuracy: High
        $x_1_6 = {62 65 61 63 6f 6e [0-4] 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_7 = "ReflectiveLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_C_2147773435_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.C"
        threat_id = "2147773435"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 f9 5b bc 4a 6a 74}  //weight: 10, accuracy: High
        $x_10_2 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91}  //weight: 10, accuracy: Low
        $x_10_3 = {3c 33 c9 41 b8 00 30 00 00 4c 03 ?? 44 8d 49 40 41 8b}  //weight: 10, accuracy: Low
        $x_10_4 = "ReflectiveLoader" ascii //weight: 10
        $x_1_5 = "\\\\.\\pipe\\sshagent" ascii //weight: 1
        $x_1_6 = {63 6f 6e 6e 65 63 74 20 74 6f 20 25 73 3a 25 64 20 66 61 69 6c 65 64 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_7 = "COBALTSTRIKE" ascii //weight: 1
        $x_1_8 = "%1024[^ ] %8[^:]://%1016[^/]%7168" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win64_CobaltStrike_C_2147773435_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.C"
        threat_id = "2147773435"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16}  //weight: 10, accuracy: High
        $x_10_3 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5}  //weight: 10, accuracy: High
        $x_10_4 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd}  //weight: 10, accuracy: High
        $x_10_5 = {41 8b c7 80 34 28 69 48 ff c0 48 3d 00 10 00 00 7c f1 48 8d 4c 24 20 41 b8 00 10 00 00 48 8b d5 e8}  //weight: 10, accuracy: High
        $x_10_6 = "ReflectiveLoader" ascii //weight: 10
        $x_1_7 = {57 6f 77 36 34 44 69 73 61 62 6c 65 57 6f 77 36 34 46 73 52 65 64 69 72 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 74 61 72 74 65 64 20 73 65 72 76 69 63 65 20 25 73 20 6f 6e 20 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_C_2147773435_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.C"
        threat_id = "2147773435"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 b1 81 7d ?? 5b bc 4a 6a 75 0b}  //weight: 10, accuracy: Low
        $x_10_2 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91}  //weight: 10, accuracy: Low
        $x_10_3 = {6a 40 68 00 30 00 00 8b ?? ?? 8b ?? ?? ?? 6a 00 ff 55}  //weight: 10, accuracy: Low
        $x_10_4 = "ReflectiveLoader" ascii //weight: 10
        $x_1_5 = "\\\\.\\pipe\\sshagent" ascii //weight: 1
        $x_1_6 = {63 6f 6e 6e 65 63 74 20 74 6f 20 25 73 3a 25 64 20 66 61 69 6c 65 64 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_7 = "COBALTSTRIKE" ascii //weight: 1
        $x_1_8 = "%1024[^ ] %8[^:]://%1016[^/]%7168" ascii //weight: 1
        $x_1_9 = "\\\\%s\\pipe\\msagent_%x" ascii //weight: 1
        $x_1_10 = {5b 63 6f 6d 6d 61 6e 64 5d 00 [0-8] 5b 63 74 72 6c 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win64_CobaltStrike_C_2147773435_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.C"
        threat_id = "2147773435"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 f9 5b bc 4a 6a 0f 85 ?? 00 00 00 49}  //weight: 10, accuracy: Low
        $x_10_2 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91}  //weight: 10, accuracy: Low
        $x_10_3 = {b8 0a 4c 53 75}  //weight: 10, accuracy: High
        $x_10_4 = {48 63 5f 3c 33 c9 41 b8 00 30 00 00 48 03 df 44 8d 49 40 8b 53 50 41 ff d6}  //weight: 10, accuracy: High
        $x_10_5 = "ReflectiveLoader" ascii //weight: 10
        $x_1_6 = "\\\\.\\pipe\\bypassuac" ascii //weight: 1
        $x_1_7 = "\\System32\\cliconfg.exe" wide //weight: 1
        $x_1_8 = "[-] ICorRuntimeHost::GetDefaultDomain" ascii //weight: 1
        $x_1_9 = "[-] Invoke_3 " ascii //weight: 1
        $x_1_10 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 72 00 75 00 6e 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_12 = "\\\\.\\pipe\\keylogger" ascii //weight: 1
        $x_1_13 = "[unknown: %02X]" ascii //weight: 1
        $x_1_14 = {2f 73 65 6e 64 25 73 00 50 4f 53 54}  //weight: 1, accuracy: High
        $x_1_15 = {72 63 61 70 3a 2f 2f 00 45 72 72 6f 72}  //weight: 1, accuracy: High
        $x_1_16 = "\\\\.\\pipe\\netview" ascii //weight: 1
        $x_1_17 = " %-22s %-20s %-14s %s" ascii //weight: 1
        $x_1_18 = "\\\\.\\pipe\\powershell" ascii //weight: 1
        $x_1_19 = "ICLRRuntimeInfo::IsLoadable" ascii //weight: 1
        $x_1_20 = "\\\\.\\pipe\\screenshot" ascii //weight: 1
        $x_1_21 = {00 4a 50 45 47 4d 45 4d 00}  //weight: 1, accuracy: High
        $x_1_22 = "\\\\.\\pipe\\mimikatz" ascii //weight: 1
        $x_1_23 = "token::elevate" ascii //weight: 1
        $x_1_24 = "\\\\.\\pipe\\hashdump" ascii //weight: 1
        $x_1_25 = "Global\\SAM" ascii //weight: 1
        $x_1_26 = "\\\\.\\pipe\\elevate" ascii //weight: 1
        $x_1_27 = "[*] %s loaded in userspace" ascii //weight: 1
        $x_1_28 = "\\\\.\\pipe\\portscan" ascii //weight: 1
        $x_1_29 = {5c 5c 25 73 5c 69 70 63 24 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 22 of ($x_1_*))) or
            ((4 of ($x_10_*) and 12 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win64_CobaltStrike_D_2147773436_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.D"
        threat_id = "2147773436"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 49 89 c9 39 d0 7d 13 48 89 c1 83 e1 03 41 8a 0c 08 41 30 0c 01 48 ff c0 eb e9 4c 89 c9}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_D_2147773436_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.D"
        threat_id = "2147773436"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff e0 58 5f 5a 8b 12 eb 86 5b 80 7e 10 00 75 3b c6 46 10 01 68 a6 95 bd 9d ff d3 3c 06 7c 1a}  //weight: 1, accuracy: High
        $x_1_2 = {31 c9 51 51 ff 76 08 ff 36 51 51 68 38 68 0d 16 ff d3 c9}  //weight: 1, accuracy: High
        $x_1_3 = {e8 00 00 00 00 58 83 c0 25 83 ec 08 89 e2 c7 42 04 33 00 00 00 89 02 e8 09 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 31 d2 48 8b 0e 41 ba c8 38 a4 40 ff d5 48 85 c0 74 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_D_2147773436_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.D"
        threat_id = "2147773436"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 00 10 00 00 4c 8d 87 80 00 00 00 48 89 d6 c7 44 24 20 04 00 00 00 31 d2 ff 15 ?? ?? ?? ?? 48 89 c5 48 8d 44 24 50 4d 89 e0 49 89 f9 48 89 ea 48 89 d9 48 89 44 24 20 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_D_2147773436_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.D"
        threat_id = "2147773436"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 00 30 00 00 31 c9 48 89 f7 ff 15 ?? ?? ?? ?? 48 89 c3 31 c0 39 f8 7d 16 48 89 c2 83 e2 03 41 8a 14 14 32 54 05 00 88 14 03 48 ff c0 eb e6}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {b9 60 ea 00 00 ff d3 eb f7 [0-16] 48 ff e1}  //weight: 1, accuracy: Low
        $x_1_4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_D_2147773436_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.D"
        threat_id = "2147773436"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff e1 41 54 55 57 56 53 48 83 ec 40 41 b9 04 00 00 00 48 63 f2 48 89 cd [0-21] 41 b8 00 30 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8d 4c 24 3c 48 89 f2 48 89 d9 41 b8 20 00 00 00 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ff ff ff 49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 ?? ?? ?? ?? 90 48 83 c4 40}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_D_2147773436_5
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.D"
        threat_id = "2147773436"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 83 c0 25 83 ec 08 89 e2 c7 42 04 33 00 00 00 89 02 e8 09 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {f0 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a}  //weight: 1, accuracy: High
        $x_1_3 = {48 31 d2 48 8b 0e 41 ba c8 38 a4 40 ff d5 48 85 c0 74 0c}  //weight: 1, accuracy: High
        $n_100_4 = {4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 64 00 65 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 68 00 65 00 6c 00 70 00 65 00 72 00 00 00}  //weight: -100, accuracy: High
        $n_100_5 = {4f 00 75 00 74 00 62 00 79 00 74 00 65 00 20 00 50 00 43 00 20 00 52 00 65 00 70 00 61 00 69 00 72 00 00 00}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_D_2147773436_6
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.D"
        threat_id = "2147773436"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8b 45 08 5d ff e0 55 89 e5 [0-32] c7 44 24 0c 04 00 00 00 c7 44 24 08 00 30 00 00 c7 04 24 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 08 20 00 00 00 89 44 24 0c ff 15 ?? ?? ?? ?? 83 ec 10 89 ?? 24 0c c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 08 ?? ?? ?? ?? c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_F_2147773437_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.F!entry"
        threat_id = "2147773437"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "entry: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 ?? ?? ?? ?? ff d3 41 b8 ?? ?? ?? ?? 68 04 00 00 00 5a 48 89 f9 ff d0 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_G_2147781999_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.G"
        threat_id = "2147781999"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 48 63 f2 49 89 cc 89 d7 4c 89 c5 48 89 f2 41 b8 00 30 00 00 31 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {41 b8 20 00 00 00 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? 49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
        $x_1_5 = {48 89 c2 83 e2 ?? 41 8a 14 14 32 54 05 ?? 88 14 03 48 ff c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win64_CobaltStrike_I_2147782890_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.I"
        threat_id = "2147782890"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 60 ea 00 00 ff d3 eb f7 [0-16] 48 ff e1}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b8 00 30 00 00 31 c9 48 89 f7 ff 15 ?? ?? ?? ?? 48 89 c3 31 c0 39 f8 7d ?? 48 89 c2 83 e2 03}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8d 4c 24 3c 48 89 f2 48 89 d9 41 b8 20 00 00 00 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ff ff ff 49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 ?? ?? ?? ?? 90 48 83 c4 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_CobaltStrike_I_2147782890_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/CobaltStrike.I"
        threat_id = "2147782890"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 04 37 44 8b f7 8b c8 48 89 44 24 50 ff 15 ?? ?? ?? ?? 8b 4c 24 54 44 8b f8 ff 15 ?? ?? ?? ?? 03 f8 8b cf 48 83 c1 08 48 3b cb 77 26 48 8d 56 08 44 8b c0 41 8b cf 49 03 d6 e8 ?? ?? ?? ?? 83 c7 08 3b fb 72 b9}  //weight: 1, accuracy: Low
        $x_1_2 = {73 79 73 6e 61 74 69 76 65 [0-8] 2c [0-8] 25 73 20 28 61 64 6d 69 6e 29 [0-8] 48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b}  //weight: 1, accuracy: Low
        $x_1_3 = {44 09 30 09 25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 09 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

