rule VirTool_Win32_CobaltStrike_A_2147756521_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.A"
        threat_id = "2147756521"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 5b 52 45 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 89 c3 57 68 04 00 00 00 50 ff d0 68 f0 b5 a2 56 68 05 00 00 00 50 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CobaltStrike_A_2147756521_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.A"
        threat_id = "2147756521"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3d 00 10 00 00 0d 00 80 b0 ?? ?? ?? ?? 2e 40}  //weight: 5, accuracy: Low
        $x_1_2 = {89 10 89 50 04 89 48 08 89 48 0c c3}  //weight: 1, accuracy: High
        $x_1_3 = {83 7e 08 04 73 03 33 c0 c3 8b 46 04 ff 30 e8 ?? ?? ?? ?? 83 46 04 04 83 46 08 fc c3}  //weight: 1, accuracy: Low
        $x_1_4 = {83 7e 08 02 73 03 33 c0 c3 8b 46 04 0f b7 00 50 e8 ?? ?? ?? ?? 83 46 04 02 83 46 08 fe 0f b7 c0 c3}  //weight: 1, accuracy: Low
        $x_5_5 = {8b 07 8b 57 04 83 c7 08 85 c0 75 2c}  //weight: 5, accuracy: High
        $x_5_6 = {8b 06 8b 56 04 83 c6 08 85 c0 75 23}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CobaltStrike_A_2147756521_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.A"
        threat_id = "2147756521"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 01 6a 02 e8 [0-48] 6a 02 58 ff 75 08 66 89 45 ec e8 [0-64] 6a 78 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55}  //weight: 1, accuracy: High
        $x_1_5 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CobaltStrike_A_2147756521_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.A"
        threat_id = "2147756521"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81 c3 ?? ?? 00 00 ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55}  //weight: 1, accuracy: High
        $x_1_5 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CobaltStrike_A_2147756521_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.A"
        threat_id = "2147756521"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26}  //weight: 1, accuracy: High
        $x_1_2 = {eb 86 5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 31 ff 57 57 57 57 57 68 3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {eb 86 5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 [0-8] 50 68 ea 0f df e0 ff d5}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 86 5d 31 c0 6a 40 b4 10 68 00 10 00 00 68 ff ff 07 00 6a 00 68 58 a4 53 e5 ff d5 83 c0 40 89 c7 50 31 c0 b0 70 b4 69 50 68 64 6e 73 61 54 68 4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {68 58 a4 53 e5 ff d5 50 e9 a8 00 00 00 5a 31 c9 51 51 68 00 b0 04 00 68 00 b0 04 00 6a 01 6a 06 6a 03 52 68 45 70 df d4 ff d5 50 8b 14 24 6a 00 52 68 28 6f 7d e2 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_CobaltStrike_STC_2147767397_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.STC"
        threat_id = "2147767397"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14}  //weight: 1, accuracy: High
        $x_1_2 = {2f 70 6f 73 74 73 2f [0-16] 2f 69 76 63 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {e9 91 01 00 00 e9 c9 01 00 00 e8 8b ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {68 6e 65 74 00 68 77 69 6e 69 ?? 68 4c 77 26 07 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CobaltStrike_B_2147773432_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.B"
        threat_id = "2147773432"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91 74}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55}  //weight: 1, accuracy: High
        $x_1_4 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da}  //weight: 1, accuracy: High
        $x_1_5 = {83 c4 10 33 c0 80 b0 ?? ?? ?? ?? 69 40 3d 00 10 00 00 7c f1 68 00 10 00 00 b9 ?? ?? ?? ?? 8d 44 24 14 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {62 65 61 63 6f 6e [0-4] 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_7 = "ReflectiveLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CobaltStrike_C_2147773434_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.C"
        threat_id = "2147773434"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5b bc 4a 6a 0f 85 ?? 00 00 00 8b}  //weight: 10, accuracy: Low
        $x_10_2 = {8e 4e 0e ec 74 [0-3] aa fc 0d 7c 74 [0-3] 54 ca af 91 75}  //weight: 10, accuracy: Low
        $x_10_3 = {b8 0a 4c 53 75}  //weight: 10, accuracy: High
        $x_10_4 = {68 00 30 00 00 0a 00 6a 40 10 00 8b ?? 3c}  //weight: 10, accuracy: Low
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
        $x_1_22 = "\\\\.\\pipe\\elevate" ascii //weight: 1
        $x_1_23 = "[*] %s loaded in userspace" ascii //weight: 1
        $x_1_24 = "\\\\.\\pipe\\hashdump" ascii //weight: 1
        $x_1_25 = "Global\\SAM" ascii //weight: 1
        $x_1_26 = "\\\\.\\pipe\\portscan" ascii //weight: 1
        $x_1_27 = {5c 5c 25 73 5c 69 70 63 24 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 22 of ($x_1_*))) or
            ((4 of ($x_10_*) and 12 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_CobaltStrike_F_2147773438_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.F!entry"
        threat_id = "2147773438"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "entry: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 5a 52 45 e8 00 00 00 00 5b 89 df 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_CobaltStrike_G_2147773439_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.G"
        threat_id = "2147773439"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 5b 89 df 52 45 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 68 f0 b5 a2 56 68 04 00 00 00 57 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 57 6a 00 ff 75 08 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8d 45 fc 50 57 ff 75 f8 56 ff 75 08 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CobaltStrike_H_2147781998_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.H"
        threat_id = "2147781998"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d 08 8b 75 0c 8b 55 10 39 f0 7d 0e 89 c1 83 e1 03 8a 0c 0a 30 0c 03 40 eb ee 89 1c 24}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CobaltStrike_H_2147781998_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.H"
        threat_id = "2147781998"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 0c c7 44 24 0c 04 00 00 00 c7 44 24 08 00 30 00 00 c7 04 24 00 00 00 00 89 74 24 04 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 08 20 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 10 89 5c 24 0c c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 08 ?? ?? ?? ?? c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CobaltStrike_H_2147781998_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.H"
        threat_id = "2147781998"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d 08 c7 44 24 10 04 00 00 00 c7 44 24 0c 00 10 00 00 8d 87 80 00 00 00 89 44 24 08 c7 44 24 04 00 00 00 00 89 1c 24 ff 15 ?? ?? ?? ?? 83 ec 14 89 c6 8d 45 e0 89 44 24 10 8b 45 1c 89 7c 24 0c 89 74 24 04 89 1c 24 89 44 24 08 ff 15 ?? ?? ?? ?? 8b 45 e0 83 ec 14 39 f8 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
        $x_1_4 = {89 c6 83 ec 10 31 c0 39 d8 7d ?? 8b 4d 10 89 c2 83 e2 03 8a 14 11 8b 4d 08 32 14 01 88 14 06 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_CobaltStrike_I_2147782908_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobaltStrike.I"
        threat_id = "2147782908"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 3e 8b 5c 3e 04 50 e8 ?? ?? ?? ?? 53 89 45 f8 e8 ?? ?? ?? ?? 8d 5c 30 08 3b 5d 08 77 23 8b d0 8b 45 f8 8d 4c 3e 08 e8 ?? ?? ?? ?? 8b f3 3b 75 08 72 cc}  //weight: 1, accuracy: Low
        $x_1_2 = {73 79 73 77 6f 77 36 34 [0-8] 2c [0-8] 25 73 20 28 61 64 6d 69 6e 29 [0-8] 48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b}  //weight: 1, accuracy: Low
        $x_1_3 = {44 09 30 09 25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 09 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

