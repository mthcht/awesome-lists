rule Backdoor_Win32_Plugx_A_2147657370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.A"
        threat_id = "2147657370"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64 74}  //weight: 5, accuracy: High
        $x_5_2 = {75 61 6c 41 c7 [0-16] 6c 6c 6f 63}  //weight: 5, accuracy: Low
        $x_5_3 = {45 78 69 74 c7 85 ?? ff ff ff 54 68 72 65 66 c7 85 ?? ff ff ff 61 64}  //weight: 5, accuracy: Low
        $x_5_4 = {03 d3 c1 e7 09 bb 44 44 44 44}  //weight: 5, accuracy: High
        $x_5_5 = {c7 06 47 55 4c 50 89 4e 14 8b 47 28}  //weight: 5, accuracy: High
        $x_2_6 = {5c 00 62 00 75 00 67 00 2e 00 6c 00 6f 00 67 00 00 00}  //weight: 2, accuracy: High
        $x_2_7 = "/Software\\CLASSES\\FAST\\PROXY" wide //weight: 2
        $x_2_8 = "/update?id=%8.8x" ascii //weight: 2
        $x_2_9 = "\\\\.\\PIPE\\RUN_AS_USER" wide //weight: 2
        $x_2_10 = "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d:" wide //weight: 2
        $x_2_11 = "ShellT2" ascii //weight: 2
        $x_2_12 = "TelnetT2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Plugx_A_2147657370_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.A"
        threat_id = "2147657370"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64 74}  //weight: 2, accuracy: High
        $x_2_2 = {75 61 6c 41 c7 85 ?? ff ff ff 6c 6c 6f 63}  //weight: 2, accuracy: Low
        $x_2_3 = {45 78 69 74 c7 85 ?? ff ff ff 54 68 72 65 66 c7 85 ?? ff ff ff 61 64}  //weight: 2, accuracy: Low
        $x_1_4 = "XPlgLoader" ascii //weight: 1
        $x_1_5 = "XPlugKeyLogger" ascii //weight: 1
        $x_1_6 = "\\shellcode\\shellcode\\XPlug" ascii //weight: 1
        $x_1_7 = "/update?id=%8.8x" ascii //weight: 1
        $x_1_8 = "\\\\.\\PIPE\\RUN_AS_USER" wide //weight: 1
        $x_1_9 = "\\msiexec.exe UAC" wide //weight: 1
        $x_1_10 = "/Software\\CLASSES\\FAST\\PROXY" wide //weight: 1
        $x_1_11 = {6b 00 6c 00 2e 00 6c 00 6f 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {25 00 73 00 5c 00 25 00 64 00 2e 00 70 00 6c 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {5c 00 62 00 75 00 67 00 2e 00 6c 00 6f 00 67 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Plugx_C_2147663455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.C"
        threat_id = "2147663455"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 00 00 00 00 78 62 69 6e 30 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 33 c0 b1 ?? 8a 98 ?? ?? ?? 00 32 d9 88 98 ?? ?? ?? 00 40 3d ?? ?? 00 00 72 ea}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 10 00 00 68 ?? ?? 00 00 6a 00 ff d3 8b f0 56 68 ?? ?? 00 00 68 ?? ?? 40 00 e8 67 fa ff ff 8b f8 6a 40 68 00 10 00 00 57 6a 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Plugx_H_2147684715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.H"
        threat_id = "2147684715"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 48 56 31 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 48 56 32 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 48 56 33 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 48 56 34 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {46 4b 2d 31 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {46 4b 2d 32 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {46 4b 2d 33 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {46 4b 2d 34 00 00}  //weight: 1, accuracy: High
        $x_1_9 = "%AUTO%\\screen" wide //weight: 1
        $x_1_10 = "%AUTO%\\XXX-SCREEN" wide //weight: 1
        $x_10_11 = {66 83 3b 25 56 57 75 ?? 66 83 7b 02 41 75 ?? 66 83 7b 04 55 75 ?? 66 83 7b 06 54 75 ?? 66 83 7b 08 4f 75 ?? 66 83 7b 0a 25}  //weight: 10, accuracy: Low
        $x_10_12 = {80 3c 07 44 75 ?? 80 7c 07 01 5a 75 ?? 80 7c 07 02 4a 75 ?? 80 7c 07 03 53}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Plugx_A_2147684941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.gen!A"
        threat_id = "2147684941"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 30 80 e9 ?? 80 f1 ?? 80 c1 ?? 88 0c 30 40 3b c3 76 ec ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 06 68 b0 ff 88 46 01 88 46 02 88 46 03 88 46 04 c6 46 05 68 b8 ?? ?? ?? ?? 88 46 06 b8 ?? ?? ?? ?? c1 e8 08 88 46 07 b9 ?? ?? ?? ?? c1 e9 10 88 4e 08 ba ?? ?? ?? ?? c1 ea 18 88 56 09 8d 44 24 ?? 50 c6 46 0a c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Plugx_I_2147686804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.I"
        threat_id = "2147686804"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6d 6d 46 75 6e 63 2e 64 6c 6c 00 47 65 74 49 6e 73 74 50 61 74 68 00 48 69 64 65 45 78 65 63 75 74 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "CommFunc.jax" wide //weight: 1
        $x_1_3 = {0f b7 45 ec 0f b7 4d ee 6b c0 64 03 c1 0f b7 4d f2 6b c0 64 03 c1 3d 0f 51 33 01}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 00 00 80 57 ff 15 ?? ?? 00 10 83 f8 ff 74 2f 56 8d 4d fc 51 53 57 50 ff 15 ?? ?? 00 10 85 c0 74 1d 53 56 57 6a 00 ff 55 ?? 5f 5e 5f 8b 35 ?? ?? 00 10 6a ff ff d6 6a ff ff d6 6a ff ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Plugx_B_2147686805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.gen!B"
        threat_id = "2147686805"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64 74}  //weight: 1, accuracy: High
        $x_1_2 = {75 61 6c 41 c7 [0-16] 6c 6c 6f 63}  //weight: 1, accuracy: Low
        $x_1_3 = {45 78 69 74 c7 85 ?? ff ff ff 54 68 72 65 66 c7 85 ?? ff ff ff 61 64}  //weight: 1, accuracy: Low
        $x_2_4 = {03 d3 c1 e7 09 bb 44 44 44 44}  //weight: 2, accuracy: High
        $x_1_5 = {c7 06 47 55 4c 50}  //weight: 1, accuracy: High
        $x_1_6 = "\\\\.\\PIPE\\RUN_AS_USER" wide //weight: 1
        $x_1_7 = "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d" wide //weight: 1
        $x_2_8 = {4b 65 79 4c 6f 67 00 00 4b 4c 50 72 6f 63 00}  //weight: 2, accuracy: High
        $x_1_9 = "XPlgLoader" ascii //weight: 1
        $x_1_10 = "XPlugKeyLogger" ascii //weight: 1
        $x_3_11 = "\\shellcode\\shellcode\\XPlug" ascii //weight: 3
        $x_1_12 = "/update?id=%8.8x" ascii //weight: 1
        $x_1_13 = {53 00 78 00 53 00 00 00 53 00 78 00 53 00 00 00 62 00 6f 00 6f 00 74 00 2e 00 63 00 66 00 67 00}  //weight: 1, accuracy: High
        $x_1_14 = "TelnetT2" ascii //weight: 1
        $x_1_15 = {50 6c 75 67 50 72 6f 63 00}  //weight: 1, accuracy: High
        $x_1_16 = {25 00 73 00 5c 00 25 00 64 00 2e 00 70 00 6c 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = {25 00 73 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 20 00 55 00 41 00 43 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = "LdrLoadShellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Plugx_A_2147686806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.A!!Plugx.gen!B"
        threat_id = "2147686806"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "Plugx: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64 74}  //weight: 1, accuracy: High
        $x_1_2 = {75 61 6c 41 c7 [0-16] 6c 6c 6f 63}  //weight: 1, accuracy: Low
        $x_1_3 = {45 78 69 74 c7 85 ?? ff ff ff 54 68 72 65 66 c7 85 ?? ff ff ff 61 64}  //weight: 1, accuracy: Low
        $x_2_4 = {03 d3 c1 e7 09 bb 44 44 44 44}  //weight: 2, accuracy: High
        $x_1_5 = {c7 06 47 55 4c 50}  //weight: 1, accuracy: High
        $x_1_6 = "\\\\.\\PIPE\\RUN_AS_USER" wide //weight: 1
        $x_1_7 = "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d" wide //weight: 1
        $x_2_8 = {4b 65 79 4c 6f 67 00 00 4b 4c 50 72 6f 63 00}  //weight: 2, accuracy: High
        $x_1_9 = "XPlgLoader" ascii //weight: 1
        $x_1_10 = "XPlugKeyLogger" ascii //weight: 1
        $x_3_11 = "\\shellcode\\shellcode\\XPlug" ascii //weight: 3
        $x_1_12 = "/update?id=%8.8x" ascii //weight: 1
        $x_1_13 = {53 00 78 00 53 00 00 00 53 00 78 00 53 00 00 00 62 00 6f 00 6f 00 74 00 2e 00 63 00 66 00 67 00}  //weight: 1, accuracy: High
        $x_1_14 = "TelnetT2" ascii //weight: 1
        $x_1_15 = {50 6c 75 67 50 72 6f 63 00}  //weight: 1, accuracy: High
        $x_1_16 = {25 00 73 00 5c 00 25 00 64 00 2e 00 70 00 6c 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = {25 00 73 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 20 00 55 00 41 00 43 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = "LdrLoadShellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Plugx_2147687509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx"
        threat_id = "2147687509"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nv.mp3" wide //weight: 1
        $x_1_2 = {68 2c 20 00 10 8d 04 45 0a 30 00 10 50 ff 15 04 20 00 10 6a 40 68 00 10 00 00 bf 00 00 10 00 57 53 ff 15 08 20 00 10 3b c3 89 45 fc 74 41 53 53 6a 03 53 6a 01 68 00 00 00 80 56 ff 15 0c 20 00 10 83 f8 ff 74 29 53 8d 4d f8 51 57 ff 75 fc 50 ff 15 10 20 00 10 85 c0 74 15 ff 55 fc 8b 35 14 20 00 10 6a ff ff d6 6a ff ff d6 6a ff ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Plugx_K_2147688609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.K!dha"
        threat_id = "2147688609"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "120"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {8b 45 f8 35 09 06 86 19 50}  //weight: 100, accuracy: High
        $x_10_2 = "Config.wav" wide //weight: 10
        $x_10_3 = "{B28E0E78-882D-403c-AF4E-BDEC9C8FA37B}" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Plugx_K_2147688609_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.K!dha"
        threat_id = "2147688609"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Can't find Func 0x%x in %s!" ascii //weight: 1
        $x_1_2 = {00 53 76 63 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 8b c4 5d 63 56 a3 ?? ?? ?? ?? e8 ?? ?? ff ff 68 b2 bb 55 3a 56 a3 ?? ?? ?? ?? e8 ?? ?? ff ff 68 5a 6e db db 56 a3 ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 4f 01 47 84 c9 75 f8 8b c8 c1 e9 02 8b f2 f3 a5 8b c8 83 e1 03 8d 85 ?? ?? ?? ?? f3 a4 8d 48 01 8a 10 40 84 d2 75 ?? 2b c1 80 ?? ?? ?? ?? ?? ff 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Plugx_M_2147690074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.M"
        threat_id = "2147690074"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Release\\shellcode.pdb" ascii //weight: 1
        $x_1_2 = "shellcode.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Plugx_N_2147691932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.N!dha"
        threat_id = "2147691932"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 8a 04 13 32 01 83 f8 00 75 0e 83 fa 00 74 04 49 4a}  //weight: 1, accuracy: High
        $x_1_2 = "rundll32 \"%s\" ActiveQvaw \"%s\"" ascii //weight: 1
        $x_1_3 = "rundll32 \"%s\" Play \"%s\"" ascii //weight: 1
        $x_1_4 = "Self Process Id:%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Plugx_O_2147693884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.O!dha"
        threat_id = "2147693884"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {75 36 80 78 01 65 75 30 80 78 02 74 75 2a 80 78 03 50 75 24 80 78 04 72 75 1e 80 78 05 6f 75 18 80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64}  //weight: 2, accuracy: High
        $x_1_2 = {b0 d0 03 00 01 0d 81 10 30 00 10 3c 10 63 3d 04 30 00 10 00 70 05 36 c6 56 56 c7 40 04 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 0d 00 30 00 10 8d 81 10 30 00 10 83 c1 09 c7 00 52 65 61 64 c7 40 04 46 69 6c 65 89 7d f8 88 58 08 89 0d 00 30 00 10 39 1d 04 30 00 10 75 27}  //weight: 1, accuracy: High
        $x_1_4 = {c7 00 6c 73 74 72 c7 40 04 63 70 79 57 88 58 08 89 0d 00 30 00 10 39 1d 04 30 00 10 75 25 64 8b 0d 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {ff d6 6a 00 6a 00 6a 00 88 5f 01 ff d6 6a 00 6a 00 6a 00 88 7f 02 ff d6 8a 55 fe 6a 00 6a 00 6a 00 88 57 03 ff d6 8a 45 ff}  //weight: 1, accuracy: High
        $x_1_6 = {0f b7 4d e8 0f b7 55 ea 6b c9 64 0f b7 45 ee 03 ca 6b c9 64 03 c8 81 f9}  //weight: 1, accuracy: High
        $x_1_7 = {2b c3 89 45 f0 c7 45 f4 08 00 00 00 6a 00 6a 00 6a 00 ff d6 8b 55 f0 8a 04 1a ff 05 00 30 00 10 2c 6b 6a 00 34 3f 6a 00 04 6b 6a 00 88 03 ff d6}  //weight: 1, accuracy: High
        $x_1_8 = {8b 4d f8 8b 41 24 8b 55 fc 8b 49 1c 8d 14 50 8b 45 f4 0f b7 14 02 8d 14 91 8b 34 02 03 f0 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Plugx_S_2147696304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.S!dha"
        threat_id = "2147696304"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 3a 5c 6c 6f 67 5c 68 61 68 61 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 00 69 00 6e 00 73 00 69 00 64 00 65 00 73 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 49 6e 74 65 6c 6c 6f 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 00 66 00 20 00 79 00 6f 00 75 00 20 00 73 00 65 00 65 00 20 00 6d 00 65 00 20 00 2c 00 74 00 68 00 65 00 20 00 75 00 61 00 63 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 20 00 70 00 61 00 73 00 74 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 00 34 00 2e 00 34 00 64 00 2d 00 25 00 32 00 2e 00 32 00 64 00 2d 00 25 00 32 00 2e 00 32 00 64 00 20 00 25 00 32 00 2e 00 32 00 64 00 3a 00 25 00 32 00 2e 00 32 00 64 00 3a 00 25 00 32 00 2e 00 32 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {58 50 6c 75 67 4b 65 79 4c 6f 67 67 65 72 2e 63 70 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {75 70 64 61 74 65 3f 69 64 3d 25 38 2e 38 78 00}  //weight: 1, accuracy: High
        $x_1_8 = {5b 00 25 00 30 00 2e 00 34 00 64 00 2d 00 25 00 30 00 2e 00 32 00 64 00 2d 00 25 00 30 00 2e 00 32 00 64 00 5d 00 2d 00 5b 00 25 00 30 00 2e 00 32 00 64 00 3a 00 25 00 30 00 2e 00 32 00 64 00 3a 00 25 00 30 00 2e 00 32 00 64 00 5d 00 20 00 65 00 72 00 63 00 6f 00 64 00 65 00 3d 00 25 00 30 00 2e 00 38 00 64 00 20 00 70 00 69 00 64 00 3d 00 25 00 30 00 2e 00 38 00 64 00 20 00 74 00 69 00 64 00 3d 00 25 00 30 00 2e 00 38 00 64 00 20 00 7c 00 7c 00 25 00 25 00 73 00 7c 00 7c 00 25 00 53 00 3d 00 3e 00 25 00 30 00 2e 00 38 00 64 00 20 00 65 00 72 00 69 00 6e 00 66 00 6f 00 3d 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Plugx_T_2147697307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.T"
        threat_id = "2147697307"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 45 e8 0f b7 4d ea 6b c0 64 03 c1 0f b7 4d ee 6b c0 64 03 c1 3d 50 50 33 01 0f 8c ab 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f b6 c0 66 01 05 ?? ?? ?? ?? b8 40 42 0f 00 66 0f b6 c1 66 01 05 ?? ?? ?? ?? 88 4e 01 b8 00 e1 f5 05}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 00 63 00 55 00 74 00 69 00 6c 00 2e 00 64 00 6c 00 6c 00 2e 00 70 00 69 00 6e 00 67 00 00 00 43 72 65 00 61 74 65 00 46 69 6c 00 65 57 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Plugx_J_2147707049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.J!dha"
        threat_id = "2147707049"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "123"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {41 81 f3 27 05 86 19 44 89 9c 24 [0-2] 00 00 8b d3 89 5c 24 58 3b 94 24 [0-2] 00 00 73 1e 8b ca 42 0f be 04 29 41 33 c3 42 88 04 29 ff c2 89 54 24 [0-1] 44 8b 9c 24 [0-2] 00 00 eb}  //weight: 100, accuracy: Low
        $x_10_2 = "Config.wav" wide //weight: 10
        $x_10_3 = "{B28E0E78-882D-403c-AF4E-BDEC9C8FA37B}" ascii //weight: 10
        $x_1_4 = "SCD LoadServer" ascii //weight: 1
        $x_1_5 = {44 72 76 48 61 73 68 00}  //weight: 1, accuracy: High
        $x_1_6 = {44 72 76 43 6f 64 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 72 76 48 61 73 68 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 72 76 43 6f 64 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Plugx_AC_2147712565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.AC"
        threat_id = "2147712565"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\CLASSES\\MJ\\PROXY" wide //weight: 1
        $x_1_2 = "Global\\DelSelf(%8.8X)" wide //weight: 1
        $x_1_3 = "\\work\\plug4.0(shellcode)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Plugx_L_2147712599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.L!dha"
        threat_id = "2147712599"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 58 2d 53 6e 00}  //weight: 5, accuracy: High
        $x_5_2 = {00 58 2d 53 69 7a 65 00}  //weight: 5, accuracy: High
        $x_5_3 = {00 58 2d 53 65 73 73 69 6f 6e 00}  //weight: 5, accuracy: High
        $x_1_4 = "CXSalvation::SalEnable" wide //weight: 1
        $x_1_5 = "\\\\.\\PIPE\\RUN_AT_SESSION(%d)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Plugx_L_2147712599_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.L!dha"
        threat_id = "2147712599"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 58 56 00 00 8b d1 66 3b 10 74 07 6a 0f e9 7c 02 00 00 8b 70 3c 03 f0 39 0e 74 07}  //weight: 1, accuracy: High
        $x_1_2 = {81 78 1c 18 00 1a 00 74 08 8b 00 85 c0 75 f1}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 00 25 ff 0f 00 00 03 01 03 c7 89 45 ec 33 c0 89 45 f4 8b c7 99 8b f8 2b 7e 34}  //weight: 1, accuracy: High
        $x_1_4 = {c1 ea 18 32 54 0e 04 8b 4d 08 c1 e9 10 32 d1 8b 4d 08 c1 e9 08 32 d1 32 55 08 88 14 37}  //weight: 1, accuracy: High
        $x_1_5 = {8b 46 04 c6 00 e9 8b 46 04 88 58 01 8b 4e 04 8b c3 c1 e8 08}  //weight: 1, accuracy: High
        $x_1_6 = {80 7c 38 14 a3 75 07 80 7c 38 19 e8 74 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Plugx_Z_2147723848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.Z"
        threat_id = "2147723848"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64 74}  //weight: 1, accuracy: High
        $x_1_2 = {75 61 6c 41 c7 [0-16] 6c 6c 6f 63}  //weight: 1, accuracy: Low
        $x_1_3 = {45 78 69 74 c7 85 ?? ff ff ff 54 68 72 65 66 c7 85 ?? ff ff ff 61 64}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 06 47 55 4c 50}  //weight: 1, accuracy: High
        $x_1_5 = {64 3a 5c 77 6f 72 6b 5c 50 6c 75 67 33 2e 30 28 47 66 29 [0-4] 5c 53 68 65 6c 6c 36 5c 52 65 6c 65 61 73 65 5c 53 68 65 6c 6c 36 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Plugx_AB_2147730069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plugx.AB"
        threat_id = "2147730069"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cookies: Sym1.0" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\1[12345678]" wide //weight: 1
        $x_1_3 = "\\\\.\\pipe\\2[12345678]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

