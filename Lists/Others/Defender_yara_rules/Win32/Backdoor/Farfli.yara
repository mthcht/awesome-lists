rule Backdoor_Win32_Farfli_A_2147595048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.A"
        threat_id = "2147595048"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_7_1 = ".farfly.org/tj/" ascii //weight: 7
        $x_3_2 = "Now is the time for all" ascii //weight: 3
        $x_3_3 = "what do ya want for nothing?" ascii //weight: 3
        $x_1_4 = "SOFTWARE\\Microsoft\\IE4\\" ascii //weight: 1
        $x_1_5 = ".txt?" ascii //weight: 1
        $x_3_6 = "setupid=%d&mac=%s" ascii //weight: 3
        $x_3_7 = "&type=%d&version=" ascii //weight: 3
        $x_3_8 = "&td_rd=%d&hp_1=%s" ascii //weight: 3
        $x_1_9 = "\\\\.\\Global\\ClanAvb" ascii //weight: 1
        $x_1_10 = "Explorer_Server" ascii //weight: 1
        $x_3_11 = "43f69cc9-8007-4b" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_7_*) and 4 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_B_2147595049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.B"
        threat_id = "2147595049"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 08 56 8b f1 89 06 8b 44 24 08 85 c0 74 02 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {f3 a5 8b cd 83 e1 03 85 d2 f3 a4}  //weight: 1, accuracy: High
        $x_1_3 = {8b 74 24 0c 57 56 ff 96 68 01 00 00 8b f8 8d 46 20 50 ff 96 68 01 00 00 8d 4e 60 8b d8 51 ff 96 68 01}  //weight: 1, accuracy: High
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_1_6 = {46 08 89 06 f7 d8 1b c0 25 05 01 00 00 89 46 04 46}  //weight: 1, accuracy: High
        $x_1_7 = {66 c7 44 24 18 58 02 89 4c 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Farfli_C_2147596695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.C"
        threat_id = "2147596695"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {68 00 00 01 c0 ff 75 08 ff 15 ?? ?? 40 00 8b f0 83 fe ff 75 04 33 c0 eb 1d 8d 45 f0 50 8d 45 e8 50 8d 45 e0 50}  //weight: 4, accuracy: Low
        $x_4_2 = {80 c9 ff 2a 08 47 3b fe 88 08 72 ee 33 ff}  //weight: 4, accuracy: High
        $x_4_3 = {b9 ff 00 00 00 2b c8 8b 85 ?? ?? ff ff 88 88 ?? ?? 43 00 eb c5 83 a5 ?? ?? ff ff 00 eb 0d 8b 85 ?? ?? ff ff 40 89 85}  //weight: 4, accuracy: Low
        $x_1_4 = {0f 84 08 00 00 00 0f 85 02 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_5 = {0f 84 0a 00 00 00 0f 85 04 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_6 = {0f 84 0e 00 00 00 0f 85 08 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_7 = {0f 84 14 00 00 00 0f 85 0e 00 00 00 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_C_2147596695_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.C"
        threat_id = "2147596695"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 00 01 c0 ff 75 08 ff 15 ?? ?? 40 00 8b f0 83 fe ff 75 04 33 c0 eb 1d 8d 45 f0 50 8d 45 e8 50 8d 45 e0 50}  //weight: 10, accuracy: Low
        $x_10_2 = {33 f6 56 56 56 56 56 ff 74 ?? ?? 6a 01 6a 03 6a 01 68 ff 01 0f 00 ff 74 24 ?? ff 74 24 ?? ff 74 24 ?? ff 15 ?? ?? ?? 00 3b c6 5e 75 03 33 c0 c3 50 ff 15 ?? ?? ?? 00 6a 01 58 c3 57 68 ff 01 0f 00}  //weight: 10, accuracy: Low
        $x_1_3 = "StartServiceA" ascii //weight: 1
        $x_1_4 = "(C) Microsoft Corporation. All rights reserved." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_D_2147596696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.D"
        threat_id = "2147596696"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {68 00 00 01 c0 ff 75 08 ff 15 ?? ?? 40 00 89 85 d0 fd ff ff 83 bd d0 fd ff ff ff 75 04 33 c0 eb 30 8d 85 ec fe ff ff}  //weight: 4, accuracy: Low
        $x_4_2 = {80 c9 ff 2a 08 47 3b fe 88 08 72 ee 33 ff}  //weight: 4, accuracy: High
        $x_4_3 = {b9 ff 00 00 00 2b c8 8b 85 ?? ?? ff ff 88 88 ?? ?? 43 00 eb c5 83 a5 ?? ?? ff ff 00 eb 0d 8b 85 ?? ?? ff ff 40 89 85}  //weight: 4, accuracy: Low
        $x_1_4 = {0f 84 08 00 00 00 0f 85 02 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_5 = {0f 84 0a 00 00 00 0f 85 04 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_6 = {0f 84 0e 00 00 00 0f 85 08 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_7 = {0f 84 14 00 00 00 0f 85 0e 00 00 00 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_A_2147601358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.A"
        threat_id = "2147601358"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 59 83 65 d8 00 59 c7 45 dc 01 00 00 00 6a 04 c7 45 e0 02 00 00 00 59 c7 45 e4 03 00 00 00 89 4d e8 c7 45 ec 05 00 00 00 c7 45 f0 06 00 00 00 c7 45 f4 07 00 00 00 c7 45 f8 08 00 00 00 c7 45 fc 09 00 00 00 8d 45 d8 03 c1 8d 55 00 3b c2 75 f7 68 ?? ?? ?? ?? e8 ?? ?? 00 00 59 50 68 ?? ?? ?? ?? ff d6 8b 35 ?? ?? ?? ?? 59 59 6a 64 ff d6 8d 45 d0 50 e8 ?? ?? ff ff 59 ff 75 14 ff 75 10 ff 75 0c ff 75 08}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 80 ee 00 00 00 c5 0f 84 ?? ?? 00 00 0f 85 ?? ?? 00 00 eb 02 68 ?? ?? ?? ?? 8d 8d ?? ?? ff ff e8 ?? ?? ff ff 8d 8d ?? ?? ff ff e8 ?? ?? ff ff 8b 45 08 c6 80 ef 00 00 00 19 6a 18 ff 15 ?? ?? ?? ?? 59 c7 45 fc 31 00 00 00 68 ?? ?? ?? ?? 8d 8d ?? ?? ff ff e8 ?? ?? ff ff 89 85 ?? ?? ff ff c6 45 fc 32}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 83 ec 10 e8 ?? ?? ff ff 83 78 10 02 75 ?? e8 ?? ?? ff ff 83 78 04 05 72 ?? e8 ?? ?? ff ff 83 78 08 01 75 ?? 8d 45 fc 53 33 db 50 6a 01 53 68 ?? ?? ?? ?? 68 02 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 8d 45 f8 c7 45 f8 04 00 00 00 50 8d 45 f4 50 8d 45 f0 50 53 68 ?? ?? ?? ?? ff 75 fc ff 15 ?? ?? ?? ?? 85 c0 75 08 83 7d f4 01 75 02 b3 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Farfli_E_2147601600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.E!dll"
        threat_id = "2147601600"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e 11 8a 04 32 3c 22 74 05 2c ?? 88 04 32 42 3b d1 7c ef 8b c6 5e c2 04 00}  //weight: 10, accuracy: Low
        $x_5_2 = {68 24 0c 0b 83 56 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_E_2147606302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.E"
        threat_id = "2147606302"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attrib \"C:\\myapp.exe\" -r -a -s -h" ascii //weight: 1
        $x_1_2 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_3 = "360TraY.exe" ascii //weight: 1
        $x_1_4 = "SeRestorePrivilege" ascii //weight: 1
        $x_1_5 = "soul*exe" ascii //weight: 1
        $x_1_6 = "software\\Microsoft\\Windows\\CurrentVersion\\exploRER\\ShellexecuteHooks" ascii //weight: 1
        $x_1_7 = {52 61 76 6d 6f 6e 64 2e 65 78 65 00 61 76 70 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_G_2147606747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.G"
        threat_id = "2147606747"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 44 24 0c 6a 10 5f 8d 0c 06 8b c6 99 f7 ff 8b 44 24 10 8a 04 02 32 01 34 ?? 46 3b 74 24 14 88 01 7c dd}  //weight: 3, accuracy: Low
        $x_3_2 = {7e 44 8b 45 08 33 c9 39 4d f8 8a 04 06 7e 10 8a 14 0b 32 d0 80 f2 ?? 41 3b 4d f8 8a c2 7c f0}  //weight: 3, accuracy: Low
        $x_3_3 = {74 1d 8d 85 d8 fe ff ff 50 57 e8 ?? ?? 00 00 85 c0 74 12 8d 85 fc fe ff ff 50 ff 75 08 eb db 8b 9d e0 fe ff ff 57}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Farfli_H_2147606855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.H"
        threat_id = "2147606855"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "71"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 70 79 46 69 6c 65 41 [0-4] 57 69 6e 45 78 65 63 [0-4] 4f 70 65 6e 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
        $x_40_2 = {8d 85 fc fe ff ff 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 59 59 83 7d 0c 00 56 be ?? ?? 40 00 75 05 be ?? ?? 40 00 83 7d 0c 00 b8 ?? ?? 40 00 75 05 b8 ?? ?? 40 00 50 b8 ?? ?? 40 00 68 ?? ?? 40 00 50 50 8d 85 fc fe ff ff 50 68 ?? ?? 40 00 56 ff 15 ?? ?? 40 00 83 c4 1c 8b c6 5e c9 c3}  //weight: 40, accuracy: Low
        $x_10_3 = {7d 00 00 5c 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 45 52 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 00 00 00 00 54 68 72 65 61 64 69 6e 67 4d 6f 64 65 6c 00 00 41 70 61 72 74 6d 65 6e 74 00}  //weight: 10, accuracy: High
        $x_20_4 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 4c 6f 6f 70 0d 0a 61 74 74 72 69 62 20 22 25 73 22 20 2d 72 20 2d 61 20 2d 73 20 2d 68 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 4c 6f 6f 70 0d 0a 64 65 6c 20 25 25 30 0d 0a}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_I_2147616654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.I"
        threat_id = "2147616654"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a c2 8b fe 2c ?? 83 c9 ff d0 e0 00 04 32 33 c0 42 f2 ae f7 d1 49 3b d1 72 e6}  //weight: 2, accuracy: Low
        $x_3_2 = {c6 45 d4 5c c6 45 d5 62 c6 45 d6 65 c6 45 d7 65 c6 45 d8 70 c6 45 d9 2e c6 45 da 73 c6 45 db 79 c6 45 dc 73}  //weight: 3, accuracy: High
        $x_2_3 = {33 c0 80 b0 ?? ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 7c f1 33 c0 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_I_2147616654_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.I"
        threat_id = "2147616654"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "shell\\open\\command" ascii //weight: 10
        $x_10_2 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 10
        $x_10_3 = {53 65 72 76 69 63 65 44 6c 6c 00}  //weight: 10, accuracy: High
        $x_10_4 = "System32\\svchost.exe -k netsvcs" ascii //weight: 10
        $x_10_5 = "Global\\Gh0st" ascii //weight: 10
        $x_1_6 = "SYSTEM\\CurrentControlSet\\Services\\BITS" ascii //weight: 1
        $x_1_7 = "\\\\.\\MINISAFEDOS" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\KasperskyLab\\WmiHlp\\{2C4D4BC6-0793-4956-A9F9-E252435469C0}" ascii //weight: 1
        $x_1_9 = "CVideoCap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_N_2147642408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.N"
        threat_id = "2147642408"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 25 5c 73 65 63 69 76 72 65 53 5c 74 65 53 6c 6f 72 74 6e 6f 43 74 6e 65 72 72 75 43 5c 4d 45 54 53 59 53 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 69 6e 64 4d 61 64 20 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 36 25 78 73 76 63 00 6e 65 74 73 76 63 73 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 65 74 53 76 63 73 00 68 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {49 6e 73 74 61 6c 6c 4d 6f 64 75 6c 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {6a 01 8d 8c 24 54 02 00 00 68 14 42 40 00 51 68 02 00 00 80 e8 56 00 00 00 56 e8 10 f8 ff ff 56 e8 26 03 00 00 53 e8 20 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Farfli_P_2147647337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.P"
        threat_id = "2147647337"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 61 63 6b 65 72 00 00 43 6c 4f 73 45}  //weight: 1, accuracy: High
        $x_1_2 = "netddos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_Q_2147647899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.Q"
        threat_id = "2147647899"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 c9 ff 33 c0 f2 ae f7 d1 49 bf ?? ?? 01 10 8b d1 83 c9 ff f2 ae f7 d1 49 8d 44 0a 01 50 e8}  //weight: 4, accuracy: Low
        $x_4_2 = {b9 81 00 00 00 33 c0 8d bc 24 1d 02 00 00 88 9c 24 1c 02 00 00 f3 ab 66 ab aa 8d 44 24 10 53 50 8d 8c 24 24 02 00 00 68 08 02 00 00 51 56 89 5c 24 24 ff 15}  //weight: 4, accuracy: High
        $x_4_3 = {f7 e3 2b da 83 c4 04 d1 eb 03 da 83 e1 03 c1 eb 05 f3 a4 0f}  //weight: 4, accuracy: High
        $x_2_4 = "zhongjie" ascii //weight: 2
        $x_2_5 = "Net-Temp.ini" ascii //weight: 2
        $x_2_6 = "c:\\NT_Path.old" ascii //weight: 2
        $x_2_7 = "My Win32 Applaction" ascii //weight: 2
        $x_2_8 = "\\syslog.dat" ascii //weight: 2
        $x_2_9 = "[%02u-%02u-%d %02u:%02u:%02u] (%s)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_R_2147649417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.R"
        threat_id = "2147649417"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Net-Temp.ini" wide //weight: 1
        $x_1_2 = "%swindows\\xinstall%d.dll" ascii //weight: 1
        $x_10_3 = "c:\\Win_lj.ini" ascii //weight: 10
        $x_10_4 = "ConneCtIOns\\pbk\\raSPHONE.pbk" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_U_2147653860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.U"
        threat_id = "2147653860"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 50 56 57 ff 15 ?? ?? ?? ?? 8b 4c 24 0c 33 c0 85 c9 76 0e 8a 14 30 80 f2 ?? 88 14 30 40 3b c1 72 f2 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 75 73 65 72 2e 64 61 74 [0-16] 42 6c 6f 63 6b 49 6e 70 75 74 [0-32] 5c 63 6d 64 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_Z_2147666527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.Z"
        threat_id = "2147666527"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 79 43 72 65 61 74 65 4d 61 00}  //weight: 1, accuracy: High
        $x_3_2 = "%s\\Parameters" ascii //weight: 3
        $x_4_3 = "[%02u-%02u-%d %02u:%02u:%02u] (%s)" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_AA_2147678441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AA"
        threat_id = "2147678441"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "270"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c6 45 e8 5c c6 45 e9 6f c6 45 ea 75 c6 45 eb 72 c6 45 ec 6c}  //weight: 100, accuracy: High
        $x_100_2 = {83 c4 0c c6 85 62 ff ff ff 55 c6 85 63 ff ff ff aa 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 c0}  //weight: 100, accuracy: High
        $x_50_3 = {c6 85 8d fe ff ff 53 c6 85 8e fe ff ff 65 c6 85 8f fe ff ff 72 c6 85 90 fe ff ff 76}  //weight: 50, accuracy: High
        $x_50_4 = {74 2e 83 bd f8 fb ff ff ff 7e 25 83 bd b4 fb ff ff 40 7e 1c 83 bd b4 fb ff ff 5b 7d 13}  //weight: 50, accuracy: High
        $x_50_5 = {ff 95 ac fb ff ff e9 69 fd ff ff e9 a8 fc ff ff 33 c0 5f 8b e5 5d c2 04 00}  //weight: 50, accuracy: High
        $x_10_6 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72}  //weight: 10, accuracy: High
        $x_30_7 = {c6 45 f0 63 c6 45 f1 61 c6 45 f2 6f c6 45 f3 6e c6 45 f4 66 c6 45 f5 7a c6 45 f6 32}  //weight: 30, accuracy: High
        $x_10_8 = {77 6f 77 2e 65 78 65 00 74 77 32 2e 65 78 65}  //weight: 10, accuracy: High
        $x_5_9 = "<H1>403 Forbidden</H1>" ascii //weight: 5
        $x_5_10 = "ttp://127.0.0.1:8888/ip.txt" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_50_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_100_*) and 3 of ($x_50_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 3 of ($x_50_*) and 1 of ($x_30_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*))) or
            ((2 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AC_2147678660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AC"
        threat_id = "2147678660"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c6 85 dc fe ff ff 61 c6 85 dd fe ff ff 76 c6 85 de fe ff ff 70 c6 85 df fe ff ff 2e c6 85 e0 fe ff ff 65}  //weight: 100, accuracy: High
        $x_100_2 = {c6 85 35 fe ff ff 75 c6 85 36 fe ff ff 63 c6 85 37 fe ff ff 6b c6 85 38 fe ff ff 33 c6 85 39 fe ff ff 36}  //weight: 100, accuracy: High
        $x_50_3 = {42 00 99 b9 19 00 00 00 f7 f9 83 c2 61 52 8d 95 64 fe ff ff 52 68}  //weight: 50, accuracy: High
        $x_50_4 = {c6 45 85 50 c6 45 86 4d c6 45 87 4f c6 45 88 4e c6 45 89 2e c6 45 8a 45 c6 45 8b 58}  //weight: 50, accuracy: High
        $x_20_5 = {c6 45 90 4d c6 45 91 58 c6 45 92 57 c6 45 93 4c c6 45 94 56 c6 45 95 49 c6 45 96 50}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AD_2147678780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AD"
        threat_id = "2147678780"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "270"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c6 45 e8 5c c6 45 e9 6f c6 45 ea 75 c6 45 eb 72 c6 45 ec 6c}  //weight: 100, accuracy: High
        $x_100_2 = {89 45 d4 66 c7 45 d8 00 00 b9 09 00 00 00 33 c0 8d 7d da f3 ab 66 ab c7 45 a4}  //weight: 100, accuracy: High
        $x_50_3 = {c6 45 f9 5c c6 45 fa 42 c6 45 fb 49 c6 45 fc 54 c6 45 fd 53}  //weight: 50, accuracy: High
        $x_50_4 = {c6 45 b0 25 c6 45 b1 73 c6 45 b2 5c c6 45 b3 2a c6 45 b4 2e c6 45 b5 2a c6 45 b6 00}  //weight: 50, accuracy: High
        $x_20_5 = {c6 85 30 fe ff ff 5c c6 85 31 fe ff ff 63 c6 85 32 fe ff ff 6d c6 85 33 fe ff ff 64}  //weight: 20, accuracy: High
        $x_20_6 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72}  //weight: 20, accuracy: High
        $x_10_7 = "<H1>403 Forbidden</H1>" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AE_2147678781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AE"
        threat_id = "2147678781"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "275"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c6 85 5c fe ff ff 4d c6 85 5d fe ff ff 58 c6 85 5e fe ff ff 57 c6 85 5f fe ff ff 4c c6 85 60 fe ff ff 56 c6 85 61 fe ff ff 49}  //weight: 100, accuracy: High
        $x_100_2 = {75 07 32 c0 e9 a9 01 00 00 c6 45 ec 05 c6 45 ed 01 c6 45 ee 00 c6 45 ef 01 8b 95 6c fc ff ff}  //weight: 100, accuracy: High
        $x_50_3 = {c6 45 90 70 c6 45 91 62 c6 45 92 6b c6 45 93 5c c6 45 94 72 c6 45 95 61 c6 45 96 73}  //weight: 50, accuracy: High
        $x_25_4 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72}  //weight: 25, accuracy: High
        $x_25_5 = "[C.a.p.s.L.o.c.k.]" ascii //weight: 25
        $x_25_6 = {c6 85 64 ff ff ff 00 b8 01 00 00 00 b8 ff ff ff ff 90 90 c6 85}  //weight: 25, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 3 of ($x_25_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_25_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AH_2147678905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AH"
        threat_id = "2147678905"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {b2 e9 d5 d2 46 57 4b 4a 47 48 ca a7 b0 dc a3 ac cd cb b3 f6 00}  //weight: 100, accuracy: High
        $x_100_2 = {c6 45 ec 46 c6 45 ed 57 c6 45 ee 4b c6 45 ef 4a 8b 55 ec 8d 8e b0}  //weight: 100, accuracy: High
        $x_20_3 = {c6 45 dc 77 c6 45 dd 61 c6 45 de 76 88 5d df}  //weight: 20, accuracy: High
        $x_20_4 = {c6 45 f4 72 c6 45 f5 65 c6 45 f6 63 c6 45 f7 76 c6 45 f8 00}  //weight: 20, accuracy: High
        $x_20_5 = {b0 65 b2 74 88 45 e9 88 45 eb 88 45 ed 88 45 f7 8d 45 e8 b1 69}  //weight: 20, accuracy: High
        $x_10_6 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72}  //weight: 10, accuracy: High
        $x_10_7 = {0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 10, accuracy: High
        $x_10_8 = {c6 45 f0 47 c6 45 f1 48 66 8b 45 f0 89 11 c7 86 a8 00 00 00 ff ff ff ff 66 89 41 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AI_2147678907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AI"
        threat_id = "2147678907"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "185"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c}  //weight: 100, accuracy: High
        $x_30_2 = {c6 45 ee 69 c6 45 ef 73 c6 45 f0 52 c6 45 f1 61 c6 45 f2 74}  //weight: 30, accuracy: High
        $x_30_3 = {8d 45 ec c6 45 ce 55 c6 45 cf aa 53 53 6a 03 53 6a 03 68 00 00 00 c0 50 c6 45 ec 5c}  //weight: 30, accuracy: High
        $x_30_4 = {c6 45 df 6e c6 45 e0 65 c6 45 e1 74 c6 45 e2 20 c6 45 e3 73 c6 45 e4 74 c6 45 e5 6f c6 45 e6 70}  //weight: 30, accuracy: High
        $x_25_5 = {c6 45 e0 23 c6 45 e1 33 c6 45 e2 32 c6 45 e3 37 c6 45 e4 37 c6 45 e5 30 88 5d e6 ff 15}  //weight: 25, accuracy: High
        $x_25_6 = {c6 45 a2 6e c6 45 a3 65 c6 45 a4 2e c6 45 a5 70 c6 45 a6 62 c6 45 a7 6b}  //weight: 25, accuracy: High
        $x_25_7 = {c6 45 f8 6e c6 45 f9 5c c6 45 fa 52 c6 45 fb 75 c6 45 fc 6e}  //weight: 25, accuracy: High
        $x_25_8 = {c6 45 f4 43 c6 45 f5 68 c6 45 f6 69 c6 45 f7 63 c6 45 f8 6b}  //weight: 25, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_30_*) and 4 of ($x_25_*))) or
            ((1 of ($x_100_*) and 4 of ($x_25_*))) or
            ((1 of ($x_100_*) and 1 of ($x_30_*) and 3 of ($x_25_*))) or
            ((1 of ($x_100_*) and 2 of ($x_30_*) and 1 of ($x_25_*))) or
            ((1 of ($x_100_*) and 3 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AJ_2147678964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AJ"
        threat_id = "2147678964"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c}  //weight: 100, accuracy: High
        $x_50_2 = {6a 14 ff d3 66 85 c0 74 20 83 7d f8 00 7d 30 83 fe 40 7e 15 83 fe 5b}  //weight: 50, accuracy: High
        $x_30_3 = {c6 45 ec 5c c6 45 ed 6f c6 45 ee 75 80 38 1e c6 45 ef 72 c6 45 f0 6c}  //weight: 30, accuracy: High
        $x_30_4 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72}  //weight: 30, accuracy: High
        $x_25_5 = {74 0b 66 81 bd ec fb ff ff 4d 5a 75 22 8d 45 ec 56}  //weight: 25, accuracy: High
        $x_25_6 = {c6 45 ec 46 c6 45 ed 57 c6 45 ee 4b c6 45 ef 4a}  //weight: 25, accuracy: High
        $x_25_7 = {c6 45 f8 6e c6 45 f9 5c c6 45 fa 52 c6 45 fb 75 c6 45 fc 6e}  //weight: 25, accuracy: High
        $x_25_8 = {c6 45 e6 55 c6 45 e7 aa 53 53 6a 03 53 6a 03 68 00 00 00 c0}  //weight: 25, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 4 of ($x_25_*))) or
            ((1 of ($x_100_*) and 4 of ($x_25_*))) or
            ((1 of ($x_100_*) and 1 of ($x_30_*) and 3 of ($x_25_*))) or
            ((1 of ($x_100_*) and 2 of ($x_30_*) and 2 of ($x_25_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_25_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_25_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AN_2147679095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AN"
        threat_id = "2147679095"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "170"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c}  //weight: 100, accuracy: High
        $x_50_2 = {b9 00 5c 26 05 33 d2 8b f9 8b f0 f7 f7 33 d2 89 45 08 8b c6 f7 f1 b9 80 ee 36 00}  //weight: 50, accuracy: High
        $x_20_3 = {a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c 53 74 61 72 74 75 70 5c 68 61 6f 35 36 37 2e 65 78 65}  //weight: 20, accuracy: High
        $x_20_4 = {c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c c6 45 f9 6f}  //weight: 20, accuracy: High
        $x_20_5 = {c6 45 c4 4b c6 45 c5 65 c6 45 c6 79 c6 45 90 41 c6 45 91 44 c6 45 92 56}  //weight: 20, accuracy: High
        $x_20_6 = {0f b7 d0 0f af 55 0c 8b 4d 10 83 c2 1f c1 fa 03 83 e2 fc c7 06 28 00 00 00 0f af d1 83 f8 10}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AO_2147679247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AO"
        threat_id = "2147679247"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "170"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "user guest ratpp && net localgroup administrators guest" ascii //weight: 100
        $x_50_2 = {c6 45 f1 49 c6 45 f2 33 c6 45 f3 32 c6 45 f4 2e c6 45 f5 64 c6 45 f6 6c c6 45 f7 6c c6 45 f8 00 68}  //weight: 50, accuracy: High
        $x_30_3 = {c6 85 05 fd ff ff 72 c6 85 06 fd ff ff 64 c6 85 07 fd ff ff 70 c6 85 08 fd ff ff 77}  //weight: 30, accuracy: High
        $x_10_4 = "COMMAND_UNPACK_RAR reve" ascii //weight: 10
        $x_10_5 = "<H1>403 Forbidden</H1>" ascii //weight: 10
        $x_20_6 = {c6 45 f2 67 c6 45 f3 6f c6 45 f4 6c c6 45 f5 6e c6 45 f6 69 c6 45 f7 57}  //weight: 20, accuracy: High
        $x_20_7 = {c6 45 f6 72 c6 45 f7 6d c6 45 f8 53 c6 45 f9 65 c6 45 fa 72 c6 45 fb 76 c6 45 fc 69}  //weight: 20, accuracy: High
        $x_20_8 = {c6 45 f6 65 c6 45 f7 2e c6 45 f8 6e c6 45 f9 69 c6 45 fa 61 c6 45 fb 4d c6 45 fc 53 c6 45 fd 44 c6 45 fe 00}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AQ_2147679273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AQ"
        threat_id = "2147679273"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c6 45 f0 63 c6 45 f1 61 c6 45 f2 6f c6 45 f3 6e c6 45 f4 66 c6 45 f5 7a c6 45 f6 32}  //weight: 100, accuracy: High
        $x_50_2 = {c6 85 34 fe ff ff 4c c6 85 35 fe ff ff 4f c6 85 36 fe ff ff 56 c6 85 37 fe ff ff 45 c6 85 38 fe ff ff 54}  //weight: 50, accuracy: High
        $x_50_3 = {c6 45 f7 5c c6 45 f8 5c c6 45 f9 42 c6 45 fa 45 c6 45 fb 45 c6 45 fc 50}  //weight: 50, accuracy: High
        $x_50_4 = {c6 85 6d ff ff ff 73 c6 85 6e ff ff ff 74 c6 85 6f ff ff ff 73 c6 85 70 ff ff ff 63 c6 85 71 ff ff ff 2e}  //weight: 50, accuracy: High
        $x_20_5 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72}  //weight: 20, accuracy: High
        $x_20_6 = {75 02 eb 3f 8b 55 fc c6 02 76 8b 45 f4 50 8b 4d f0 51 8b 55 fc 83 c2 01}  //weight: 20, accuracy: High
        $x_10_7 = {77 6f 77 2e 65 78 65 00 74 77 32 2e 65 78 65}  //weight: 10, accuracy: High
        $x_5_8 = "<H1>403 Forbidden</H1>" ascii //weight: 5
        $x_5_9 = "ttp://127.0.0.1:8888/ip.txt" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 3 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AR_2147679594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AR"
        threat_id = "2147679594"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "user guest ratpp && net localgroup administrators guest" ascii //weight: 10
        $x_10_2 = "COMMAND_UNPACK_RAR reve" ascii //weight: 10
        $x_10_3 = "<H1>403 Forbidden</H1>" ascii //weight: 10
        $x_1_4 = {ff 61 c6 85 ?? ff ff ff 76 c6 85 ?? ff ff ff 70 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 78 c6 85 ?? ff ff ff 65}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 4b c6 85 ?? ff ff ff 76 c6 85 ?? ff ff ff 4d c6 85 ?? ff ff ff 6f c6 85 ?? ff ff ff 6e c6 85 ?? ff ff ff 58 c6 85 ?? ff ff ff 50 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 78 c6 85 ?? ff ff ff 65}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 52 c6 85 ?? ff ff ff 61 c6 85 ?? ff ff ff 76 c6 85 ?? ff ff ff 4d c6 85 ?? ff ff ff 6f c6 85 ?? ff ff ff 6e c6 85 ?? ff ff ff 44 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 78 c6 85 ?? ff ff ff 65}  //weight: 1, accuracy: Low
        $x_1_7 = {ff 4d c6 85 ?? ff ff ff 63 c6 85 ?? ff ff ff 73 c6 85 ?? ff ff ff 68 c6 85 ?? ff ff ff 69 c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 6c c6 85 ?? ff ff ff 64 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 78 c6 85 ?? ff ff ff 65}  //weight: 1, accuracy: Low
        $x_1_8 = {ff 65 c6 85 ?? ff ff ff 67 c6 85 ?? ff ff ff 75 c6 85 ?? ff ff ff 69 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 78 c6 85 ?? ff ff ff 65}  //weight: 1, accuracy: Low
        $x_1_9 = {ff 6b c6 85 ?? ff ff ff 6e c6 85 ?? ff ff ff 73 c6 85 ?? ff ff ff 64 c6 85 ?? ff ff ff 74 c6 85 ?? ff ff ff 72 c6 85 ?? ff ff ff 61 c6 85 ?? ff ff ff 79 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 78 c6 85 ?? ff ff ff 65}  //weight: 1, accuracy: Low
        $x_1_10 = {ff 61 c6 85 ?? ff ff ff 76 c6 85 ?? ff ff ff 63 c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 6e c6 85 ?? ff ff ff 74 c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 72 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 78 c6 85 ?? ff ff ff 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_AZ_2147682703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AZ"
        threat_id = "2147682703"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 4d 5c c6 44 24 4e 2e c6 44 24 4f 5c c6 44 24 50 6b c6 44 24 51 69 88 5c 24 52 88 5c 24 53 c6 44 24 54 6d c6 44 24 55 64 c6 44 24 56 78 c6 44 24 57 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 e0 53 88 4d e1 c6 45 e3 45 c6 45 e4 76 88 4d e5 c6 45 e6 6e}  //weight: 1, accuracy: High
        $x_1_3 = "lla/4.0 (TOKEZ)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BD_2147683052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BD"
        threat_id = "2147683052"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 79 17 00 00 66 89 08 83 7c 24}  //weight: 1, accuracy: High
        $x_1_2 = {b9 63 ea 00 00 66 89 08 83 7c 24}  //weight: 1, accuracy: High
        $x_1_3 = {b9 4c ee 00 00 66 89 08 83 7c 24}  //weight: 1, accuracy: High
        $x_1_4 = {b4 d8 ff ff 10 00 e8 ?? ?? 00 00 83 c4 0c 3b c3 75 40 81 7c 24}  //weight: 1, accuracy: Low
        $x_4_5 = {51 8d 54 24 ?? 52 bb (9e|91) 01 00 00 e8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_BE_2147683149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BE"
        threat_id = "2147683149"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Load_Path" ascii //weight: 2
        $x_2_2 = "netsvcs" ascii //weight: 2
        $x_3_3 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 3
        $x_4_4 = "\\esent.dll" ascii //weight: 4
        $x_5_5 = "%s\\wi%dnd.temp" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BH_2147686457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BH"
        threat_id = "2147686457"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 89 44 24 44 c6 44 24 39 65 c6 44 24 3c 79 c6 44 24 40 6d ff d5 8b 35}  //weight: 1, accuracy: High
        $x_1_2 = {89 4c 24 24 88 54 24 28 c6 44 24 1c 47 c6 44 24 1f 55 c6 44 24 23 4e ff d5 50 ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 2c 72 c6 44 24 2e 6f c6 44 24 2f 74 ff d3 56 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {c6 44 24 11 4d c6 44 24 12 42 c6 44 24 14 30 c6 44 24 16 6d c6 44 24 17 62 0f 84 c3}  //weight: 1, accuracy: High
        $x_1_5 = {c6 44 24 18 47 c6 44 24 1a 74 c6 44 24 1b 55 c6 44 24 1f 4e c6 44 24 21 6d ff d5}  //weight: 1, accuracy: High
        $x_1_6 = {c6 44 24 54 47 c6 44 24 56 74 c6 44 24 57 56 c6 44 24 5b 6d c6 44 24 5d 49 c6 44 24 60 6f c6 44 24 64 74 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Farfli_BI_2147688405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BI"
        threat_id = "2147688405"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\FW.FW" ascii //weight: 1
        $x_1_2 = {53 65 74 46 69 6c 65 50 6f 69 6e 74 65 72 [0-5] 25 73 25 73 25 73 [0-5] 25 73 25 73 2a 2e 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 6f 7a 69 00 00 00 00 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 29}  //weight: 1, accuracy: High
        $x_1_4 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 [0-8] 25 31 [0-5] 22 25 31 ?? 25 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_CB_2147691059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.CB"
        threat_id = "2147691059"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 db 36 0f be 14 28 3a d6 74 08 c1 cb 0d 03 da 40 eb ef 3b df 75 e7}  //weight: 2, accuracy: High
        $x_2_2 = "http://hh.rooter.tk/ytj/ytj.exe" ascii //weight: 2
        $x_1_3 = {95 bf 8e 4e 0e ec e8 ?? ?? ff ff 83 ec 04 83 2c 24 3c e9}  //weight: 1, accuracy: Low
        $x_1_4 = {89 34 24 bf 98 fe 8a 0e e8 ?? ff ff ff 83 ec 04 83 2c 24 70 83 ec 64 bf 72 fa 4d db}  //weight: 1, accuracy: Low
        $x_1_5 = {bf 54 ca af 91 e8 ?? fe ff ff 6a 04 68 00 10 00 00 6a 44 6a 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_DA_2147706193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.DA"
        threat_id = "2147706193"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8a 1c 10 89 4d e8 8a 0c 31 32 d9 b9 05 00 00 00 88 1c 10 99 f7 f9 85 d2}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 38 4d 5a 74 0a 5f 5e 5d 33 c0 5b 83 c4 64 c3 8b 70 3c 03 f0 89 74 24 20 81 3e 50 45 00 00 74 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_DB_2147708399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.DB"
        threat_id = "2147708399"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 e4 b8 4d 5a 00 00 c6 07 4d c6 47 01 5a 66 39 07 74 07 33 c0 e9 10 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 01 80 ea 26 80 f2 29 88 14 01 41 3b ce 7c ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_DC_2147708422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.DC"
        threat_id = "2147708422"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 29 57 c6 44 24 2a 4f c6 44 24 2b 4c c6 44 24 2c 46 88 5c 24 2d c6 44 24 18 3a c6 44 24 19 32 c6 44 24 1a 30 c6 44 24 1b 31 c6 44 24 1c 35 c6 44 24 1d 2d c6 44 24 1e 56 c6 44 24 1f 49 c6 44 24 20 50}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 0c b9 ab 05 00 00 25 ff 00 00 00 56 99 f7 f9 8b 74 24 0c 80 c2 3d 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_DD_2147708514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.DD"
        threat_id = "2147708514"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 11 80 ea 86 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 19 8b 45 fc 03 45 f8 88 10 eb c7}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 f5 67 c6 45 f6 75 c6 45 f7 65 c6 45 f8 73 c6 45 f9 74 c6 45 fa 20 c6 45 fb 2f c6 45 fc 61 c6 45 fd 64 c6 45 fe 64 c6 45 ff 00 6a 00 8d 45 a0 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {61 67 6d 6b 69 73 32 00 5c 5c 2e 5c 61 67 6d 6b 69 73 32 00 48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_CT_2147725374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.CT!bit"
        threat_id = "2147725374"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 03 8d ?? ?? ff ff 0f be 11 0f be 85 ?? ?? ff ff 2b d0 8b 4d fc 03 8d ?? ?? ff ff 88 11 8b 55 fc 03 95 ?? ?? ff ff 0f be 02 0f be 8d ?? ?? ff ff 33 c1 8b 55 fc 03 95 ?? ?? ff ff 88 02 eb a1}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 47 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 67}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 08 03 4d f8 8a 55 f8 88 11 8b 45 f8 33 d2 f7 75 10 8b 45 0c 33 c9 8a 0c 10 8b 55 f8 89 8c 95 ?? ?? ff ff eb c7}  //weight: 1, accuracy: Low
        $x_1_4 = {81 3a 50 45 00 00 74 07 33 c0 e9 ?? ?? ?? 00 6a 04 68 00 20 00 00 8b 45 ?? 8b 48 ?? 51 8b 55 ?? 8b 42 34 50 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 4d c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 7a c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 61 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 34 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 20 c6 85 ?? ?? ff ff 28 c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 6d c6 85 ?? ?? ff ff 70 c6 85 ?? ?? ff ff 61 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 62 c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 29 c6 85 ?? ?? ff ff 00}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 4b c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 68 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Farfli_QT_2147725616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.QT!bit"
        threat_id = "2147725616"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lyb/log.html?" ascii //weight: 1
        $x_1_2 = "360Safe.exe" ascii //weight: 1
        $x_1_3 = "\\Fonts\\service.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_QU_2147727199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.QU!bit"
        threat_id = "2147727199"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c}  //weight: 1, accuracy: High
        $x_1_2 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72}  //weight: 1, accuracy: High
        $x_1_3 = {4b 50 8d 45 ?? 50 c6 45 ?? 45 c6 45 ?? 52 c6 45 ?? 4e c6 45 ?? 45 c6 45 ?? 4c c6 45 ?? 33 c6 45 ?? 32}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 08 0f b7 cf 03 c6 8a 4c 4d ?? 30 08 47 46 3b 75}  //weight: 1, accuracy: Low
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_QX_2147727884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.QX!bit"
        threat_id = "2147727884"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 2f 01 8a 14 1e 47 32 d0 6a 00 88 14 1e ff 15 ?? ?? ?? ?? 8b c6 b9 05 00 00 00 99 f7 f9 85 d2 75 02 33 ff 8b 44 24 18 46 3b f0 7c d2}  //weight: 1, accuracy: Low
        $x_1_2 = {66 3d 7e 00 75 02 33 c0 8a 19 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 da 40 88 19 41 4e 75 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_QY_2147730496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.QY!bit"
        threat_id = "2147730496"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KSafeTray.exe" ascii //weight: 1
        $x_1_2 = "360tray.exe" ascii //weight: 1
        $x_1_3 = "/c del /q %s" ascii //weight: 1
        $x_1_4 = {00 4c 6f 6e 67 5a 75 6f 6d 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "InjectDLL.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_RA_2147734621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.RA!bit"
        threat_id = "2147734621"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 e1 63 c6 45 e2 2e c6 45 e3 63 c6 45 e4 63 c6 45 e5 32 c6 45 e6 35 c6 45 e7 79 c6 45 e8 72 c6 45 e9 2e c6 45 ea 6f}  //weight: 1, accuracy: High
        $x_1_2 = "System%c%c%c.exe" ascii //weight: 1
        $x_1_3 = "XXOOXXOO:%s|%d|%d|%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_RB_2147735012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.RB!bit"
        threat_id = "2147735012"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 e0 44 c6 45 e1 65 c6 45 e2 66 c6 45 e3 61 c6 45 e4 75 c6 45 e6 74 c6 45 e7 2e c6 45 e8 78 c6 45 e9 6d}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 54 0e fc 30 50 ff 0f b6 14 0e 30 10 0f b6 54 0e 04 30 50 01 0f b6 54 0e 08 30 50 02 41 83 c0 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_G_2147753904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.G!MTB"
        threat_id = "2147753904"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 ea 7a 80 f2 19 88 91 ?? ?? ?? ?? 50 33 c0 74 06 00 8a 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_ABM_2147789555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.ABM!MTB"
        threat_id = "2147789555"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 8b 06 8b c8 25 ff 0f 00 00 c1 e9 0c}  //weight: 10, accuracy: High
        $x_10_2 = {8b 4d 0c 01 0c 18 8b 42 04 47 83 e8 08 83 c6 02 d1 e8 3b f8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_AM_2147792970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AM!MTB"
        threat_id = "2147792970"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BaiduAllSoft" ascii //weight: 3
        $x_3_2 = "URLDownloadToFileA" ascii //weight: 3
        $x_3_3 = "users.qzone.qq.com" ascii //weight: 3
        $x_3_4 = "cgi_get_portrait.fcg" ascii //weight: 3
        $x_3_5 = "c:\\windows\\blackcat1.log" ascii //weight: 3
        $x_3_6 = "Hello World!" ascii //weight: 3
        $x_3_7 = "C:\\INTERNAL\\REMOTE.EXE" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GZ_2147814053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GZ!MTB"
        threat_id = "2147814053"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {30 f0 d2 e1 8a 45 00 80 d9 1b 10 e9 8a 4d 02}  //weight: 10, accuracy: High
        $x_1_2 = "svchsot.exe" ascii //weight: 1
        $x_1_3 = "host123.zz.am" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BA_2147817188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BA!MTB"
        threat_id = "2147817188"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 04 39 bd ?? ?? ?? ?? 80 c2 1f 32 c2 46 88 04 39 8b c1}  //weight: 5, accuracy: Low
        $x_5_2 = {c6 44 24 1a 46 c6 44 24 1b ?? c6 44 24 1c ?? c6 44 24 1d ?? c6 44 24 1e ?? c6 44 24 1f ?? c6 44 24 20 ?? c6 44 24 22 44 c6 ?? 24 23 ?? c6 44 24}  //weight: 5, accuracy: Low
        $x_5_3 = {b0 6c b1 65 88 44 24 ?? 88 44 24 ?? 8d 44 24 ?? c6 44 24 ?? 53 50 c6 44 24 ?? 68 88 4c 24 ?? 88 4c 24 ?? c6 44 24 ?? 78 c6 44 24 0b 00}  //weight: 5, accuracy: Low
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BXA_2147817409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BXA!MTB"
        threat_id = "2147817409"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a0 78 5b 04 42 31 29 32 d0 40 81 ca ?? ?? ?? ?? 32 9a ?? ?? ?? ?? 30 5f 32 c6 4d 55 30 73 a5 97}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_AFX_2147817420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AFX!MTB"
        threat_id = "2147817420"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 0c 8b 4c 24 14 47 03 c6 6a 00 8a 0c 0f 30 08}  //weight: 10, accuracy: High
        $x_10_2 = {c6 45 f4 57 50 c6 45 f5 69 c6 45 f6 6e c6 45 f7 6c c6 45 f8 6f c6 45 f9 67 c6 45 fa 6f c6 45 fb 6e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_FT_2147818658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.FT!MTB"
        threat_id = "2147818658"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 74 24 0c 80 c2 08 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_VM_2147819500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.VM!MTB"
        threat_id = "2147819500"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 b8 ?? ?? ?? ?? 8a 0a 32 4d ef 02 4d ef 88 0a 42 89 55 08 c3 8b 45 e8 c7 45 ?? ?? ?? ?? ?? 40 eb bf}  //weight: 10, accuracy: Low
        $x_1_2 = "2345MPCSafe" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_XZ_2147820479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.XZ!MTB"
        threat_id = "2147820479"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8c fc ff ff 46 c6 85 ?? ?? ?? ?? 2d c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 63 c6 85 ?? ?? ?? ?? 75 c6 85 ?? ?? ?? ?? 72 c6 85}  //weight: 10, accuracy: Low
        $x_10_2 = {84 fc ff ff 43 c6 85 ?? ?? ?? ?? 6f c6 85 ?? ?? ?? ?? 6d c6 85 ?? ?? ?? ?? 6f c6 85 ?? ?? ?? ?? 64 c6 85}  //weight: 10, accuracy: Low
        $x_1_3 = "\\Program Files\\%d%D.COM" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_BF_2147824395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BF!MTB"
        threat_id = "2147824395"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 8a 19 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 da 40 88 19 41 4e 75}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 19 44 c6 44 24 1a 56 c6 44 24 1c 50 c6 44 24 1d 49 c6 44 24 1e 33 c6 44 24 1f 32 c6 44 24 20 2e c6 44 24 21 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BG_2147824905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BG!MTB"
        threat_id = "2147824905"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c9 8a 1c 38 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 38 40 3b c6 72}  //weight: 2, accuracy: High
        $x_1_2 = "gitee.com//standar//plug-in-2//raw/master//Sen" ascii //weight: 1
        $x_1_3 = "hloworld.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Farfli_BH_2147825429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BH!MTB"
        threat_id = "2147825429"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 01 80 f2 19 80 c2 7a 88 14 01 41 3b ce 7c}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 01 80 ea 7a 80 f2 19 88 14 01 41 3b ce 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BI_2147826107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BI!MTB"
        threat_id = "2147826107"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d1 03 c2 8b 55 e0 33 55 f8 8b 4d d4 83 e1 03 33 4d bc 8b 75 10 8b 0c 8e 33 4d ec 03 d1 33 c2 8b 55 08 0f b6 0a 2b c8 8b 55 08 88 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BY_2147829775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BY!MTB"
        threat_id = "2147829775"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {32 d5 41 8b 14 24 49 81 c4 04 00 00 00 40 3a e1 41 33 d3 41 f6 c3 98 f7 da e9}  //weight: 5, accuracy: High
        $x_1_2 = "cYreenQillssf" ascii //weight: 1
        $x_1_3 = "vmps0" ascii //weight: 1
        $x_1_4 = "vmps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BN_2147830294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BN!MTB"
        threat_id = "2147830294"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 01 80 f2 91 80 ea 67 88 14 01 41 3b 4c 24 08 7c}  //weight: 2, accuracy: High
        $x_1_2 = "%s.exe" ascii //weight: 1
        $x_1_3 = "fuckyou" ascii //weight: 1
        $x_1_4 = "[Print Screen]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BM_2147830320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BM!MTB"
        threat_id = "2147830320"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 8c 83 c2 01 89 55 8c 8b 45 8c 3b 45 dc 7d 16 8b 4d 08 03 4d 8c 0f be 11 83 f2 62 8b 45 a0 03 45 8c 88 10 eb}  //weight: 2, accuracy: High
        $x_1_2 = "[PRINT_SCREEN]" ascii //weight: 1
        $x_1_3 = "[EXECUTE_key]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BO_2147830450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BO!MTB"
        threat_id = "2147830450"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 14 01 80 ea 31 80 f2 fc 88 14 01 41 3b ce 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BP_2147831116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BP!MTB"
        threat_id = "2147831116"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {33 c5 89 45 fc c6 45 ec 4b c6 45 ed 45 c6 45 ee 52 c6 45 ef 4e c6 45 f0 45 c6 45 f1 4c c6 45 f2 33 c6 45 f3 32 c6 45 f4 2e c6 45 f5 64 c6 45 f6 6c c6 45 f7 6c c6 45 f8 00 c6 45 d0 47 c6 45 d1 65 c6 45 d2 74 c6 45 d3 50 c6 45 d4 72}  //weight: 3, accuracy: High
        $x_2_2 = "cYreenQillthht" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BQ_2147831129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BQ!MTB"
        threat_id = "2147831129"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 4c 04 04 8b 14 24 02 d0 32 d1 88 54 04 04 40 3d 8b 00 00 00 72}  //weight: 3, accuracy: High
        $x_2_2 = "Applications\\VMwareHostOpen.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BR_2147831366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BR!MTB"
        threat_id = "2147831366"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "aHR0cDovLzE3Mi4yNDcuMjIzLjEzMDo4OTc1L0lCb3hIZWxwZXIuZGxs" ascii //weight: 2
        $x_2_2 = "aHR0cDovLzE3Mi4yNDcuMjIzLjEzMDo4OTc1L2" ascii //weight: 2
        $x_2_3 = "baobeier\\Dll1\\Release\\Dll1.pdb" ascii //weight: 2
        $x_2_4 = "Users\\Public\\Documents\\\\IBoxHelper.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BS_2147831381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BS!MTB"
        threat_id = "2147831381"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 fc 80 34 08 b9 03 c1 41 3b cb 7c}  //weight: 3, accuracy: High
        $x_2_2 = "s\\%sair.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BT_2147831483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BT!MTB"
        threat_id = "2147831483"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {f7 e1 c1 ea 02 8d 14 92 8b c1 2b c2 66 8b 54 84 04 66 31 14 4d [0-4] 41 3b ce 7c}  //weight: 3, accuracy: Low
        $x_1_2 = "Rmepr`pfXHhaqkvndwXRhlgkrr^@qwsgmpSdppmjo^Qqk" wide //weight: 1
        $x_1_3 = "Enter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BU_2147831851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BU!MTB"
        threat_id = "2147831851"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 01 34 9b 2c 65 88 01 41 4a 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BW_2147832515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BW!MTB"
        threat_id = "2147832515"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 14 01 80 f2 ?? 80 c2 ?? 88 14 01 41 3b ce 7c}  //weight: 4, accuracy: Low
        $x_1_2 = "PluginMe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BX_2147832516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BX!MTB"
        threat_id = "2147832516"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8d 55 e8 b1 cc 03 d0 2a c8 40 32 0a 88 0c 13 83 f8 05 76}  //weight: 3, accuracy: High
        $x_2_2 = "C:\\syslog.dat" ascii //weight: 2
        $x_2_3 = "CcMainDll.dll" ascii //weight: 2
        $x_1_4 = "TestFun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_AAB_2147832732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AAB!MTB"
        threat_id = "2147832732"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d fc 80 04 11 7a 03 ca 8b 4d fc 80 34 11 19 03 ca 42 3b d0 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_AAC_2147833036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.AAC!MTB"
        threat_id = "2147833036"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 14 01 80 f2 19 80 c2 46 88 14 01 41 3b 4c 24 08 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BV_2147836100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BV!MTB"
        threat_id = "2147836100"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 e0 02 33 d0 8b 4d f8 c1 e9 03 8b 45 ec c1 e0 04 33 c8 03 d1 8b 4d f0 33 4d f8 8b 45 fc 83 e0 03 33 45 e8 8b 75 10 8b 04 86 33 45 ec 03 c8 33 d1 8b 4d 08 03 4d fc 0f b6 01 03 c2 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 0f b6 02 89 45 ec eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BZ_2147836464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BZ!MTB"
        threat_id = "2147836464"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 f9 81 c2 d1 00 00 00 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a 8b 45 f8 83 c0 01 89 45 f8 8b 45 fc 99 b9 03 00 00 00 f7 f9 85 d2 75}  //weight: 2, accuracy: High
        $x_1_2 = "211.152.147.97/bbs" ascii //weight: 1
        $x_1_3 = "www.sarahclub.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BAA_2147836755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BAA!MTB"
        threat_id = "2147836755"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c9 0f b7 d1 8a 94 55 ?? ?? ?? ?? 30 10 41 40 4e 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BAA_2147836755_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BAA!MTB"
        threat_id = "2147836755"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 30 8b d1 81 e2 ff ff 00 00 8a 54 54 0c 32 da 41 88 1c 30 40 3b c7 72}  //weight: 2, accuracy: High
        $x_2_2 = "c:\\WinRecel\\air.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BAB_2147837270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BAB!MTB"
        threat_id = "2147837270"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {27 a9 92 19 5b 97 98 8b 5a 21 81 b8 6e df 55 03 c9 81 5b 21 81 b2 cf 54 ed 97 b6 10 cd 96 75}  //weight: 2, accuracy: High
        $x_2_2 = {31 66 84 dd 7a 54 fd f7 ac 7a de a1 b5 29 67 5f ed 91 09 60 ff 49 92 19 53 2b c9 fd fa 7b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BAE_2147837675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BAE!MTB"
        threat_id = "2147837675"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 45 08 8d 45 dc c6 45 dc 57 50 57 c6 45 dd 72 c6 45 de 69 c6 45 df 74 c6 45 e0 65 c6 45 e1 46 c6 45 e2 69 c6 45 e3 6c c6 45 e4 65 ff d6}  //weight: 2, accuracy: High
        $x_1_2 = "1.exe" ascii //weight: 1
        $x_1_3 = "user.qzone.qq.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BAD_2147837791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BAD!MTB"
        threat_id = "2147837791"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 ff 8b 45 08 8d 0c 02 0f b7 c7 8a 44 45 ?? 30 01 47 42 3b d6 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BAG_2147837974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BAG!MTB"
        threat_id = "2147837974"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c9 0f b7 d1 8a 14 55 [0-4] 30 14 38 40 41 3b c6 72}  //weight: 2, accuracy: Low
        $x_2_2 = "note.youdao.com/yws/public/resource" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GCW_2147838817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GCW!MTB"
        threat_id = "2147838817"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 09 8a d9 c0 e3 ?? 8b d0 c1 ea ?? 32 d3 89 4d fc c1 e9 ?? 8a d8 c0 e3 ?? 32 cb 8a 5d 0c 81 45 ?? 47 86 c8 61 02 d1 8b 4d 10 83 e6 ?? 33 75 f8 32 d8 8a 0c b1 32 4d fc 02 cb 32 d1 28 17 ff 4d f4 0f b6 07 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BAH_2147838877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BAH!MTB"
        threat_id = "2147838877"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 01 80 c2 66 80 f2 fe 88 14 01 41 3b 4c 24 08 7c}  //weight: 2, accuracy: High
        $x_1_2 = "%s.exe" ascii //weight: 1
        $x_1_3 = "c%c%c%c%c%c.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GDH_2147839838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GDH!MTB"
        threat_id = "2147839838"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 5c 24 30 8b 44 24 28 83 c0 01 0f b6 80 ?? ?? ?? ?? 88 44 1c 48 8b 44 24 30 8d 68 ff 89 e8 31 d8 f7 d0 09 e8 78 05 e8 ?? ?? ?? ?? 83 fd ?? 0f 86}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BAI_2147841122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BAI!MTB"
        threat_id = "2147841122"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 4d 08 8a 14 11 32 94 45 04 ff ff ff 8b 85 f8 fe ff ff 25 [0-4] 8b 4d 08 88 14 01 66 8b 95 fc fe ff ff 66 83 c2 01 66 89 95 fc fe ff ff e9}  //weight: 3, accuracy: Low
        $x_2_2 = "xui.ptlogin2.qq.com" ascii //weight: 2
        $x_2_3 = "%s.exe" ascii //weight: 2
        $x_2_4 = "%s.dmp" ascii //weight: 2
        $x_1_5 = "[Scroll Lock]" ascii //weight: 1
        $x_1_6 = "[Print Screen]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_BAC_2147843095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.BAC!MTB"
        threat_id = "2147843095"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 6a 00 6a 00 50 b9 57 37 01 00 81 c6 74 dd 04 00 8b f8 50 6a 00 6a 00 f3 a5 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = "103.163.47.247" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GIC_2147845980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GIC!MTB"
        threat_id = "2147845980"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b0 6c 88 44 24 1a 88 44 24 1b 68 ?? ?? ?? ?? 8d 44 24 14 33 db 50 c6 44 24 ?? 44 c6 44 24 ?? 56 c6 44 24 ?? 50 c6 44 24 ?? 49 c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 88 5c 24 ?? ff d6}  //weight: 10, accuracy: Low
        $x_1_2 = "Startup\\hao567.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GNL_2147851379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GNL!MTB"
        threat_id = "2147851379"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b0 41 b3 6c 68 ?? ?? ?? ?? 51 88 44 24 ?? c6 44 24 ?? 44 c6 44 24 ?? 56 88 44 24 ?? c6 44 24 ?? 50 c6 44 24 ?? 49 c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 88 5c 24 ?? 88 5c 24 ?? c6 44 24}  //weight: 10, accuracy: Low
        $x_1_2 = "PluginMe1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GMF_2147888644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GMF!MTB"
        threat_id = "2147888644"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 6f 6e 6e c7 45 ?? 65 63 74 00 c7 45 ?? 46 74 70 4f c7 45 ?? 70 65 6e 46 c7 45 ?? 69 6c 65 00 c7 45 ?? 49 6e 74 65 c7 45 ?? 72 6e 65 74 c7 45 ?? 52 65 61 64 c7 45 ?? 46 69 6c 65 88 5d ?? ff 15 ?? ?? ?? ?? 89 85}  //weight: 10, accuracy: Low
        $x_1_2 = "zhu.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GMC_2147891911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GMC!MTB"
        threat_id = "2147891911"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {22 31 1b 2f 99 32 41 79 00 67 4c 40 21 0e}  //weight: 10, accuracy: High
        $x_1_2 = "@VProtect" ascii //weight: 1
        $x_1_3 = "ZqL2GA1OT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GMQ_2147892675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GMQ!MTB"
        threat_id = "2147892675"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c8 31 d2 f7 f6 0f b6 04 17 30 04 0b 83 c1 01 39 cd 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_XG_2147896357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.XG!MTB"
        threat_id = "2147896357"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//gitee.com" ascii //weight: 1
        $x_1_2 = "//ProgramData//Sen.png" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "hloworld.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GAB_2147898748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GAB!MTB"
        threat_id = "2147898748"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 db 57 33 c0 be 00 ?? ?? ?? 80 b0 ?? ?? ?? ?? b6 40 3b c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GAC_2147898775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GAC!MTB"
        threat_id = "2147898775"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {88 5d e8 c6 45 ec 43 c6 45 ed 72 c6 45 ee 65 c6 45 ef 61 c6 45 f0 74 c6 45 f1 65 c6 45 f2 45 c6 45 f3 76 c6 45 f4 65 c6 45 f5 6e c6 45 f6 74 c6 45 f7 41 88 5d f8 ff d7 50 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GZZ_2147905464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GZZ!MTB"
        threat_id = "2147905464"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "M4,kxH8" ascii //weight: 5
        $x_5_2 = {9d 10 fb 22 5a 61 01 29 24 37 4c 10 59 52 3b f0 71 ed}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GZZ_2147905464_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GZZ!MTB"
        threat_id = "2147905464"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 64 24 00 80 b4 05 ?? ?? ?? ?? d7 40 3d c0 67 0f 00 75}  //weight: 10, accuracy: Low
        $x_1_2 = "\\ProgramData\\update.exe" ascii //weight: 1
        $x_1_3 = "\\ProgramData\\jfds.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Farfli_GNK_2147917815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Farfli.GNK!MTB"
        threat_id = "2147917815"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 02 99 be c8 01 00 00 f7 fe 83 c2 36 8b 45 e0 8b 40 08 8b 75 ec 0f be 04 30 33 c2 8b 55 ec 88 04 11 8b 45 e8 83 c0 01 89 45 e8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

