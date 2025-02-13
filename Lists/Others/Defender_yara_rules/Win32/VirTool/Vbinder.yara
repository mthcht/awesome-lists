rule VirTool_Win32_Vbinder_A_2147606414_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.A"
        threat_id = "2147606414"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 00 69 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 00 00 00 00 12 00 00 00 46 00 69 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 32 00 00 00 10 00 00 00 74 00 65 00 6d 00 70 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "proje\\MK Binder\\server\\Project1.vbp" wide //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "GetTempPathA" ascii //weight: 1
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_B_2147607343_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.B"
        threat_id = "2147607343"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CP666BinderV.2\\Stub" wide //weight: 1
        $x_1_2 = {2e 00 63 00 6d 00 64 00 00 00 00 00 08 00 00 00 2e 00 62 00 61 00 74 00 00 00 00 00 08 00 00 00 2e 00 74 00 78 00 74 00 00 00 00 00 18 00 00 00 6e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = {00 48 75 66 66 6d 61 6e 43 6f 64 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_C_2147607525_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.C"
        threat_id = "2147607525"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 66 00 20 00 45 00 78 00 69 00 73 00 74 00 20 00 00 00 0e 00 00 00 20 00 47 00 6f 00 74 00 6f 00 20 00 53 00 00 00 16 00 00 00 44 00 65 00 6c 00 20 00}  //weight: 1, accuracy: High
        $x_1_2 = "{[Settings]}" wide //weight: 1
        $x_1_3 = "{[File_Names]}" wide //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = {00 48 75 66 66 6d 61 6e 43 6f 64 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_D_2147611196_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.D"
        threat_id = "2147611196"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 7a ff 04 70 ff f5 00 00 00 00 fc 75 00 07 6b 7a ff fd 3d 00 1a f5 00 00 00 00 f5 ff ff ff ff 1b 05 00 6c 70 ff 5e 06 00 10 00 71 74 ff 00 0e 6c 74 ff f5 00 00 00 00 c7 1c 94 00 00 03 14 00 5a 27 50 ff 6c 74 ff 1b 05 00 4a aa 6c 70 ff 0b 07 00 0c 00 31 08 ff f5 00 00 00 00 f5 ff ff ff ff 3a 2c ff 08 00 4e 1c ff 04 1c ff 3e 08 ff 23 4c ff 04 0c ff 0a 09 00 14 00 04 0c ff ff 36 08 20}  //weight: 1, accuracy: High
        $x_1_2 = {3c 00 3c 00 3e 00 3e 00 00 00 00 00 08 00 00 00 3c 00 5c 00 5c 00 3e 00 00 00 00 00 10 00 00 00 3c 00 3c 00 44 00 44 00 44 00 44 00 3e 00 3e 00 00 00 00 00 12 00 00 00 36 00 36 00 36 00 36 00 36 00 36 00 36 00 36 00 36 00 00 00 54 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 42 00 61 00 73 00 65 00 20 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 69 00 63 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 20 00 76 00 31 00 2e 00 30 00 00 00 00 00 12 00 00 00 4d 00 65 00 74 00 61 00 6c 00 6c 00 69 00 63 00 61 00 00 00 0c 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Vbinder_N_2147616785_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.N"
        threat_id = "2147616785"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Documents and Settings\\yardim60\\Desktop\\Poison Crypter Private 2\\Stub\\Stub.vbp" wide //weight: 1
        $x_1_2 = "bismillahAllahHerkeziKorusun" wide //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_P_2147618523_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.P"
        threat_id = "2147618523"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CreateProcess" wide //weight: 2
        $x_2_2 = "WriteProcessMemory" wide //weight: 2
        $x_2_3 = "GetThreadContext" wide //weight: 2
        $x_2_4 = "SetThreadContext" wide //weight: 2
        $x_2_5 = "ResumeThread" wide //weight: 2
        $x_2_6 = "RtlMoveMemory" wide //weight: 2
        $x_2_7 = "VirtualAllocEx" wide //weight: 2
        $x_2_8 = "\\stiki.vbp" wide //weight: 2
        $x_2_9 = {73 74 69 6b 69 00 73 74 69 6b 69 00 00 73 74 69 6b 69}  //weight: 2, accuracy: High
        $x_1_10 = {73 74 69 6b 69 00}  //weight: 1, accuracy: High
        $x_1_11 = {2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_2_*) and 2 of ($x_1_*))) or
            ((9 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Vbinder_Q_2147618524_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.Q"
        threat_id = "2147618524"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateProcess" ascii //weight: 1
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "GetThreadContext" ascii //weight: 1
        $x_1_4 = "SetThreadContext" ascii //weight: 1
        $x_1_5 = "ResumeThread" ascii //weight: 1
        $x_1_6 = "RtlMoveMemory" ascii //weight: 1
        $x_1_7 = "VirtualAllocEx" ascii //weight: 1
        $x_1_8 = "\\stiki.vbp" wide //weight: 1
        $x_1_9 = {73 74 69 6b 69 00 73 74 69 6b 69 00 00 73 74 69 6b 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_T_2147618629_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.T"
        threat_id = "2147618629"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Documents and Settings\\Mert.MERTKAN\\Desktop\\Poison Crypter  free\\Stub\\Stub.vbp" wide //weight: 1
        $x_1_2 = "Metallica" wide //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_B_2147618861_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.gen!B"
        threat_id = "2147618861"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d c4 fc 03 40 fc 8f e4 fc 01 00 04 e4 fc 1b 05 00 1b 06 00 0a 07 00 0c 00 04 e4 fc 5a f5 00 00 00 00 f5 04 00 00 00 04 e4 fc fe 8e 01 00 00 00 10 00 80 08 04 b8 fd 4d d4 fc 03 40 fc 8f e4 fc 00 00 04 70 fe 4d c4 fc 03 40 fc 8f e4 fc 01 00 04 8c fe 4d b4 fc 03 40 fc 8f e4 fc 02 00 fe c1 a4 fc 00 30 00 00 f5 03 00 00 00 6c e4 fc 52 fe c1 94 fc 40 00 00 00 f5 04 00 00 00 6c e4 fc 52 04 e4 fc 1b 08 00 1b 09 00 0a 07 00 0c 00 04 e4 fc 5a f5 00 00 00 00 59 90 fc 6c 90 fe f5 00 00 00 00 80 10 00 2e e8 fc 40 6c 70 fe 6c b8 fd 0a 0a 00 14 00 3c 2d e8 fc f5 00 00 00 00 04 74 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_AC_2147622321_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.AC"
        threat_id = "2147622321"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@*\\AD:\\VMW-1\\_1_\\STB\\STB+vbp" wide //weight: 1
        $x_1_2 = "Alien-Spirit" wide //weight: 1
        $x_1_3 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 53 00 54 00 42 00 2e 00 45 00 78 00 45 00}  //weight: 1, accuracy: High
        $x_1_4 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_5 = "silw3r" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_BO_2147626046_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.BO"
        threat_id = "2147626046"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mdBinderFinal\\mdCrypt\\vbStub\\vbStub.vbp" wide //weight: 10
        $x_1_2 = "Crypter by drizzle.. Coder from hackhound" wide //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_AU_2147630839_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.AU"
        threat_id = "2147630839"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 6e 00 64 00 65 00 74 00 65 00 63 00 74 00 61 00 62 00 6c 00 65 00 73 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 6e 63 72 79 70 74 46 69 6c 65 00 44 65 63 72 79 70 74 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_AW_2147630894_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.AW"
        threat_id = "2147630894"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 00 65 00 74 00 61 00 20 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 5c 00 53 00 74 00 75 00 62 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 31 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 32 00 48 55 4e 54 57 55 56 4a 55 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_CK_2147648096_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.CK"
        threat_id = "2147648096"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 59 00 00 00 ff d6 8d 4d dc 88 45 dc 51 e8}  //weight: 2, accuracy: High
        $x_2_2 = {b9 50 00 00 00 ff d6 8d 55 dc 88 45 dc 52 e8}  //weight: 2, accuracy: High
        $x_1_3 = {3d 4d 5a 00 00 0f 85 ?? ?? 00 00 83 ?? 3c 6a 04}  //weight: 1, accuracy: Low
        $x_2_4 = {8b 4d 08 8b 11 2b d6 70 ?? 2b d0}  //weight: 2, accuracy: Low
        $x_1_5 = "NtWriteVirtualMemory" wide //weight: 1
        $x_1_6 = "NtUnmapViewOfSection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Vbinder_CL_2147648471_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.CL"
        threat_id = "2147648471"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xpre\\xpre.vbp" wide //weight: 1
        $x_1_2 = "svr,avgupsvc,nvcpl,zonealarm,zlclient,vscan,virus,firewal" wide //weight: 1
        $x_1_3 = "TVqQAAMAAAAEAAAA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbinder_CQ_2147653594_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbinder.CQ"
        threat_id = "2147653594"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbinder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c7 45 fc 10 00 00 00 6a 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 45 fc ?? 00 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = {6a ff 68 20 02 00 00 e8 ?? ?? ?? ff 06 00 8b (75|7d) 08 ff (36 57|37 56)}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 0c ff 30 ff b5 ?? ?? ff ff 6a ff 68 20 02 00 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_2_4 = {00 52 61 63 6b 65 74 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 00 73 00 74 00 26 00 26 00 64 00 65 00 6c 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

