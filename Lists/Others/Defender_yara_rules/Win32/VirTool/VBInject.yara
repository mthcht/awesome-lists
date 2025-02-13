rule VirTool_Win32_VBInject_C_2147599460_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.C"
        threat_id = "2147599460"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/#/+\\#\\" ascii //weight: 1
        $x_1_2 = "\\vbpStub.vbp" wide //weight: 1
        $x_1_3 = {62 61 73 43 6f 6e 74 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 61 73 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {62 61 73 50 72 6f 63 65 73 53 00}  //weight: 1, accuracy: High
        $x_1_6 = {62 61 73 52 75 6e 50 45 00}  //weight: 1, accuracy: High
        $x_1_7 = "GetThreadContext" ascii //weight: 1
        $x_1_8 = "ReadProcessMemory" ascii //weight: 1
        $x_1_9 = "SetThreadContext" ascii //weight: 1
        $x_1_10 = "SuspendThread" ascii //weight: 1
        $x_1_11 = "ResumeThread" ascii //weight: 1
        $x_1_12 = "CreateProcessA" ascii //weight: 1
        $x_1_13 = "WriteProcessMemory" ascii //weight: 1
        $x_1_14 = "VirtualAllocEx" ascii //weight: 1
        $x_1_15 = "VirtualProtectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

rule VirTool_Win32_VBInject_2147600125_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject"
        threat_id = "2147600125"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "M3N3G@TT1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_2147600125_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject"
        threat_id = "2147600125"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MRunPE" ascii //weight: 1
        $x_1_2 = {2e 00 65 00 58 00 65 [0-16] 3c 00 3c 00 35 00 30 00 43 00 45 00 4e 00 54 00 3d 00 47 00 2d 00 55 00 4e 00 49 00 54 00 3e 00 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_A_2147600192_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!A"
        threat_id = "2147600192"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "--Z00P--" wide //weight: 5
        $x_1_2 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_3 = "GetDrive" wide //weight: 1
        $x_1_4 = "SYNTHETICUSER.FGVS" wide //weight: 1
        $x_1_5 = "\\Everwood\\" wide //weight: 1
        $x_2_6 = "ApplicationEncryption" ascii //weight: 2
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_5_8 = {53 74 75 62 00 63 73 72 73 73}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_B_2147601231_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!B"
        threat_id = "2147601231"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 41 44 57 52 49 50 72 6f 6a 65 63 74 31 00 45 58 45 43 55 54 45}  //weight: 5, accuracy: High
        $x_5_2 = "modInject" ascii //weight: 5
        $x_2_3 = "modCrypt" ascii //weight: 2
        $x_2_4 = "modProtect" ascii //weight: 2
        $x_2_5 = "modMain" ascii //weight: 2
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_9_7 = {f5 04 00 00 00 f5 00 30 00 00 6c ?? ?? 6c ?? ?? 6c ?? ?? 5e ?? ?? ?? ?? 71 ?? ?? 3c 6c ?? ?? 71 ?? ?? 6c ?? ?? f5 00 00 00 00 c7}  //weight: 9, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_C_2147607576_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!C"
        threat_id = "2147607576"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ollydbg" wide //weight: 1
        $x_1_2 = "regmon.exe" wide //weight: 1
        $x_1_3 = "filemon.exe" wide //weight: 1
        $x_1_4 = "procmon.exe" wide //weight: 1
        $x_4_5 = "-skipanti" wide //weight: 4
        $x_10_6 = "WriteProcessMemory" ascii //weight: 10
        $x_10_7 = {f3 00 01 c1 e7 04 58 ff 9d fb 12 fc 0d 6c 50 ff 6c 40 ff fc a0 00 0a 04 50 ff 66 ec fe df 01 00 26}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_D_2147611402_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.D"
        threat_id = "2147611402"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "StubSBX" ascii //weight: 2
        $x_2_2 = "crxss" ascii //weight: 2
        $x_2_3 = "RunPE" ascii //weight: 2
        $x_2_4 = "consenting computerName=m" wide //weight: 2
        $x_2_5 = "xlm32api" wide //weight: 2
        $x_1_6 = "1234567890" wide //weight: 1
        $x_1_7 = "mProcess" ascii //weight: 1
        $x_1_8 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_11 = "Process32Next" ascii //weight: 1
        $x_1_12 = "RtlMoveMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_K_2147611586_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!K"
        threat_id = "2147611586"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\users\\Emperor Zhou Tai Nu\\Desktop\\StubSRC_Hat\\Stub SRC UD by RaidX\\Stub SRC" wide //weight: 1
        $x_1_2 = {6d 6f 64 52 43 34 00}  //weight: 1, accuracy: High
        $x_1_3 = "ResumeThread" ascii //weight: 1
        $x_1_4 = "CreateProcessA" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_M_2147617122_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.M"
        threat_id = "2147617122"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c 00 60 e8 00 00 00 00 58 2d 62 fd ff ff 8b 30 03 f0 2b c0 8b fe 66 ad c1 e0 0c 8b c8 50 ad 2b c8 03 f1 8b c8 57 51 49 8a 44 39 06 74 05}  //weight: 1, accuracy: High
        $x_1_2 = {46 00 3a 88 1c 40 04 d0 c4 00 45 00 50 02 00 61 00 63 00 6b 44 a0 8c 10 e9 53 c6 c5 63 2e 00 76 0d 00 62 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_Q_2147618614_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!Q"
        threat_id = "2147618614"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 58 fc fb 01 04 e4 fc f5 04 00 00 00 04 e8 fc 6c 90 fd f5 08 00 00 00 aa 6c fc fd 0a 09 00 14 00 3c 6c e8 fc 6c 64 fe aa 71 9c fd 04 ec fc 6c 00 fe 0a 0d 00 08 00 3c 6c 00 fe 0a 0e 00 04 00 3c 14}  //weight: 1, accuracy: High
        $x_1_2 = "carb0n crypter" wide //weight: 1
        $x_1_3 = "CallAPIbyName" ascii //weight: 1
        $x_1_4 = "RunPE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_S_2147619569_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!S"
        threat_id = "2147619569"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 05 89 75 ?? eb 46 ff b5 ?? ?? ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 66 3b c6 74 e6 ff b5 ?? ?? ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 66 3b c6 74 d1}  //weight: 1, accuracy: Low
        $x_1_2 = {75 08 89 b5 ?? ?? ff ff eb 49 ff b5 ?? ?? ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 66 3b c6 74 e3 ff b5 ?? ?? ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 66 3b c6 74 ce}  //weight: 1, accuracy: Low
        $x_3_3 = {f6 c4 01 74 07 ba ?? ?? 40 00 eb 15 f6 c4 02 74 07 ba ?? ?? 40 00 eb 09 a8 40 74 14}  //weight: 3, accuracy: Low
        $x_3_4 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_R_2147620991_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.R"
        threat_id = "2147620991"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 8b f0 5b 8d 45 ?? 53 50 56 c7 45 9c 58 59 59 59 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 04 00 00 00 6c 10 00 f5 00 00 00 00 5f 08 00 ?? 00 06 58 00 40 0a ?? 00 0c 00}  //weight: 1, accuracy: Low
        $x_2_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 42 00 61 00 73 00 65 00 20 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 69 00 63 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 20 00 76 00 31 00 2e 00 30 00 00 00 00 00 12 00 00 00 4d 00 65 00 74 00 61 00 6c 00 6c 00 69 00 63 00 61 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {74 65 78 74 00 00 00 00 [0-64] 50 61 73 73 77 6f 72 64 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_T_2147621116_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.T"
        threat_id = "2147621116"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "from Win32_VideoController" wide //weight: 1
        $x_1_2 = "VMware SVGA" wide //weight: 1
        $x_1_3 = "S3 Trio32/64" wide //weight: 1
        $x_1_4 = "Sandboxie " wide //weight: 1
        $x_1_5 = "Detected!" wide //weight: 1
        $x_1_6 = "[CWSandbox" wide //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule VirTool_Win32_VBInject_V_2147621607_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.V"
        threat_id = "2147621607"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CCrypto.EncryptDecrypt" wide //weight: 1
        $x_1_2 = "StandardProfile /v \"DoNotAllowExceptions" wide //weight: 1
        $x_1_3 = "StandardProfile\\AuthorizedApplications\\List" wide //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_W_2147621625_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.W"
        threat_id = "2147621625"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "191"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {40 6c ec fc 6c 00 fe 0a ?? 00 14 00 3c 2d ?? fc 00 22 6c 74 ff f5 f8 00 00 00 aa 6c a8 fc ae fd 69 bc fc 04 ac fc fb 94 ?? fc fc 22 71 dc fc}  //weight: 100, accuracy: Low
        $x_10_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 00}  //weight: 10, accuracy: High
        $x_10_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 00}  //weight: 10, accuracy: High
        $x_10_4 = {53 75 73 70 65 6e 64 54 68 72 65 61 64 00}  //weight: 10, accuracy: High
        $x_10_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 10, accuracy: High
        $x_10_6 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00}  //weight: 10, accuracy: High
        $x_10_7 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00}  //weight: 10, accuracy: High
        $x_10_8 = "SystemDrive" wide //weight: 10
        $x_10_9 = "UserName" wide //weight: 10
        $x_10_10 = {45 6e 63 72 79 70 74 46 69 6c 65 00}  //weight: 10, accuracy: High
        $x_1_11 = {5a 77 53 79 73 74 65 6d 44 65 62 75 67 43 6f 6e 74 72 6f 6c 00}  //weight: 1, accuracy: High
        $x_1_12 = {49 73 64 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 9 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_Z_2147622700_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.Z"
        threat_id = "2147622700"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "winmgmts:" wide //weight: 10
        $x_10_2 = "X-CR Light" wide //weight: 10
        $x_1_3 = "modRC4" ascii //weight: 1
        $x_1_4 = "modAnVM" ascii //weight: 1
        $x_1_5 = "modAnSB" ascii //weight: 1
        $x_1_6 = "modMemExec" ascii //weight: 1
        $x_10_7 = "FindResourceA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AA_2147622705_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AA"
        threat_id = "2147622705"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Carb0n Crypter" wide //weight: 10
        $x_10_2 = {58 00 58 00 58 00 58 00 58 00 00 [0-16] 41 00 41 00 41 00 41 00 41 00 00}  //weight: 10, accuracy: Low
        $x_2_3 = "SetThreadContext" wide //weight: 2
        $x_2_4 = "WriteProcessMemory" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AW_2147622843_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!AW"
        threat_id = "2147622843"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "clsBlowfish" ascii //weight: 1
        $x_1_2 = "EncryptByte" ascii //weight: 1
        $x_1_3 = "EncryptFile" ascii //weight: 1
        $x_1_4 = "fni.nurotua" wide //weight: 1
        $x_1_5 = "Blowfish decryption" wide //weight: 1
        $x_1_6 = "Projekte" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AE_2147622891_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AE"
        threat_id = "2147622891"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f5 00 00 00 00 cc 1c 40 02 00 0e 6c 38 ff ec f4 04 eb b6 e8 71 34 ff 00 19 f5 00 00 00 00 04 2c ff 6c 34 ff f5 01 00 00 00 ae fe 64 1c ff 3d 02 00 28 f5 01 00 00 00 6c 2c ff 6c 3c ff 9e 0b 02 00 04 00 23 18 ff 1b 03 00 f5 00 00 00 00 fe fd fc 52 2f 18 ff 1c 31 02 00 0e 6c 2c ff 6c 3c ff 9e fb fe 31 78 ff 00 02 00 0a 04 2c ff 66 1c ff fb 01 1e 42 02 00 02 00 02 00 00 14}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AI_2147624120_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AI"
        threat_id = "2147624120"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {08 00 00 00 2e 00 65 00 78 00 65 00}  //weight: 20, accuracy: High
        $x_20_2 = "###(())###" wide //weight: 20
        $x_20_3 = {00 6d 52 75 6e 50 45 00}  //weight: 20, accuracy: High
        $x_20_4 = {00 6d 43 6f 6e 74 65 78 74 00}  //weight: 20, accuracy: High
        $x_20_5 = {00 6d 50 72 6f 63 65 73 73 00}  //weight: 20, accuracy: High
        $x_20_6 = "StrToBytArray" ascii //weight: 20
        $x_20_7 = "UnEncryptStr" ascii //weight: 20
        $x_1_8 = "Can not start victim process!" wide //weight: 1
        $x_1_9 = "ReadProcessMemory" ascii //weight: 1
        $x_1_10 = "SetThreadContext" ascii //weight: 1
        $x_1_11 = "SuspendThread" ascii //weight: 1
        $x_1_12 = "ResumeThread" ascii //weight: 1
        $x_1_13 = "CreateProcessA" ascii //weight: 1
        $x_1_14 = "WriteProcessMemory" ascii //weight: 1
        $x_1_15 = "VirtualProtectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AJ_2147624124_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJ"
        threat_id = "2147624124"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6d 6f 64 43 72 79 70 74 54 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 6d 6f 64 49 6e 6a 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6d 6f 64 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 43 52 69 6a 6e 64 61 65 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "mdsijdsopajdoas" wide //weight: 1
        $x_1_6 = "ndosijdopajdo" wide //weight: 1
        $x_1_7 = "dsopdksaokdas" wide //weight: 1
        $x_1_8 = {08 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 1c 00 00 00 67 00 61 00 64 00 66 00 64 00 73 00 67 00 61 00 64 00 73 00 66 00 73 00 66 00 73 00}  //weight: 1, accuracy: High
        $x_1_9 = "WriteProcessMemory" ascii //weight: 1
        $x_1_10 = "CallWindowProcA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AQ_2147624127_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AQ"
        threat_id = "2147624127"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 8a 04 18 a2 ?? ?? ?? ?? ff 37 e8 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 8a 18 32 1d ?? ?? ?? ?? ff 37 e8 ?? ?? ?? ?? 88 18 a1 ?? ?? ?? ?? 83 c0 01 70 15 3b 45 0c a3 ?? ?? ?? ?? 0f 8e}  //weight: 1, accuracy: Low
        $x_1_2 = {89 18 6a 01 58 66 03 45 e0 0f 80 ?? ?? ?? ?? 89 45 e0 eb ae e8 ?? ?? ?? ?? 56 56 56 56 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {66 8b d7 66 c1 fa 0f 8b da 33 55 ac 33 1d ?? ?? ?? ?? 66 3b da 7f 39 0f bf d9 3b de 72 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AO_2147624311_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!AO"
        threat_id = "2147624311"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "massafacka" wide //weight: 2
        $x_2_2 = "ping; 1.2; 0.3; 0.4 - n; 1 - w; 500 > nul" wide //weight: 2
        $x_2_3 = "Melt.bat" wide //weight: 2
        $x_2_4 = "VLCPort" wide //weight: 2
        $x_2_5 = "copiedfile.exe" wide //weight: 2
        $x_2_6 = "dddddedddd.ddd" wide //weight: 2
        $x_1_7 = "NtUnmapViewOfSection" wide //weight: 1
        $x_1_8 = "WriteProcessMemory" wide //weight: 1
        $x_1_9 = "RtlDecompressBuffer" wide //weight: 1
        $x_1_10 = "SetThreadContext" wide //weight: 1
        $x_1_11 = "Projekt1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AP_2147624342_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!AP"
        threat_id = "2147624342"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 81 7d a8 4d 5a 74 55}  //weight: 2, accuracy: High
        $x_2_2 = {81 bd ac fe ff ff 50 45 00 00 0f 84 b9 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {75 2f 8b 8d fc fe ff ff 8b 95 e0 fe ff ff 8b 85 7c fd ff ff 6a 04 68 00 30 00 00 51 52 50 e8}  //weight: 2, accuracy: High
        $x_1_4 = "Can not start victim process!" wide //weight: 1
        $x_1_5 = "/(*)\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AL_2147624404_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AL"
        threat_id = "2147624404"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Anibus Detected!" wide //weight: 1
        $x_1_2 = "VB!CRYPT" wide //weight: 1
        $x_1_3 = {72 00 65 00 67 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {70 00 72 00 6f 00 63 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AM_2147624506_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AM"
        threat_id = "2147624506"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {d0 ed 3c 8f 33 55 8a 2d 46 ef 6e 65 9a e9 04 83 3d 48 50 d9 08 b9 ce 00 ac cc f8 61 cb 88 74 5d 3a 46 8d 8a c8 3e c9 10 d8 47 50 72 33}  //weight: 3, accuracy: High
        $x_1_2 = "Skipjack EncryptFile procedure" wide //weight: 1
        $x_1_3 = "Hash Value (CryptHashData API)" wide //weight: 1
        $x_1_4 = "session key (CryptDeriveKey API)" wide //weight: 1
        $x_1_5 = "WriteProcessMemory" wide //weight: 1
        $x_1_6 = "SetThreadContext" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AN_2147624555_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AN"
        threat_id = "2147624555"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\PB_Stub {Scrambled}\\Project1.vbp" wide //weight: 1
        $x_1_2 = {50 50 56 44 50 45 58 51 00 00 00 00 6d 64 6c 45 6e 6a 65 6b 74 6f 72 00 4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 35 00 6d 64 6c 4d 61 69 6e 00 50 72 6f 6a 65 63 74 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AO_2147624687_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AO"
        threat_id = "2147624687"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 6f 64 43 43 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 00 72 00 65 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 57 00 00 00 00 00 0a 00 00 00 6e 00 74 00 64 00 6c 00 6c 00 00 00 28 00 00 00 4e 00 74 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = "This program cannot be run in Sandboxie. Please Close Sandboxie." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AP_2147624760_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AP"
        threat_id = "2147624760"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 79 74 49 6e 00 00 00 62 79 74 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: High
        $x_1_2 = {28 34 ff 02 00 6c 64 ff 6c 68 ff 0b 04 00 0c 00 23 30 ff 2a 23 2c ff 0a 05 00 04 00 e8 0b 06 00 04 00 23 28 ff 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AQ_2147624833_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!AQ"
        threat_id = "2147624833"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yromeMssecorPetirW" wide //weight: 1
        $x_1_2 = "txetnoCdaerhTteS" wide //weight: 1
        $x_1_3 = "noitceSfOweiVpamnUtN" wide //weight: 1
        $x_1_4 = "Twofish decryption" wide //weight: 1
        $x_1_5 = "tnuoCkciTteG" wide //weight: 1
        $x_1_6 = "DecryptFile" ascii //weight: 1
        $x_2_7 = "b-2rFf6c*r" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AR_2147624835_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!AR"
        threat_id = "2147624835"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c7 45 fc 11 00 00 00 8b 85 a8 fe ff ff 03 85 9c fe ff ff [0-6] 89 85}  //weight: 4, accuracy: Low
        $x_4_2 = {8b 85 a4 fd ff ff 03 85 98 fd ff ff [0-6] 89 45 8c}  //weight: 4, accuracy: Low
        $x_1_3 = {66 81 7d e0 ff 00 75 08 66 c7 45 e0 0e 00 eb 0e 66 8b 45 e0 66 05 01 00 70 ?? 66 89 45 e0}  //weight: 1, accuracy: Low
        $x_1_4 = {66 b9 59 00 e8 ?? ?? ff ff ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb 0b e8 ?? ?? ff ff 89 85 ?? ff ff ff 66 b9 50 00}  //weight: 1, accuracy: Low
        $x_1_5 = {58 59 59 59 6a 04 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_6 = {58 59 59 59 [0-32] c7 45 ?? 59 50 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AS_2147625219_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AS"
        threat_id = "2147625219"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 65 6d 6f 72 79 45 78 65 63 75 74 65 00 00 00 44 65 63 6f 6d 70 72 65 73 73 00 00 4d 6d 61 69 6e 00 00 00 43 41 42 4e 00 00 00 00 50 72 6f 6a 65 63 74 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 45 00 78 00 00 00 00 00 20 00 00 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 45 00 78 00 00 00 00 00 18 00 00 00 52 00 65 00 73 00 75 00 6d 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AV_2147625367_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!AV"
        threat_id = "2147625367"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 e9 03 00 00 68 e8 03 00 00 e8 ?? ?? ?? ?? 8b d0 8d 4d b4 e8 ?? ?? ?? ?? 8d 4d 98 e8 ?? ?? ?? ?? c7 45 fc 04 00 00 00 33 d2 8d 4d 98 e8 ?? ?? ?? ?? 8d 45 98 50 68 ea 03 00 00 68 e8 03 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {68 f5 03 00 00 68 e8 03 00 00 e8 ?? ?? ?? ?? 8b d0 8d 8d ?? ?? ff ff e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 8d ?? ?? ff ff e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 8d ?? ?? ff ff e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 e8}  //weight: 1, accuracy: Low
        $x_10_3 = {66 8b d7 66 c1 fa 0f 8b da (33 1d ?? ?? ?? ?? 33|33 55 ac 33 1d ?? ?? ?? ??) 66 3b da 7f 39 0f bf d9 3b de 72 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AU_2147625458_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AU"
        threat_id = "2147625458"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 35 08 00 0f bf c0 50 8d 4d}  //weight: 2, accuracy: High
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "EncryptByte" ascii //weight: 1
        $x_1_4 = "!!!!!=)" wide //weight: 1
        $x_1_5 = "Skipjack EncryptFile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AV_2147625460_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AV"
        threat_id = "2147625460"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Blowfish decryption" wide //weight: 1
        $x_1_2 = "23lenrek" wide //weight: 1
        $x_1_3 = "SetThreadContext" wide //weight: 1
        $x_1_4 = "EncryptFile" ascii //weight: 1
        $x_5_5 = "WriteProcessMemory" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AX_2147625484_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!AX"
        threat_id = "2147625484"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptDecrypt" ascii //weight: 1
        $x_1_2 = "modCrypt" ascii //weight: 1
        $x_1_3 = "modMain" ascii //weight: 1
        $x_1_4 = "Cryptographic Provider" wide //weight: 1
        $x_1_5 = "WriteProcessMemory" wide //weight: 1
        $x_1_6 = "ZwUnmapViewOfSection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AW_2147625508_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AW"
        threat_id = "2147625508"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 6f 4e 6f 74 43 61 6c 6c 00 00 00 43 61 6c 6c 41 50 49 42 79 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 00 72 00 65 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 57 00 00 00 00 00 0a 00 00 00 6e 00 74 00 64 00 6c 00 6c 00 00 00 28 00 00 00 4e 00 74 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 00 00 00 00 1c 00 00 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 45 00 78 00 00 00 00 00 08 00 00 00 50 00 61 00 53 00 53 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AX_2147625509_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AX"
        threat_id = "2147625509"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 6f 64 4d 61 69 6e 00 4d 6f 64 52 75 6e 74 69 6d 65 00 00 4d 6f 64 44 65 63 6f 64 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 00 00 43 00 3a 00 5c 00 61 00 6e 00 61 00 6c 00 79 00 7a 00 65 00 72 00 5c 00 73 00 63 00 61 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6e 00 74 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 00 00 28 00 00 00 5a 00 77 00 55 00 6e 00 6d 00 61 00 70 00 56 00 69 00 65 00 77 00 4f 00 66 00 53 00 65 00 63 00 74 00 69 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AY_2147625510_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AY"
        threat_id = "2147625510"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 00 45 00 20 00 73 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 00 00 00 00 3a 00 00 00 43 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 76 00 69 00 63 00 74 00 69 00 6d 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {f5 04 00 00 00 04 ?? ?? 6c ?? ?? f5 08 00 00 00 aa 6c ?? ?? 0a 0e 00 14 00 3c 6c ?? ?? 6c ?? ?? aa 71 ?? ?? 04 ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AZ_2147625550_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!AZ"
        threat_id = "2147625550"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "EncryptFile" ascii //weight: 3
        $x_3_2 = "WriteProcessMemory" wide //weight: 3
        $x_3_3 = "SetThreadContext" wide //weight: 3
        $x_3_4 = "23lenrek" wide //weight: 3
        $x_1_5 = "TEA decryption" wide //weight: 1
        $x_1_6 = "Blowfish decryption" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AZ_2147625571_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AZ"
        threat_id = "2147625571"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 52 75 6e 50 45 00 00 53 74 75 62 4d 6f 64 75 6c 65 00 00 53 74 75 62 50 72 6f 6a 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 00 5a 00 20 00 73 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 21 00 00 00 1e 00 00 00 46 00 69 00 6c 00 65 00 20 00 6c 00 6f 00 61 00 64 00 20 00 65 00 72 00 72 00 6f 00 72 00 00 00 2e 00 00 00 50 00 45 00 20 00 73 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 21 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BA_2147625574_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BA"
        threat_id = "2147625574"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 52 75 6e 50 45 00 00 6d 50 72 6f 63 65 73 73 00 00 00 00 6d 43 6f 6e 74 65 78 74 00 00 00 00 52 63 34 00 46 6f 72 6d 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 00 5a 00 20 00 73 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 21 00 00 00 1e 00 00 00 46 00 69 00 6c 00 65 00 20 00 6c 00 6f 00 61 00 64 00 20 00 65 00 72 00 72 00 6f 00 72 00 00 00 2e 00 00 00 50 00 45 00 20 00 73 00 69 00 67 00 6e 00 61 00 74 00 75 00 72 00 65 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 21 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BB_2147625576_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BB"
        threat_id = "2147625576"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 74 61 72 74 00 00 00 52 43 34 00 46 6f 72 6d 31 00 00 00 4d 6f 64 75 6c 65 32 00 50 72 6f 6a 65 63 74 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {f5 00 00 00 00 59 ?? ?? f5 04 00 00 00 04 ?? ?? 6c ?? ?? f5 08 00 00 00 aa 6c ?? ?? 0a 09 00 14 00 3c 1e 6f 04 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BB_2147625621_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BB"
        threat_id = "2147625621"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 fc 11 00 00 00 8b 85 a8 fe ff ff 03 85 9c fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {74 00 78 00 65 00 74 00 6e 00 6f 00 43 00 64 00 61 00 65 00 72 00 68 00 54 00 74 00 65 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {31 45 d4 8b 45 c0 31 45 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BC_2147625833_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BC"
        threat_id = "2147625833"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 70 00 00 00 8b 85 ?? (fa|fb) ff ff 03 85 ?? fd ff ff 89 85 ?? (fb|fc) ff ff c7 45 fc 71 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc 10 00 00 00 81 bd ?? (fd|fc) ff ff 50 45 00 00 74 05 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 51 14 8b 40 0c 8a 04 10 32 05 ?? ?? ?? ?? 8b 4d 08 8b 09 8b 55 08 8b 12 8b 35 ?? ?? ?? ?? 2b 72 14 8b 49 0c 88 04 31 c7 45 fc 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BE_2147625880_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BE"
        threat_id = "2147625880"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\Angelical\\Mis documentos\\Arma X 2 Source\\" wide //weight: 5
        $x_2_2 = "##SS##" wide //weight: 2
        $x_2_3 = "IIIIIIIIIIIIIIIIIIIIOIKKKKKKKKK" wide //weight: 2
        $x_3_4 = {6a 04 51 56 c7 45 ?? 58 59 59 59 e8}  //weight: 3, accuracy: Low
        $x_2_5 = {66 0f b6 0c 11 66 33 0c 70 ff 15 ?? ?? ?? ?? 8b 0b 8b 75 ?? 8b 51 0c 88 04 3a}  //weight: 2, accuracy: Low
        $x_1_6 = "txetnoCdaerhTteG" wide //weight: 1
        $x_1_7 = "23LENREK" wide //weight: 1
        $x_1_8 = "noitceSfOweiVpamnUtN" wide //weight: 1
        $x_1_9 = "xEcollAlautriV" wide //weight: 1
        $x_1_10 = "yromeMssecorPetirW" wide //weight: 1
        $x_1_11 = "txetnoCdaerhTteS" wide //weight: 1
        $x_1_12 = "daerhTemuseR" wide //weight: 1
        $x_1_13 = "yromeMlautriVetirWtN" wide //weight: 1
        $x_1_14 = "daerhTtxetnoCteGtN" wide //weight: 1
        $x_1_15 = "daerhTtxetnoCteStN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_BG_2147625893_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BG"
        threat_id = "2147625893"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Slayer616sSource" wide //weight: 10
        $x_20_2 = {6d 6f 64 49 6e 6a 65 63 74 00 00 00 6d 6f 64 43 72 79 70 74 54 65 78 74 00 00 00 00 43 52 69 6a 6e 64 61 65 6c 00}  //weight: 20, accuracy: High
        $x_10_3 = {62 79 74 4d 65 73 73 61 67 65 00 00 62 79 74 50 61 73 73 77 6f 72 64 00 62 79 74 49 6e 00}  //weight: 10, accuracy: High
        $x_3_4 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 00 00}  //weight: 3, accuracy: High
        $x_3_5 = {4e 00 74 00 53 00 65 00 74 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 00 00}  //weight: 3, accuracy: High
        $x_3_6 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 45 00 78 00 00 00}  //weight: 3, accuracy: High
        $x_3_7 = {4e 00 74 00 52 00 65 00 73 00 75 00 6d 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 00 00}  //weight: 3, accuracy: High
        $x_3_8 = {43 00 72 00 65 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 57 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_3_*))) or
            ((2 of ($x_10_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_BI_2147625917_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BI"
        threat_id = "2147625917"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b d7 66 c1 fa 0f 66 8b da 33 55 ac 66 33 d9 66 3b da 7f 39 0f bf d9 3b de 72 05}  //weight: 1, accuracy: High
        $x_1_2 = {50 45 00 00 0f 85 ?? ?? 00 00 8b 45 10 6a 44 5b ff 30 89 9d 4c fd ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 33 f3 ab 59 8d bd ?? ?? ff ff f3 ab 6a 11 8d bd ?? ?? ff ff 59 33 f6 f3 ab 8d bd ?? ?? ff ff 6a 0c ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BF_2147626145_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BF"
        threat_id = "2147626145"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 18 81 bd ?? ?? ff ff 50 45 00 00 74 0c 83 8d ?? ?? ff ff ff e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 18 32 1d ?? ?? ?? ?? ff 37 e8 ?? ?? ff ff 88 18 a1 ?? ?? ?? ?? 83 c0 01 70 15 3b 45 0c a3 ?? ?? ?? ?? 0f 8e}  //weight: 1, accuracy: Low
        $x_1_3 = {fe ff ff 83 c4 14 03 85 90 fd ff ff ba ?? ?? ?? ?? 8d 8d fc fc ff ff 0f 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BG_2147626171_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BG"
        threat_id = "2147626171"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe ff ff 50 45 00 00 0f 85 03 00 81 bd}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 54 03 85 ?? fd ff ff ba ?? ?? ?? ?? 0f 80}  //weight: 1, accuracy: Low
        $x_2_3 = {66 8b d7 66 c1 fa 0f 8b da 33 1d ?? ?? ?? ?? 33 55 ?? 66 3b da 7f 39 0f bf d9 3b de 72 05}  //weight: 2, accuracy: Low
        $x_2_4 = {7f 28 66 b9 cc 00 e8 ?? ?? ff ff 57 ff 35 ?? ?? ?? ?? 8a d8 e8 ?? ?? ff ff 88 18 6a 01 58 03 c7 0f 80 ?? ?? ?? ?? 8b f8 eb d3 66 b9 58 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_BH_2147626278_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BH"
        threat_id = "2147626278"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50}  //weight: 2, accuracy: Low
        $x_2_2 = {b9 59 00 00 00 ff d6 8b 55 ?? b9 58 00 00 00 88 02 ff d6 8b 4d ?? 88 41 01 b9 51 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {89 85 78 ff ff ff b9 f8 00 00 00 [0-7] 8a d0 8b 45 e0 8b 7d e4 8b 48 0c 8a 04 19 8b cf 22 d0}  //weight: 2, accuracy: Low
        $x_1_4 = {ff ff 01 00 00 00 c7 85 ?? ?? ff ff 02 00 00 00 89 5d ?? 89 85 ?? ff ff ff c7 85 ?? ff ff ff 08 00 00 00 74 ?? 66 83 39 01 75}  //weight: 1, accuracy: Low
        $x_1_5 = {66 3b 75 a0 7f 5e 8b 07 8d 4d c8 0f bf d6 51 52 50 c7 45 d0 01 00 00 00 c7 45 c8 02 00 00 00}  //weight: 1, accuracy: High
        $x_2_6 = {b9 c3 00 00 00 ff d6 88 45 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? b9 cc 00 00 00 ff d6}  //weight: 2, accuracy: Low
        $x_2_7 = {8b 40 3c 03 c3 89 45 ?? 8b 45 ?? 8b 40 28 03 c3 c6 00 b8 40 03 5f 14 89 18 83 c0 04 66 c7 00 ff e0}  //weight: 2, accuracy: Low
        $x_2_8 = {6a 01 89 08 8b 4d ?? 89 50 04 8b 55 ?? 89 48 08 8d 4d ?? 89 50 0c 8d 45 ?? 50 51}  //weight: 2, accuracy: Low
        $x_2_9 = {8b 49 0c 68 f8 00 00 00 03 c8 8d 95 ?? ?? ff ff 51 52 e8 ?? ?? ?? ?? ff d7 8d 85 ?? ?? ff ff 50 ff ?? 81 bd ?? ?? ff ff 50 45 00 00}  //weight: 2, accuracy: Low
        $x_1_10 = {53 00 62 00 69 00 65 00 44 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {26 00 48 00 43 00 43 00 00 00}  //weight: 1, accuracy: High
        $n_10_12 = "Audit Commander" ascii //weight: -10
        $n_100_13 = {70 74 72 61 66 66 65 72 2e 72 75 2f 00}  //weight: -100, accuracy: High
        $n_100_14 = "pTraffer.ucListView" ascii //weight: -100
        $n_888_15 = "Cannot prepare the error notification email. Please copy the information and send to HydroComp by separate email" wide //weight: -888
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_BI_2147626356_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BI"
        threat_id = "2147626356"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fb 12 fc 0d 6c 6c ff 80 0c 00 fc a0 6c 6c ff 6c 5c ff e0 1c}  //weight: 1, accuracy: High
        $x_1_2 = {f5 58 59 59 59 59 40 ff 6c 6c ff 0a 03 00 0c 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 62 67 74 68 69 73 00 41 53 44 78 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 00 74 00 57 00 72 00 69 00 74 00 65 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {4e 00 74 00 52 00 65 00 73 00 75 00 6d 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BJ_2147626496_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BJ"
        threat_id = "2147626496"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a8 fe ff ff 03 ?? 9c fe ff ff 0f 80 ?? ?? ?? ?? 89 ?? 58 fe ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 56 6c 8b 46 78 [0-3] 03 d0 [0-6] 89 96 c8 02 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {8a 1c 10 03 cb 0f 80 ?? ?? ?? ?? 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 89 4d}  //weight: 1, accuracy: Low
        $x_1_4 = {58 59 59 59 6a 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_BK_2147626736_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BK"
        threat_id = "2147626736"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Zcvnjmpcp,cvc" wide //weight: 1
        $x_1_2 = "ZGlrcplcr" wide //weight: 1
        $x_1_3 = "EcrKmbsjcF_lbjcU" wide //weight: 1
        $x_1_4 = "UpgrcNpmacqqKckmpw" wide //weight: 1
        $x_1_5 = "LrSlk_nTgcuMdQcargml" wide //weight: 1
        $x_1_6 = ": GdoKtW =" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule VirTool_Win32_VBInject_BL_2147626788_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BL"
        threat_id = "2147626788"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 6e 00 00 00 8b 85 ?? ?? ff ff 03 85 ?? ?? ff ff 89 85 ?? ?? ff ff c7 45 fc 6f 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 4d 5a 00 00 74 05 e9}  //weight: 1, accuracy: High
        $x_1_3 = {8b 51 0c 2b 51 14 0f b6 4c 02 02 03 d0 0f b6 1c 39 0f b6 42 01}  //weight: 1, accuracy: High
        $x_1_4 = {3b d9 7f 13 a1 ?? ?? ?? ?? 8b 70 0c 2b 70 14 c6 04 1e cc 03 da eb e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_BM_2147626855_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BM"
        threat_id = "2147626855"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 6f 64 52 43 34 00}  //weight: 1, accuracy: High
        $x_2_2 = {6d 6f 64 49 6e 6a 65 63 74 00}  //weight: 2, accuracy: High
        $x_2_3 = {6d 6f 64 41 6e 74 69 56 4d 00}  //weight: 2, accuracy: High
        $x_1_4 = {6a 53 50 ff d6 8d 8d ?? ?? ff ff 6a 65 51 ff d6 8d 95 ?? ?? ff ff 6a 72}  //weight: 1, accuracy: Low
        $x_2_5 = {6a 52 51 ff d6 8d 95 ?? ?? ff ff 6a 45 52 ff d6 8d 85 ?? ?? ff ff 6a 2a}  //weight: 2, accuracy: Low
        $x_3_6 = {6a 42 52 ff d6 8d 85 ?? ?? ff ff 6a 4f 50 ff d6 8d 8d ?? ?? ff ff 6a 58 51 ff d6 8d 95 ?? ?? ff ff 6a 2a}  //weight: 3, accuracy: Low
        $x_1_7 = {6a 04 51 56 c7 45 ?? 58 59 59 59 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_BO_2147626920_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BO"
        threat_id = "2147626920"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fc 6c 34 fe aa 71 6c fd 00 0d f5 1e 00 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {fb 12 fc 0d 6c 6c ff 80 0c 00 fc a0 [0-3] 6c 6c ff 6c 5c ff e0 1c}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 41 00 00 00 04 e0 fe ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 6c 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 72 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f5 74 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? fb ef 50 fe f5 44 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_BP_2147627025_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BP"
        threat_id = "2147627025"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 58 fc 0d f5 00 00 00 00 04 58 ff fc a0 f4 59 fc 0d}  //weight: 1, accuracy: High
        $x_1_2 = {f5 58 59 59 59 59 ?? ff 6c 6c ff}  //weight: 1, accuracy: Low
        $x_4_3 = {6c 70 fe 6c 64 fe aa 71 9c fd}  //weight: 4, accuracy: High
        $x_4_4 = {6c 78 fe 6c 6c fe aa 71 ec fd}  //weight: 4, accuracy: High
        $x_4_5 = {6c 68 fe 6c 5c fe aa 71 8c fd}  //weight: 4, accuracy: High
        $x_4_6 = {6c 74 fe 6c 68 fe aa 71 a0 fd}  //weight: 4, accuracy: High
        $x_1_7 = {f4 1e a9 e7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 68 ff 18 00}  //weight: 1, accuracy: Low
        $x_1_8 = {6b 6e ff 6b 6c ff fb 12 e7 04 44 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_BQ_2147627066_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BQ"
        threat_id = "2147627066"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {94 84 fc 1c 00 94 84 fc 10 00 aa 71 9c fd 04}  //weight: 1, accuracy: High
        $x_1_2 = {f4 10 a9 e7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 68 ff 18 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BT_2147627402_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BT"
        threat_id = "2147627402"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 00 8b 42 0c 8b 72 14 8b 15 ?? ?? ?? ?? 2b c6 8a 1c 02 03 d0 32 d9 88 1a}  //weight: 1, accuracy: Low
        $x_1_2 = {66 8b c2 66 c1 f8 0f 66 8b d8 66 33 d9 66 89 0d ?? ?? ?? ?? 33 c6 66 3b d8 7f 1d}  //weight: 1, accuracy: Low
        $x_1_3 = {68 f8 00 00 00 03 c8 51 8d 95 ?? ?? ff ff 52 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 81 bd ?? ?? ff ff 50 45 00 00 74 14}  //weight: 1, accuracy: Low
        $x_1_4 = {b9 01 00 00 00 33 c0 3b 45 ?? 7f 14 8b 15 ?? ?? ?? ?? 8b 72 0c 2b 72 14 c6 04 06 cc 03 c1 eb e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_BU_2147627404_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BU"
        threat_id = "2147627404"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 80 fc 1c 00 94 80 fc 10 00 aa 71 9c fd}  //weight: 1, accuracy: High
        $x_1_2 = {55 00 70 00 67 00 72 00 63 00 4e 00 70 00 6d 00 61 00 63 00 71 00 71 00 4b 00 63 00 6b 00 6d 00 70 00 77 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 00 72 00 51 00 63 00 72 00 41 00 6d 00 6c 00 72 00 63 00 76 00 72 00 52 00 66 00 70 00 63 00 5f 00 62 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BV_2147627443_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BV"
        threat_id = "2147627443"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 78 fe 6c 6c fe aa 71 a4 fd}  //weight: 1, accuracy: High
        $x_1_2 = {55 00 70 00 67 00 72 00 63 00 4e 00 70 00 6d 00 61 00 63 00 71 00 71 00 4b 00 63 00 6b 00 6d 00 70 00 77 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {51 00 63 00 72 00 52 00 66 00 70 00 63 00 5f 00 62 00 41 00 6d 00 6c 00 72 00 63 00 76 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {f4 02 a9 e7 71 70 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_BW_2147627539_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BW"
        threat_id = "2147627539"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6c 78 fe 6c 6c fe aa 71 a4 fd}  //weight: 5, accuracy: High
        $x_1_2 = {fb 11 6c 78 ff 04 4c ff fc a0 04 78 ff 66 10 ff 8c 00 f5 08 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {f4 58 fc 0d f5 00 00 00 00 04 ?? ff fc a0 [0-2] f4 59 fc 0d f5 01 00 00 00 04 ?? ff fc a0 [0-2] f4 59 fc 0d f5 02}  //weight: 1, accuracy: Low
        $x_1_4 = {6b 6e ff 6b 6c ff fb 12 e7 04 44 ff}  //weight: 1, accuracy: High
        $x_1_5 = {f3 c3 00 fc 0d [0-9] f3 cc 00 fc 0d}  //weight: 1, accuracy: Low
        $x_1_6 = {f5 58 59 59 59 59 [0-48] f3 59 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_BX_2147627659_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BX"
        threat_id = "2147627659"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 1c fb 1c 00 94 1c fb 10 00 aa 71 24 fc 04 60}  //weight: 1, accuracy: High
        $x_1_2 = {94 54 fa 1c 00 94 54 fa 10 00 aa 71 9c fd}  //weight: 1, accuracy: High
        $x_2_3 = "8B4C240851<PATCH1>E8<PATCH2>5989016631C0C3" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_BY_2147627686_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!BY"
        threat_id = "2147627686"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ff 00 00 00 3b f0 7f 2e 81 fe 00 01 00 00 72 06 ff 15 ?? ?? ?? ?? 8b ce ff 15 ?? ?? ?? ?? 8b 4f ?? 66 89 04 71 b8 01 00 00 00 03 c6 0f 80 ?? ?? ?? ?? 8b f0 eb c9}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 ff 00 00 00 66 3b f0 7f 2a 0f bf fe 81 ff 00 01 00 00 72 06 ff 15 ?? ?? ?? ?? 8b 55 d0 b8 01 00 00 00 66 03 c6 66 89 34 7a 0f 80}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 01 51 56 c7 45 ?? e8 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 04 51 56 c7 45 9c 58 59 59 59 e8}  //weight: 1, accuracy: High
        $x_1_5 = {6a 01 50 0f 80 8b 00 00 00 56 c7 45 a0 c3 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_6 = {8d 45 e0 50 e8 ?? ?? ?? ?? 33 db 66 3d ff ff 8d 4d e4 0f 94 c3 51 f7 db e8 ?? ?? ?? ?? 33 d2 66 3d ff ff 0f 94 c2 8d 45 e8}  //weight: 1, accuracy: Low
        $x_1_7 = {45 6e 63 72 79 70 74 44 61 74 61 00 44 65 63 72 79 70 74 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_8 = {4b 65 79 00 45 6e 63 72 79 70 74 46 69 6c 65 00 44 65 63 72 79 70 74 46 69 6c 65 00 44 65 63 72 79 70 74 42 79 74 65 00}  //weight: 1, accuracy: High
        $x_1_9 = "Pimp Crypter 2.0 private version" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_CA_2147627709_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CA"
        threat_id = "2147627709"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 0c 2b 48 14 8b 85 ?? ?? ff ff 03 4d c0 51 8b 4d b8 03 c8 51 ff b5 ?? ?? ff ff e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 6a 01 58 01 45 e8 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CB_2147627790_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CB"
        threat_id = "2147627790"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 95 b4 fe ff ff 8b 85 a8 fe ff ff 03 c2 83 c4 24 ba}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 0a 8a 14 18 8b 45 ec 8b 48 0c 2b 48 14 a1 ?? ?? ?? ?? 30 14 01}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 9c 58 59 59 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CC_2147627866_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CC"
        threat_id = "2147627866"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6c 68 fe 6c 5c fe aa 71 94 fd}  //weight: 2, accuracy: High
        $x_1_2 = {f4 59 fc 0d f5 04 00 00 00 04 58 ff fc a0 f4 50 fc 0d f5 05 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {f5 fe 00 00 00 c2 04 58 ff 9d 44 2c ff fb 94 1c ff fc 22 04 58 ff 9d fb 12}  //weight: 1, accuracy: High
        $x_1_4 = {6d 4d 41 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_CD_2147628095_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CD"
        threat_id = "2147628095"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 8c fe ff ff 03 85 80 fe ff ff 0f 80 ?? ?? 00 00 89 85 f4 fd ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 85 a8 fe ff ff 03 85 9c fe ff ff 0f 80 ?? ?? 00 00 89 85 ?? fe ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 88 fe ff ff 03 85 7c fe ff ff 0f 80 ?? ?? 00 00 89 85 f0 fd ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 85 dc fe ff ff 03 85 58 fd ff ff [0-6] 89 85 90 fe ff ff}  //weight: 1, accuracy: Low
        $x_4_5 = {66 b9 c3 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 b9 cc 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_CE_2147628162_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CE"
        threat_id = "2147628162"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f5 04 00 00 00 f5 58 59 59 59 59 40 ff 6c 6c ff}  //weight: 1, accuracy: High
        $x_1_2 = {6c b0 fe 6c a4 fe aa 71 9c fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CE_2147628162_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CE"
        threat_id = "2147628162"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 33 c0 8a 04 13 8b 55 00 8a 0c 08 8b 42 0c 8b 72 14 8b 15 ?? ?? ?? ?? 2b c6 88 0d ?? ?? ?? ?? 03 d0 8a 1a 32 d9 88 1a 8b 0d ?? ?? ?? ?? 41 3b cf 89 0d ?? ?? ?? ?? 0f 8e ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {52 ff d7 6a 47 8d 85 ?? ?? ff ff 50 ff d7 6a 6f 8d 8d ?? ?? ff ff 51 ff d7 6a 54 8d 95 ?? ?? ff ff 52 ff d7 6a 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CB_2147628300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.CB"
        threat_id = "2147628300"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\_loaderVB\\" wide //weight: 1
        $x_1_2 = {73 46 69 6c 65 4e 61 6d 65 00 00 00 6c 70 42 79 74 65 00 00 55 73 65 72 4b 65 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CF_2147628431_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CF"
        threat_id = "2147628431"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0c 1a 8b 5d ?? 8b d3 33 c1 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42}  //weight: 2, accuracy: Low
        $x_2_2 = {05 f8 00 00 00 0f 80 ?? ?? 00 00 6b d2 28 0f 80 ?? ?? 00 00 03 c2 8b 51}  //weight: 2, accuracy: Low
        $x_1_3 = "Select * from Win32_Process Where Name = '" wide //weight: 1
        $x_1_4 = {fe ff ff 50 45 00 00 0f 85 03 00 81 bd}  //weight: 1, accuracy: Low
        $x_2_5 = {8d 4e 58 ba ?? ?? 40 00 c7 85 ?? ?? ff ff 07 00 01 00 ff 15 ?? ?? ?? ?? 8b 0e 8d 46 58 50 56 ff 51}  //weight: 2, accuracy: Low
        $x_1_6 = {44 65 6d 64 61 44 61 74 61 57 57 57 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 62 79 74 49 6e 57 57 57 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 62 79 74 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: Low
        $x_3_7 = {ff ff 03 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 00 00 00 c7 85 ?? ?? ff ff 00 30 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 00 00 00 c7 85 ?? ?? ff ff 40 00 00 00 c7 85 ?? ?? ff ff 03 00 00 00}  //weight: 3, accuracy: Low
        $x_1_8 = "C:\\Documents and Settings\\LuisN2" wide //weight: 1
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

rule VirTool_Win32_VBInject_CG_2147628550_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CG"
        threat_id = "2147628550"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {94 78 fc 1c 00 94 78 fc 10 00 aa 71 9c fd}  //weight: 1, accuracy: High
        $x_1_2 = {8b 40 1c 03 41 10 [0-6] 89 85 40 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 a8 fe ff ff 03 85 b4 fe ff ff [0-13] 89 85 24 fe ff ff}  //weight: 1, accuracy: Low
        $x_3_4 = {38 00 42 00 34 00 43 00 32 00 34 00 30 00 38 00 35 00 31 00 3c 00 [0-32] 3e 00 45 00 38 00 3c 00 [0-32] 3e 00 35 00 39 00 38 00 39 00 30 00 31 00 36 00 36 00 33 00 31 00 43 00 30 00 43 00 33 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_CH_2147628583_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CH"
        threat_id = "2147628583"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c b8 fc 6c 34 fe aa 71 6c fd 00}  //weight: 1, accuracy: High
        $x_1_2 = {f5 50 45 00 00 cc 1c ?? ?? 00 02 00 1e f5 44 00 00 00 6c 84 fc ae fd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CI_2147628726_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CI"
        threat_id = "2147628726"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 f8 00 00 00 0f 80 ?? ?? ?? ?? 8b 4d ?? 6b c9 28 0f 80 ?? ?? ?? ?? 03 c1 0f 80 08 00 [0-3] 6a 28 8b (85|45)}  //weight: 2, accuracy: Low
        $x_2_2 = {66 b9 59 00 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb 0b e8 ?? ?? ?? ?? 89 85 ?? ?? ff ff 66 b9 50 00}  //weight: 2, accuracy: Low
        $x_2_3 = {00 30 00 00 c7 85 ?? ?? ?? ?? 03 00 00 00 8d b5 ?? ?? ?? ?? 6a 03 ff b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 40 00 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {58 59 59 59 6a 04 03 00 c7 45}  //weight: 2, accuracy: Low
        $x_3_5 = "El Bruto crypter" wide //weight: 3
        $x_1_6 = "M3M0Ry" ascii //weight: 1
        $x_1_7 = {00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_CN_2147629352_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CN"
        threat_id = "2147629352"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6c b0 fe 6c a4 fe aa [0-13] 71 8c fd}  //weight: 3, accuracy: Low
        $x_3_2 = {6c b0 fe fd 69 ?? fc [0-16] 6c a4 fe fd 69 ?? fc [0-40] 71 8c fd}  //weight: 3, accuracy: Low
        $x_3_3 = {6c 78 fe 6c 6c fe aa 71 90 fd}  //weight: 3, accuracy: High
        $x_3_4 = {6c 78 fe fd 69 [0-16] 6c 6c fe fd 69 [0-32] 71 ec fd}  //weight: 3, accuracy: Low
        $x_3_5 = {6c 44 ff 94 08 00 fc 01 aa 99 08 00 98 01 1b}  //weight: 3, accuracy: High
        $x_3_6 = {6c ec fc 6c 68 fe aa 71 a0 fd}  //weight: 3, accuracy: High
        $x_1_7 = {f3 c3 00 fc 0d [0-9] f3 cc 00 fc 0d}  //weight: 1, accuracy: Low
        $x_1_8 = {f5 04 00 00 00 f5 58 59 59 59}  //weight: 1, accuracy: High
        $x_1_9 = {f4 58 fc 0d [0-17] f4 59 fc 0d [0-17] f4 59 fc 0d [0-17] f4 59 fc 0d}  //weight: 1, accuracy: Low
        $x_2_10 = {ff f5 f8 00 00 00 aa f5 28 00 00 00 6c ?? ff b2 aa f5 (0c|14) 00 00 00 aa 02 00 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_CP_2147629820_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CP"
        threat_id = "2147629820"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 04 06 cc 03 c1 eb ?? 8d 45 ?? 50 c6 45 ?? 58 e8 ?? ?? ?? ?? 8d 4d ?? 51 c6 45 ?? 59 a1 ?? ?? ?? ?? 8b 50 14 8b 48 0c 2b ca 8b 54 24 04 8a 02 8b 15 ?? ?? ?? ?? 88 04 11 ff ?? ?? ?? ?? 00 c2 04 00}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 04 13 8b 55 00 8b 72 14 8a 0c 08 8b 42 0c 8b 15 ?? ?? ?? ?? 2b c6 03 d0 88 0d ?? ?? ?? ?? 30 0a 8b 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 00 30 00 00 2b 48 14 8d 95 ?? ?? ff ff c1 e1 04 03 48 0c ff d7 8b 85 ?? ?? ff ff c7 85 ?? ?? ff ff 40 00 00 00 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DD_2147629840_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.DD"
        threat_id = "2147629840"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 05 00 00 00 c2 f5 02 00 00 00 aa fb 13 fc}  //weight: 1, accuracy: High
        $x_1_2 = {e7 f5 4d 5a 00 00 cc 1c ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {4a c2 f5 01 00 00 00 aa [0-31] e7 fb 13}  //weight: 1, accuracy: Low
        $x_1_4 = {f3 e8 00 2b ?? ?? 6c ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_CQ_2147629920_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CQ"
        threat_id = "2147629920"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f5 08 c5 bb 6c c7 1c ee 01}  //weight: 1, accuracy: High
        $x_1_2 = {f5 88 6a 3f 24 f5 00 00 00 00 08 08 00 06 40 00 a3 00 13 f5 d3 08 a3 85 f5 01 00 00 00 08 08 00 06 40 00 a3 00 13 f5 2e 8a 19 13}  //weight: 1, accuracy: High
        $x_1_3 = "4E7457726974655669727475616C4D656D6F7279" wide //weight: 1
        $x_1_4 = "8B4C240851<PATCH1>E8<PATCH2>5989016631C0C3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CT_2147629981_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CT"
        threat_id = "2147629981"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {94 40 fc 1c 00 94 40 fc 10 00 aa 71 90 fd}  //weight: 1, accuracy: High
        $x_1_2 = {38 00 42 00 34 00 43 00 32 00 34 00 30 00 38 00 35 00 31 00 3c 00 50 00 41 00 54 00 43 00 48 00 ?? ?? 3e 00 45 00 38 00 3c 00 50 00 41 00 54 00 43 00 48 00 ?? ?? 3e 00 35 00 39 00 38 00 39 00 30 00 31 00 36 00 36 00 33 00 31 00 43 00 30 00 43 00 33 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CU_2147630094_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CU"
        threat_id = "2147630094"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7f 24 66 b9 cc 00 e8 ?? ?? ?? ?? 50 53 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c6 03 c3 0f 80 ?? ?? ?? ?? 8b d8 eb d2}  //weight: 1, accuracy: Low
        $x_1_2 = {66 b9 e8 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {66 2b c7 0f 80 ?? ?? 00 00 0f bf c0 50 8b 45 10 ff 30}  //weight: 1, accuracy: Low
        $x_1_4 = {75 18 68 92 00 00 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 66 83 08 ff c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_DH_2147630125_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.DH"
        threat_id = "2147630125"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 16 00 00 00 8d 45 d8 50 8d 45 dc 50 e8 ?? ?? ff ff c7 45 fc 17 00 00 00 8d 45 d8 50 8d 45 dc 50 e8 ?? ?? ff ff c7 45 fc 18 00 00 00 c7 [0-5] e8 03 00 00 c7 [0-5] 01 00 00 00 c7 [0-5] 01 00 00 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CV_2147630205_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CV"
        threat_id = "2147630205"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 88 fc 1c 00 94 88 fc 10 00 aa 71 9c fd}  //weight: 1, accuracy: High
        $x_1_2 = {94 0c fc 1c 00 94 0c fc 10 00 aa 71 60 fd}  //weight: 1, accuracy: High
        $x_2_3 = {6c 74 ff ae f5 05 00 00 00 ae 71 74 ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DJ_2147630296_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.DJ"
        threat_id = "2147630296"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f b6 0c 08 8b 45 c4 66 33 0c 50 ff 15 ?? ?? ?? ?? 8b 4d a8 8b 51 0c 8b 4d e8 88 04 1a b8 01 00 00 00 03 c1 0f 80}  //weight: 1, accuracy: Low
        $x_1_2 = {74 3f 66 83 38 01 75 39 8b 35 ?? ?? ?? ?? 8b cf 81 c6 f8 00 00 00 8b 50 14}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 c0 8d 45 e8 50 8b 85 c4 fe ff ff 8d 8d ac fe ff ff 83 c2 08 6a 04 51 0f 80 ?? ?? ?? ?? 52 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CW_2147630471_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CW"
        threat_id = "2147630471"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 85 84 fe ff ff 83 c4 24 03 45 ac}  //weight: 2, accuracy: High
        $x_2_2 = {83 c4 24 8b 45 ac 03 85 84 fe ff ff}  //weight: 2, accuracy: High
        $x_1_3 = {66 b9 c3 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 b9 cc 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c6 45 dc c3 ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 45 dc cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_CX_2147630472_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CX"
        threat_id = "2147630472"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 59 00 00 00 [0-8] b9 58 00 00 00 [0-8] 88 41 01 b9 51 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 45 ec 6b f6 28 8b 51 14 0f 80 ?? ?? ?? ?? 03 f0 8b 41 10 0f 80 ?? ?? ?? ?? 2b f2 3b f0 72 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 d4 fe ff ff 8b 8d cc fd ff ff [0-6] 03 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DN_2147630527_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.DN"
        threat_id = "2147630527"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 fe 00 00 00 c2 04 60 ff 9d e7 aa 04 60 ff 9d fb 12}  //weight: 1, accuracy: High
        $x_1_2 = {e7 f5 4d 5a 00 00 cc 1c ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 50 45 00 00 cc 1c ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_4 = {f5 2a 00 00 00 0b ?? 00 04 00 23 ?? ?? 2a 23 ?? ?? f5 56 00 00 00 0b ?? 00 04 00 23 ?? ?? 2a 23 ?? ?? f5 4d 00 00 00 0b ?? 00 04 00 23 ?? ?? 2a 23 ?? ?? f5 57}  //weight: 1, accuracy: Low
        $x_1_5 = {f3 e8 00 2b ?? ?? 6c ?? ff}  //weight: 1, accuracy: Low
        $x_1_6 = {bc 02 f5 f8 00 00 00 aa f5 28 00 00 00 08 08 00 8a ?? ?? b2 aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_CY_2147630834_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CY"
        threat_id = "2147630834"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 32 00 43 6c 61 73 73 31 00 00 50 72 6f 79 65 63 74 6f 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 65 63 72 79 70 74 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_CZ_2147631125_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!CZ"
        threat_id = "2147631125"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 78 ff 6c 60 ff fc 90 fb 11 fc f0 6e ff 6c 78 ff f5 10 27 00 00 c2 f5 00 00 00 00 c7 1c bc 04}  //weight: 1, accuracy: High
        $x_1_2 = {f5 04 00 00 00 aa 71 6c ff f3 c3 00 2b 46 ff 6c 6c ff f5 01 00 00 00 0a 02 00 0c 00 3c 6c 6c ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_DR_2147631345_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.DR"
        threat_id = "2147631345"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 58 59 59 59 59 ?? ff 6c ?? ff [0-10] f5 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 e8 00 2b ?? ?? 6c ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {80 0c 00 fc 90 6c [0-10] c2 [0-8] fc 90 fb 11}  //weight: 1, accuracy: Low
        $x_1_4 = {fb 11 fc f0 6e ff 6c 78 ff f5 ?? ?? 00 00 c2 f5 ?? ?? 00 00 02 00 fc 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_DV_2147631776_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.DV"
        threat_id = "2147631776"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a c2 f5 01 00 00 00 aa [0-54] fb 12 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 63 00 00 00 04 40 ff 0a 08 00 08 00 f5 6d 00 00 00 04 2c ff 0a 08 00 08 00 f5 64 00 00 00 04 e4 fe 0a 08 00 08 00 f5 20}  //weight: 1, accuracy: High
        $x_1_3 = {f3 e8 00 2b ?? ?? 6c ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_DW_2147631777_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.DW"
        threat_id = "2147631777"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e7 f5 4d 5a 00 00 c7 c3 1c}  //weight: 1, accuracy: High
        $x_1_2 = {f3 00 01 c1 e7 04 ?? ff 9d fb 12 fc 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {4a f5 02 00 00 00 fe 6c 50 ff ba 00 00 05 1e 3a 00 00 6c 6c 60 ff f5 26 00 00 00 04 40 ff 0a 1b 00 08 00 04 40 ff f5 48}  //weight: 1, accuracy: High
        $x_1_4 = "8B4C240851<PATCH1>E8<PATCH2>5989016631C0C3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_DA_2147631791_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DA"
        threat_id = "2147631791"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a c2 f5 01 00 00 00 aa [0-31] e7 fb 13}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 07 00 01 00 08 08 00 8f 05 00 66}  //weight: 1, accuracy: Low
        $x_1_3 = {31 0c ff 04 68 ff 3e 0c ff fd c7 6c ff 3e 10 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_DX_2147631827_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.DX"
        threat_id = "2147631827"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "D:\\S1\\S2\\ProjectCC.vbp" wide //weight: 2
        $x_1_2 = "modShortcuts" ascii //weight: 1
        $x_1_3 = "modCPUInfo" ascii //weight: 1
        $x_1_4 = "clsHuffman" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DB_2147631858_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DB"
        threat_id = "2147631858"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 04 00 00 00 f5 58 59 59 59}  //weight: 1, accuracy: High
        $x_1_2 = {f4 58 fc 0d [0-17] f4 59 fc 0d [0-17] f4 59 fc 0d [0-17] f4 59 fc 0d}  //weight: 1, accuracy: Low
        $x_2_3 = {f5 07 00 01 00 71 ?? ?? f5 00 00 00 00 f5 07 00 00 00 04 ?? ?? ?? 8e 01 00 00 00 10 00 80 08 28 ?? ?? 6b 00 f5 00 00 00 00 6c ?? ?? 52 28 ?? ?? 65 00 f5 01 00 00 00 6c ?? ?? 52 28 ?? ?? 72 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DC_2147631933_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DC"
        threat_id = "2147631933"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 8d ac fe ff ff 8b 95 b8 fe ff ff [0-22] 89 8d 64 fe ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {03 ca 8b 55 ?? 0f 80 ?? ?? ?? ?? 89 8a b0 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {c7 00 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_4 = {b9 59 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {b9 c3 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_EB_2147631959_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.EB"
        threat_id = "2147631959"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Polifemo Ebrio Crypter\\Stub.vbp" wide //weight: 1
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_DD_2147632009_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DD"
        threat_id = "2147632009"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 70 fc 1c 00 94 70 fc 10 00 aa 71 9c fd}  //weight: 1, accuracy: High
        $x_1_2 = {e7 80 0c 00 4a ae 0b 23 00 04 00 23 28 ff 2a}  //weight: 1, accuracy: High
        $x_1_3 = ":;TMVZMS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_EF_2147632052_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.EF"
        threat_id = "2147632052"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e7 f5 4d 5a 00 00 c7 c3 1c}  //weight: 1, accuracy: High
        $x_1_2 = {f4 05 a9 c1 fb 12 fc 0d}  //weight: 1, accuracy: High
        $x_1_3 = "4D5A900 " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_DE_2147632061_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DE"
        threat_id = "2147632061"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 04 00 00 00 f5 58 59 59 59}  //weight: 1, accuracy: High
        $x_1_2 = {f4 58 fc 0d [0-17] f4 59 fc 0d [0-17] f4 59 fc 0d [0-17] f4 59 fc 0d}  //weight: 1, accuracy: Low
        $x_2_3 = {f5 40 00 00 00 f5 00 30 00 00 6c ?? ?? 6c ?? ?? 6c ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_2_4 = {f5 07 00 01 00 71 ?? ?? f5 00 00 00 00 f5 00 00 00 00 04 ?? ?? fe 8e 01 00 00 00 10 00 80 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DF_2147632063_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DF"
        threat_id = "2147632063"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 80 fe 1c 00 94 80 fe 10 00 aa 08 08 00 8f 24 01}  //weight: 1, accuracy: High
        $x_1_2 = {f4 24 fc 0d f5 02 00 00 00 04 50 ff fc a0 f4 08 fc 0d f5 03 00 00 00 04 50 ff fc a0 f4 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_EG_2147632069_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.EG"
        threat_id = "2147632069"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 74 00 78 00 74 00 00 00 00 00 02 00 00 00 5c 00 00 00 08 00 00 00 2e 00 65 00 78 00 65 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5f 5f 76 62 61 4c 61 74 65 4d 65 6d 43 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 6a 01 6a ff 6a 20 ff 15 ?? ?? 40 00 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 03 ff 15 ?? ?? 40 00 [0-6] 83 c4 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-8] c7 85 ?? ff ff ff 08 40 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {57 00 68 00 69 00 74 00 65 00 43 00 6f 00 61 00 74 00 00 00 56 42 41 36 2e 44 4c 4c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_VBInject_EK_2147632085_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.EK"
        threat_id = "2147632085"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Crypt3r\\demonio666vip.vbp" wide //weight: 3
        $x_2_2 = "clsTwofish" ascii //weight: 2
        $x_1_3 = "RtlMoveMemory" ascii //weight: 1
        $x_1_4 = "EncryptByte" ascii //weight: 1
        $x_2_5 = "Indetectables.net" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DG_2147632234_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DG"
        threat_id = "2147632234"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fb 12 fc 0d 6c ?? ?? 80 ?? ?? fc a0}  //weight: 2, accuracy: Low
        $x_1_2 = {f5 07 00 01 00 71 ?? ?? ((??|?? ??) f5 00 00 00 00 f5 ?? 00 00 00 04 ?? ??|1e)}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 58 59 59 59 (71 ?? ?? (14|1e)|59 ?? ?? 6c ?? ?? 0a ?? 00 0c 00 6c ?? ?? f5 ?? 00)}  //weight: 1, accuracy: Low
        $x_1_4 = {58 59 59 59 04 ?? ?? 0a ?? 00 08 00 04 00 fe c1}  //weight: 1, accuracy: Low
        $x_1_5 = {f3 e8 00 2b ?? ?? 6c ?? ?? 0a ?? 00 0c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {f5 e8 00 00 00 71 ?? ?? (14|1e ?? ?? (1e|f4))}  //weight: 1, accuracy: Low
        $x_1_7 = {80 0c 00 fc 90 6c ?? ff 08 08 00 8a 40 00 c2 [0-48] 08 08 00 8a 3c 00 fc 90 fb 11}  //weight: 1, accuracy: Low
        $x_1_8 = "&H59595958" wide //weight: 1
        $x_1_9 = {ad e7 fe 64 84 fc ea 01 f5 28 00 00 00 6c 70 ff f5 f8 00 00 00 aa f5 28 00 00 00 6c 74 ff b2 aa 80 10 00 2e e8 fc 40}  //weight: 1, accuracy: High
        $x_1_10 = {f5 03 00 00 00 6c ?? ?? 52 fe c1 ?? ?? 40 00 00 00 08 00 fe c1 ?? ?? 00 30 00 00}  //weight: 1, accuracy: Low
        $x_1_11 = {ad e7 fe 64 ?? ?? ?? ?? ?? ?? f5 f8 00 00 00 6c ?? ?? aa f5 28 00 00 00 6c ?? ?? b2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DH_2147632252_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DH"
        threat_id = "2147632252"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 94 08 00 28 02 aa 99 08 00 50 01}  //weight: 1, accuracy: High
        $x_1_2 = {f3 c3 00 fc 0d [0-48] f3 cc 00 fc 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {80 0c 00 fc 90 fd d0 08 00 ?? 00 fb 11 94 08 00 ?? 00 80 0c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {ff f5 f8 00 00 00 aa f5 28 00 00 00 6c ?? ff b2 aa f5 (0c|14) 00 00 00 aa 02 00 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_DJ_2147632414_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DJ"
        threat_id = "2147632414"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {aa 08 08 00 8f 28 01 0a 00 94 ?? ?? 1c 00 94 01 10 00}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 44 00 00 00 08 08 00 8f 74 01 f5 07 00 01 00 08 08 00}  //weight: 1, accuracy: High
        $x_1_3 = {4a c2 f5 01 00 00 00 aa [0-31] e7 fb 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_DJ_2147632414_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DJ"
        threat_id = "2147632414"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 03 8b 48 0c 8b 45 c0 66 0f b6 0c 11 66 33 0c 70}  //weight: 1, accuracy: High
        $x_1_2 = ":;TMVZMS" wide //weight: 1
        $x_1_3 = {8b c4 83 c0 04 93 8b e3 8b 5b fc 81 eb ?? ?? 40 00 87 dd 83 bd ?? ?? 40 00 01 0f 84 ?? ?? 00 00 80 bd ?? ?? 40 00 90 74 ?? 8d 85 ?? ?? 40 00 50 ff 95 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_EW_2147632519_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.EW"
        threat_id = "2147632519"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 61 6d 53 74 65 61 6c 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 00 69 00 63 00 74 00 69 00 6d 00 20 00 45 00 6d 00 61 00 69 00 6c 00 20 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff 15 24 10 40 00 8d 55 9c 8d 45 ac 52 8d 4d bc 50 8d 55 cc 51 52 eb 41 8d 55 8c 8d 4d cc c7 45 94 80 af 40 00 c7 45 8c 08 00 00 00 ff 15 7c 10 40 00}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 18 b9 04 00 02 80 b8 0a 00 00 00 66 3b f3 89 4d a4 89 45 9c 89 4d b4 89 45 ac 89 4d c4 89 45 bc 74 43 8d 55 8c 8d 4d cc c7 45 94 30 af 40 00 c7 45 8c 08 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_DL_2147632535_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DL"
        threat_id = "2147632535"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 85 40 fd ff ff 03 85 34 fd ff ff [0-6] 89 45 84}  //weight: 2, accuracy: Low
        $x_1_2 = {66 b9 59 00 e8 [0-56] 66 b9 50 00}  //weight: 1, accuracy: Low
        $x_1_3 = {66 33 0c 42 e8 ?? ?? ff ff 8a d8 ff 75 ?? 8b 45 0c ff 30 e8 ?? ?? ff ff 88 18 8b 45 e0 3b 45 d8 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DM_2147632835_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DM"
        threat_id = "2147632835"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 40 1c 03 41 10}  //weight: 2, accuracy: High
        $x_2_2 = {66 33 0c 42 e8 ?? ?? ?? ?? 8a d8 [0-24] 88 18}  //weight: 2, accuracy: Low
        $x_1_3 = {3d 4d 5a 00 00 74 05 e9 ?? ?? ?? ?? 8b 45 0c}  //weight: 1, accuracy: Low
        $x_2_4 = {35 00 39 00 38 00 39 00 30 00 31 00 36 00 36 00 33 00 31 00 43 00 30 00 43 00 33 00 00 00}  //weight: 2, accuracy: High
        $x_1_5 = {99 6a 05 5e f7 fe 83 c2 01 [0-6] 33 ca}  //weight: 1, accuracy: Low
        $x_2_6 = {07 00 01 00 09 00 [0-3] 8b 45 08 c7}  //weight: 2, accuracy: Low
        $x_1_7 = "margorp" ascii //weight: 1
        $x_2_8 = {00 30 00 00 c7 85 ?? ?? ?? ?? 03 00 00 00 8d b5 ?? ?? ?? ?? 6a 03 ff b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 40 00 00 00}  //weight: 2, accuracy: Low
        $x_2_9 = {05 f8 00 00 00 0f 80 ?? ?? ?? ?? 8b 4d ?? 8b 89 ?? ?? ?? ?? 6b c9 28 0f 80 ?? ?? ?? ?? 03 c1 0f 80}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DN_2147632862_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DN"
        threat_id = "2147632862"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 05 00 00 00 c2 f5 02 00 00 00 aa fb 13 fc 0e}  //weight: 1, accuracy: High
        $x_1_2 = {4a c2 f5 01 00 00 00 aa 6c 0c 00 4d f8 fe 08 40}  //weight: 1, accuracy: High
        $x_1_3 = {80 0c 00 fc 90 6c 78 ff 08 08 00 8a (3c|40) 00 c2 08 08 00 8a (40|44) 00 fc 90 fb 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FJ_2147632922_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.FJ"
        threat_id = "2147632922"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Stub nuevo DUNEDAI.vbp" wide //weight: 2
        $x_1_2 = "SwashLabs" wide //weight: 1
        $x_1_3 = "DecryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_FK_2147632993_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.FK"
        threat_id = "2147632993"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\DEMON\\Malware Production" wide //weight: 1
        $x_1_2 = "Sharki\\Sharki Cripter\\DEMON." wide //weight: 1
        $x_2_3 = {50 51 ff d7 8b d0 8d 4d e0 ff d6 50 68 ?? ?? ?? ?? ff d7 8b d0 8d 4d dc ff d6 50 6a 01 6a ff 6a 20 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DO_2147633039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DO"
        threat_id = "2147633039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {94 7c fc 1c 00 6c 20 fe aa fd 69 ?? ?? f5 01 00 00 00 6c b8 fc}  //weight: 2, accuracy: Low
        $x_2_2 = {aa 71 9c fd 0a 00 94 ?? ?? 1c 00 94 01 10 00}  //weight: 2, accuracy: Low
        $x_2_3 = {94 70 fc 1c 00 94 70 fc 10 00 aa 30 9c fd}  //weight: 2, accuracy: High
        $x_1_4 = {fb 12 fc 0d 6c 6c ff 80 0c 00 fc a0 [0-3] 6c 6c ff 6c 5c ff e0 1c}  //weight: 1, accuracy: Low
        $x_1_5 = {ae f5 05 00 00 00 ae 71 ?? ff 03 00 6c 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DP_2147633041_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DP"
        threat_id = "2147633041"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 c1 f8 0f 66 33 05 ?? ?? ?? ?? 66 8b 4d ?? 66 c1 f9 0f 66 33 4d ?? 66 3b c1 7f}  //weight: 2, accuracy: Low
        $x_2_2 = {66 8b d7 66 c1 fa 0f 8b da 33 55 ?? 33 1d ?? ?? ?? ?? 66 3b da 7f}  //weight: 2, accuracy: Low
        $x_1_3 = {66 b9 58 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {66 b9 59 00 e8}  //weight: 1, accuracy: High
        $x_1_5 = {66 b9 cc 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DQ_2147633042_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DQ"
        threat_id = "2147633042"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e7 f5 4d 5a 00 00 c7 c3 1c}  //weight: 3, accuracy: High
        $x_1_2 = {fb 12 fc 0d 6b ?? ?? e7 6b ?? ?? e7 08 08 00 06 ?? 00 a7 02 00 fd 80}  //weight: 1, accuracy: Low
        $x_1_3 = {fb 12 fc 0d 04 ?? ?? fc 22 80 ?? ?? fc a0}  //weight: 1, accuracy: Low
        $x_3_4 = {f5 03 00 00 00 6c ?? ?? 52 fe c1 ?? ?? 40 00 00 00 08 00 fe c1 ?? ?? 00 30 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_FQ_2147633128_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.FQ"
        threat_id = "2147633128"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 8b 45 ?? 99 6a 05 5e f7 fe 83 c2 02 0f 80 ?? ?? 00 00 33 ca}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f b6 08 8b 45 84 8b 55 ?? 66 33 0c 42}  //weight: 1, accuracy: Low
        $x_1_3 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FR_2147633129_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.FR"
        threat_id = "2147633129"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 89 4d c8 c7 45 fc 0a 00 00 00 8b 45 c8 89 45 9c 81 7d 9c 00 01 00 00 73 09 83 a5 7c ff ff ff 00 eb 0b}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f b6 08 8b 85 ?? ?? ff ff 8b 95 ?? ?? ff ff 66 33 0c 42}  //weight: 1, accuracy: Low
        $x_1_3 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_DX_2147633330_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DX"
        threat_id = "2147633330"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e7 f5 4d 5a 00 00 c7 c3 1c}  //weight: 1, accuracy: High
        $x_1_2 = {f5 07 00 01 00 71 ?? ?? 1e}  //weight: 1, accuracy: Low
        $x_1_3 = {6c 74 ff ae f5 05 00 00 00 ae 71 74 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FT_2147633335_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.FT"
        threat_id = "2147633335"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b c3 db e2 7d ?? 6a 50}  //weight: 1, accuracy: Low
        $x_1_2 = {3b c3 db e2 7d ?? 6a 58}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 01 6a ff 6a 20 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {43 00 4e 00 54 00 42 00 52 00 41 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "\\Sadok\\" wide //weight: 1
        $x_1_6 = {26 00 2f 00 26 00 25 00 26 00 28 00 3d 00 29 00 25 00 26 00 26 00 25 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2e 00 45 00 58 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {78 00 52 00 43 00 34 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_DY_2147633386_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DY"
        threat_id = "2147633386"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 33 0c 42 e8 ?? ?? ?? ?? 8a d8 [0-24] 88 18}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 40 1c 03 41 10 0f 80 0c 00 8b 85 ?? ?? ff ff 8b 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = "munE\\ksiD\\secivreS\\100teSlortnoC\\METSYS" wide //weight: 1
        $x_1_4 = {2a 00 58 00 4f 00 42 00 56 00 2a 00 00 00 00 00 0c 00 00 00 2a 00 55 00 4d 00 45 00 51 00 2a 00}  //weight: 1, accuracy: High
        $x_1_5 = {65 00 73 00 72 00 65 00 76 00 65 00 52 00 00 00 12 00 00 00 65 00 6c 00 69 00 66 00 20 00 70 00 6f 00 72 00 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_DZ_2147633425_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!DZ"
        threat_id = "2147633425"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 2a 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 56 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 4d 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 57}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 1e 32 18 ff 75 ?? 8b 45 ?? ff 30 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "5989016631C0C3" wide //weight: 1
        $x_1_4 = "8B4C240851" wide //weight: 1
        $x_1_5 = {f5 03 00 00 00 6c ?? ?? 52 fe c1 ?? ?? 40 00 00 00 08 00 fe c1 ?? ?? 00 30 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {58 59 59 59 6a 04 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_7 = {59 50 6a 02 04 00 66 c7 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_EA_2147633426_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!EA"
        threat_id = "2147633426"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d8 ff 75 e4 ff 75 e0 07 00 33 ca e8}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 09 09 4d 4e 4f 4a 39 4e 2f 2f 2f 50 31 37 2f 2f 2f 4e 51 0c 02 21 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FZ_2147633575_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.FZ"
        threat_id = "2147633575"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 e8 00 00 00 89 5d}  //weight: 1, accuracy: High
        $x_1_2 = {b9 c3 00 00 00 ff d6 88}  //weight: 1, accuracy: High
        $x_1_3 = {8a 04 39 32 c2 83 c3 01 88 04 31 8b 44 24 18 70 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_EC_2147633579_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!EC"
        threat_id = "2147633579"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2A5649525455414C2A" wide //weight: 1
        $x_1_2 = "38423443323430383531" wide //weight: 1
        $x_1_3 = "3539383930313636333143304333" wide //weight: 1
        $x_1_4 = "44726F702066696C65" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_ED_2147633637_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!ED"
        threat_id = "2147633637"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 70 fe 6c 64 fe aa 71 90 fd}  //weight: 1, accuracy: High
        $x_1_2 = {fd 69 4c ff fb a4 3c ff fc 22 6c 5c ff fc 90 fb 96}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_EE_2147633899_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!EE"
        threat_id = "2147633899"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 e8 00 00 00 71 78 ff 1e}  //weight: 1, accuracy: High
        $x_1_2 = {f5 07 00 01 00 71 ?? ?? 1e}  //weight: 1, accuracy: Low
        $x_1_3 = {c2 08 08 00 8a 3c 00 fc 90 fd 67 ?? ?? 04 ?? ?? 28 ?? ?? ?? ?? fb b4 ?? ?? fb 9c ?? ?? fb 17}  //weight: 1, accuracy: Low
        $x_1_4 = "H59595958" wide //weight: 1
        $x_1_5 = {f5 26 00 00 00 04 ?? ff 0a ?? 00 08 00 04 ?? ff 3a ?? ff ?? 00 fb ef ?? ?? fc 46 71}  //weight: 1, accuracy: Low
        $x_1_6 = {f5 58 59 59 59 (71 ?? ??|59 ?? ?? 6c ?? ?? f5 ?? 00 00 00 0a ?? 00 0c 00 3c (1e|6c ?? ff f5 ?? 00))}  //weight: 1, accuracy: Low
        $x_1_7 = {80 0c 00 4a e4 f4 03 fe 6b ?? (fe|ff) ?? ?? 1e}  //weight: 1, accuracy: Low
        $x_1_8 = {f4 58 fc 0d 0a ?? 00 08 00 1e ?? ?? [0-48] 04 ?? ff f4 5b}  //weight: 1, accuracy: Low
        $x_1_9 = {f5 58 00 00 00 fc 0e 0a ?? 00 08 00 1e ?? ?? [0-96] 04 ?? 03 01 01 01 fd fe ff (f4 5b|f5 5b 00)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_GT_2147634555_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.GT"
        threat_id = "2147634555"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 48 e8 ae e4 ff ff 8b d0 8d 8d ec fe ff ff e8 b3 e4 ff ff 6a 53 e8 9a e4 ff ff 8b d0 8d 8d e8 fe ff ff e8 9f e4 ff ff 6a 66 e8 86 e4 ff ff 8b d0 8d 8d e4 fe ff ff e8 8b e4 ff ff 6a 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GW_2147635793_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.GW"
        threat_id = "2147635793"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d0 8d 8d 5c ff ff ff ff 15 ?? ?? ?? ?? 50 6a 01 6a ff 6a 20 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {c7 45 fc 0a 00 00 00 ba ?? ?? ?? ?? 8d 4d ac ff 15 ?? ?? ?? ?? c7 45 fc 0b 00 00 00 8d 45 88 89 85 20 ff ff ff c7 85 18 ff ff ff 08 40 00 00}  //weight: 5, accuracy: Low
        $x_1_3 = {2e 00 53 00 63 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 00 4c 00 49 00 38 00 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {42 00 4b 00 4e 00 49 00 49 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 00 45 00 48 00 30 00 31 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 00 43 00 49 00 31 00 45 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_GX_2147635936_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.GX"
        threat_id = "2147635936"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 02 00 00 00 68 a1 6a 8b ?? ?? ?? 40 00 c7 ?? 0c 02 00 00 3d d8 51 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {70 01 00 00 68 d0 37 10 8b ?? ?? ?? 40 00 c7 ?? 74 01 00 00 f2 51 e8 d5}  //weight: 10, accuracy: Low
        $x_10_3 = {30 01 00 00 00 68 88 fe 8b ?? ?? ?? 40 00 c7 ?? 34 01 00 00 b3 16 51 e8}  //weight: 10, accuracy: Low
        $x_1_4 = {dc 04 00 00 c1 cf 0d 03 8b ?? ?? ?? 40 00 c7 ?? e8 04 00 00 e1 8b 5a 24}  //weight: 1, accuracy: Low
        $x_1_5 = {dc 04 00 00 c1 cf 0d 03 8b ?? ?? ?? ?? 00 c7 ?? ?? 03 00 00 e8 24 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_EI_2147636708_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!EI"
        threat_id = "2147636708"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f b6 0c 02 8b 55 a8 66 33 0c 7a ff 15 ?? ?? ?? ?? 8b 4d bc 8b 5d e0 8b 51 0c 8b 4d c0 88 04 32 8b 75 e8 b8 01 00 00 00 03 c1 0f 80}  //weight: 1, accuracy: Low
        $x_1_2 = {74 3e 66 83 39 01 75 38 8b f3 8b 45 ?? 6b f6 28 8b 51 14 0f 80 ?? ?? ?? ?? 03 f0 8b 41 10 0f 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_EJ_2147636890_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!EJ"
        threat_id = "2147636890"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 66 33 0c 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {68 f8 00 00 00 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 81 bd ?? ?? ff ff 50 45 00 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {05 f8 00 00 00 0f 80 ?? ?? 00 00 6b d2 28 0f 80 ?? ?? 00 00 03 c2 8b 51 14 0f 80 ?? ?? 00 00 2b c2 8b 51 10 3b c2 89 85 ?? ?? ff ff 72 20}  //weight: 1, accuracy: Low
        $x_1_4 = {81 c1 84 01 00 00 ff d6 8b 85 48 ff ff ff ba e8 ?? 40 00 8d 88 88 01 00 00 ff d6 8b 8d 48 ff ff ff ba e8 ?? 40 00 81 c1 8c 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_HM_2147636964_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.HM"
        threat_id = "2147636964"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Mis Cosas\\Programacion\\Visual Basic 6\\Mis Sources\\Kx-Crypte" wide //weight: 1
        $x_1_2 = "SC\\Stub\\Proyecto1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_EK_2147637489_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!EK"
        threat_id = "2147637489"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f5 58 59 59 59}  //weight: 1, accuracy: High
        $x_2_2 = {6c 3c fe 6c 30 fe aa 71 a0 fd}  //weight: 2, accuracy: High
        $x_2_3 = {6c 0c fe 6c 00 fe aa 71 6c fd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_IH_2147637652_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.IH"
        threat_id = "2147637652"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 00 00 00 c7 45 ?? ?? ?? ?? ?? 8d 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? c7 45 ?? 65 00 00 00 c7 45 ?? ?? ?? ?? ?? 8d 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 6d 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 70 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {7a 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 65 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 6f 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 66 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 73 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 79 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 65 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 78 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_EL_2147637662_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!EL"
        threat_id = "2147637662"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f5 00 00 00 00 05 ?? 00 22 ?? 00 89 06 00 f4 01 ad e7 fe 64 ?? ?? ?? 01}  //weight: 2, accuracy: Low
        $x_1_2 = {22 02 00 8a ?? 00 f5 ?? ?? 00 00 aa f5 ?? 00 00 00 76 ?? 00 b2}  //weight: 1, accuracy: Low
        $x_1_3 = {aa f5 28 00 0b 00 22 ?? 00 8a ?? 00 f5 ?? ?? 00 00 ?? ?? ?? ?? 00 00 76 ?? 00 b2}  //weight: 1, accuracy: Low
        $x_2_4 = {f4 00 fb fd 23 ?? ff 2a 31 ?? ff 2f ?? ff 04 ?? ff}  //weight: 2, accuracy: Low
        $x_2_5 = {f5 01 00 00 00 04 ?? ?? fd 16 10 00 ?? ff fd fe ?? ff 5e 00 00 04 00 f5 02 00 00 00 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_IP_2147637810_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.IP"
        threat_id = "2147637810"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f b6 08 8b 45 08 8b 80 ?? ?? 00 00 8b 95 ?? ?? ff ff 66 8b 04 50 66 25 ff 00 66 33 c8}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 04 83 65 ?? 00 8d 45 ?? 50 66 b9 c3 00}  //weight: 1, accuracy: Low
        $x_1_3 = "exe sihT" wide //weight: 1
        $x_1_4 = "*LAUTRIV*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_EN_2147638112_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!EN"
        threat_id = "2147638112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 00 fb fd 23 ?? ff 2a 31 ?? ff 2f ?? ff 04 ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 3c 00 f5 f8 00 00 00 aa f5 28 00 00 00 76 ?? ?? b2 aa}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 07 00 01 00 22 ?? 00 8f 00 00 [0-2] 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_EO_2147638160_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!EO"
        threat_id = "2147638160"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 81 b0 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 80 a4 00 00 00 [0-10] 83 c0 08}  //weight: 1, accuracy: Low
        $x_1_3 = {66 b9 ff 00 [0-16] 66 b9 d0 00}  //weight: 1, accuracy: Low
        $x_1_4 = {50 68 bd ca 3b d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_EP_2147638520_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!EP"
        threat_id = "2147638520"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 68 fe 6c 5c fe aa 71 b0 fd}  //weight: 1, accuracy: High
        $x_1_2 = {6c 40 fe 6c 34 fe aa 71 5c fd}  //weight: 1, accuracy: High
        $x_1_3 = {6c 54 fe 6c 48 fe aa 71 7c fd}  //weight: 1, accuracy: High
        $x_1_4 = {6c 58 fe 6c 4c fe aa 71 9c fd}  //weight: 1, accuracy: High
        $x_1_5 = {f5 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_6 = {f3 c3 00 fc 0d}  //weight: 1, accuracy: High
        $x_2_7 = {6c 68 ff f5 28 00 00 00 aa 5e ?? ?? ?? ?? aa f5 2c 00 00 00 04 0c ff a3}  //weight: 2, accuracy: Low
        $x_1_8 = {4d 5a 52 45 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_ER_2147638756_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!ER"
        threat_id = "2147638756"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 f8 00 00 00 aa f4 28 6b ?? ?? b1}  //weight: 1, accuracy: Low
        $x_1_2 = {00 30 f5 03 00 00 00 6c ?? ?? 52 28 ?? ?? 40 00 f5 04 00 00 00 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 00 01 00 00 b2 f5 01 00 00 00 80 0c 00 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ES_2147638833_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!ES"
        threat_id = "2147638833"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a 52 45 e9 db 10 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {f3 00 01 c1 e7 04 ?? ff 9d fb 12 fc 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JX_2147638841_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.JX"
        threat_id = "2147638841"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 8b 04 50 66 25 ff 00 66 33 c8 e8 ?? ?? ?? ?? 8b 4d ?? 03 8d ?? ?? ?? ?? 88 01 e9}  //weight: 2, accuracy: Low
        $x_2_2 = {05 f8 00 00 00 0f 80 ?? ?? ?? ?? 8b 4d ?? 6b c9 28 0f 80 ?? ?? ?? ?? 03 c1 0f 80 ?? ?? ?? ?? 89 45}  //weight: 2, accuracy: Low
        $x_1_3 = "exe sihT" wide //weight: 1
        $x_1_4 = "atadppA" wide //weight: 1
        $x_1_5 = {68 79 a9 e1 f2 ff 75 ?? 8b 85 ?? ?? ?? ?? 8b 00 ff b5 ?? ?? ?? ?? ff 50 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_ET_2147638959_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!ET"
        threat_id = "2147638959"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 b9 ff 00 ?? ?? ?? ?? ?? ?? ?? ?? [0-8] 66 b9 d0 00}  //weight: 10, accuracy: Low
        $x_1_2 = {68 c2 8c 10 c5 68 [0-2] 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 d0 37 10 f2 68 [0-2] 40 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 c8 46 4a c5 68 [0-2] 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_FA_2147639521_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FA"
        threat_id = "2147639521"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f5 f8 00 00 00 aa (f4 28|f5 28 00) ?? ?? ?? [0-3] (b1 e7|b2) aa}  //weight: 10, accuracy: Low
        $x_10_2 = {f5 07 00 01}  //weight: 10, accuracy: High
        $x_1_3 = {4a c2 f5 01 00 00 00 aa [0-31] e7 fb 13}  //weight: 1, accuracy: Low
        $x_1_4 = {f3 c3 00 fc 0d}  //weight: 1, accuracy: High
        $x_1_5 = {f3 b8 00 fc 0d}  //weight: 1, accuracy: High
        $x_10_6 = "hTsip orrgmac naon tebr nui " ascii //weight: 10
        $x_10_7 = {00 30 f5 03 00 00 00 6c ?? ?? 52 28 ?? ?? 40 00 f5 04 00 00 00 6c 03 00 28}  //weight: 10, accuracy: Low
        $x_10_8 = {00 30 f5 04 00 00 00 6c ?? ?? 52 28 ?? ?? 40 00 f5 05 00 00 00 6c 03 00 28}  //weight: 10, accuracy: Low
        $x_10_9 = {f5 03 00 00 00 6c ?? ?? 52 fe c1 ?? ?? 40 00 00 00 08 00 fe c1 ?? ?? 00 30 00 00}  //weight: 10, accuracy: Low
        $x_10_10 = {6c 60 fe 6c 54 fe aa 71 b4 fd}  //weight: 10, accuracy: High
        $x_10_11 = {6c 64 fe 6c 58 fe aa 71 ac fd}  //weight: 10, accuracy: High
        $x_10_12 = {fd 4e 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? 28 ?? ?? 74 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? 28 ?? ?? 57 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? 28 ?? ?? 72 00 04 ?? ?? 0a ?? ?? ?? ?? 04 ?? ?? fb ef ?? ?? 28 ?? ?? 69 00}  //weight: 10, accuracy: Low
        $x_10_13 = {aa 08 08 00 8f f4 00 0a 00 94 ?? ?? 1c 00 94 ?? ?? 10 00}  //weight: 10, accuracy: Low
        $x_10_14 = {6c 68 ff f5 28 00 00 00 aa 5e ?? ?? ?? ?? aa f5 2c 00 00 00 04 0c ff a3}  //weight: 10, accuracy: Low
        $x_10_15 = {69 00 74 00 00 00 00 00 04 00 00 00 65 00 50 00 00 00 00 00 04 00 00 00 72 00 6f 00 00 00 00 00 04 00 00 00 73 00 73 00 00 00 00 00 04 00 00 00 4d 00 65 00}  //weight: 10, accuracy: High
        $x_10_16 = {f5 0a 00 00 00 04 ?? ?? 9e aa f5 2c 00 00 00 04 ?? ?? a3 (04 ec f9 04 dc f9 fb 94 48 ff fc f6|(??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) 1b ?? 00)}  //weight: 10, accuracy: Low
        $x_1_17 = {fb 12 fc 0d 6c ?? ?? 6c ?? ?? fc a0}  //weight: 1, accuracy: Low
        $x_10_18 = {fd f4 63 0b ?? ?? ?? ?? 23 ?? ?? 2a 23 ?? ?? f4 65 0b ?? ?? ?? ?? 23 ?? ?? 2a 23 ?? ?? f4 73 0b ?? ?? ?? ?? 23 ?? ?? 2a 23 ?? ?? f4 73 0b ?? ?? ?? ?? 23 ?? ?? 2a 23 ?? ?? f4 4d 0b ?? ?? ?? ?? 23 ?? ?? 2a 23 ?? ?? f4 65}  //weight: 10, accuracy: Low
        $x_1_19 = "C:\\/bebrtTBtde programa\\" ascii //weight: 1
        $n_100_20 = "Microsoft.ConfigurationManager.DmpConnector.Connector.pdb" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_FC_2147639631_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FC"
        threat_id = "2147639631"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 b8 00 fc 0d}  //weight: 1, accuracy: High
        $x_1_2 = {f3 c3 00 fc 0d}  //weight: 1, accuracy: High
        $x_1_3 = {f5 09 96 2a 3f}  //weight: 1, accuracy: High
        $x_1_4 = {f5 95 e3 35 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_KR_2147639641_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.KR"
        threat_id = "2147639641"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 51 0c 8b 8d ?? ?? ff ff 88 04 0a (e9|eb) 50 00 8b ?? 0c 8b ?? ?? ?? ff ff 33 ?? 8a ?? ?? [0-16] 33 0c (90 90|82) ff 15 ?? 10 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FD_2147639724_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FD"
        threat_id = "2147639724"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b9 58 00 00 00 ff d6 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b9 59 00 00 00 ff d6 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b9 59 00 00 00 ff d6 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b9 59 00 00 00}  //weight: 3, accuracy: Low
        $x_3_2 = {b9 c3 00 00 00 ff d6 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b9 cc 00 00 00 ff d6}  //weight: 3, accuracy: Low
        $x_1_3 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {52 65 73 75 6d 65 54 68 72 65 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_FE_2147639930_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FE"
        threat_id = "2147639930"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RtlMoveMemory" ascii //weight: 1
        $x_1_2 = "phoneGetHookSwitch" ascii //weight: 1
        $x_1_3 = "DdeDisconnectList" ascii //weight: 1
        $x_1_4 = "\"oN\"" ascii //weight: 1
        $x_1_5 = "\"seY\"" ascii //weight: 1
        $x_1_6 = "\"exe." ascii //weight: 1
        $x_1_7 = "||||QREBTNFFjQzgkJ" wide //weight: 1
        $x_1_8 = "||M1UBx0Qfd1TE5USX9lTP10QPJFU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule VirTool_Win32_VBInject_LA_2147639969_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.LA"
        threat_id = "2147639969"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 fc 03 00 00 00 ba ?? ?? ?? ?? 8d 4d dc e8 ?? ?? ?? ?? 8d 45 dc 50 e8 ?? ?? ?? ?? 66 2d ff ff 66 f7 d8 1b c0 40 f7 d8 66 89 45 d8 8d 4d dc e8}  //weight: 10, accuracy: Low
        $x_10_2 = {43 00 2a 00 5c 00 41 00 4f 00 3a 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 63 00 6f 00 6f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 65 00 63 00 68 00 74 00 20 00 70 00 75 00 62 00 5c 00 [0-32] 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_1_3 = "ccevtmgr.exe" wide //weight: 1
        $x_1_4 = "avgemc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_LK_2147640383_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.LK"
        threat_id = "2147640383"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 07 00 01 00 71 ?? ?? ((??|?? ??) f5 00 00 00 00 f5 ?? 00 00 00 04 ?? ??|1e)}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 f8 00 00 00 aa f4 28 6b ?? ?? b1}  //weight: 1, accuracy: Low
        $x_1_3 = {80 0c 00 4a e4 f4 03 fe 6b ?? (fe|ff) ?? ?? 1e}  //weight: 1, accuracy: Low
        $x_1_4 = {41 56 45 4e 47 49 4e 60 45 2e 45 58 45 21 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FG_2147640837_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FG"
        threat_id = "2147640837"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 38 fe 6c 2c fe aa 71 2c fd}  //weight: 1, accuracy: High
        $x_1_2 = {f5 07 00 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ME_2147641198_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ME"
        threat_id = "2147641198"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c3 f8 00 00 00 8b 0e 0f 80 ?? ?? ?? ?? 6b c0 28 0f 80 ?? ?? ?? ?? 03 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {80 fb 09 76 13 66 33 c9 8a cb 66 83 e9 07 0f 80 ?? ?? ?? ?? ff d7 8a d8 8a 45 e0 3c 09 76 14}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 a8 e8 00 00 00 89 7d a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FI_2147641320_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FI"
        threat_id = "2147641320"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 00 76 00 69 00 6c 00 44 00 72 00 61 00 67 00 6f 00 6e 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "Incorrect size descriptor in Gost decryption" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FJ_2147642175_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FJ"
        threat_id = "2147642175"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 45 cc 50 ff 75 0c e8 ?? ?? ff ff 89 45 a8 8d 45 a8 50 8d 45 e0 50}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 01 6a 08 8d 45 ?? 50 6a 04 68 80 01 00 00 e8 ?? ?? ?? ff 83 c4 1c c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 ff 75 ?? 8b 45 08 ff 30 8b 45 0c ff 30 6a 00}  //weight: 2, accuracy: Low
        $x_1_3 = {6c 00 6c 00 6f 00 63 00 45 00 78 00 ?? ?? ?? ?? 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 ?? ?? ?? ?? 57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {75 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 ?? ?? ?? ?? 4e 00 74 00 57 00 72 00 69 00 74 00 65 00 56 00 69 00 72 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_FK_2147642238_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FK"
        threat_id = "2147642238"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 91 a4 00 00 00 90 13 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 08 [0-6] 89 95}  //weight: 4, accuracy: Low
        $x_1_2 = {89 81 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 8a b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 95 e3 35 69}  //weight: 1, accuracy: High
        $x_1_5 = {c7 02 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 c2 8c 10 c5 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_FL_2147642243_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FL"
        threat_id = "2147642243"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 04 51 52 e8 ?? ?? ?? 00 8b 45 ?? 6a 00 50 6a 01 8d 4d ?? 6a 00 51 6a 10 6a 00 ff d3}  //weight: 2, accuracy: Low
        $x_1_2 = "ZwWriteVirtualMemory" ascii //weight: 1
        $x_1_3 = "win32_process" wide //weight: 1
        $x_1_4 = "MSMPENG.EXE" wide //weight: 1
        $x_1_5 = "AVGUARD.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_FM_2147642332_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FM"
        threat_id = "2147642332"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 1c 03 41 10 [0-6] 8b 4d 08 89 81 ac 02}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 80 fc 01 00 00 07 00 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FN_2147642374_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FN"
        threat_id = "2147642374"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 4e 51 c7 00 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f b6 0c 08 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 66 33 0c 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {50 89 8a b0 00 00 00 ff d6 8d 8d ?? ?? ?? ?? 6a 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_FP_2147642587_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FP"
        threat_id = "2147642587"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 81 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 95 e3 35 69}  //weight: 1, accuracy: High
        $x_1_3 = {66 b9 ff 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 45 ?? 50 66 b9 d0 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 b9 58 00 e8 [0-48] 66 b9 59 00}  //weight: 1, accuracy: Low
        $x_1_5 = {03 c8 0f 80 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 55 ?? 89 0c 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_FQ_2147642654_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FQ"
        threat_id = "2147642654"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 ac ef 1c 00 94 ac ef 10 00 aa 08 08 00 8f}  //weight: 1, accuracy: High
        $x_1_2 = {f5 07 00 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FS_2147642891_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FS"
        threat_id = "2147642891"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 74 75 62 00 63 69 39 6d 2c 39 33 32 38 63 6d 33 6d 72 39 32 38 33 63 2c 72 2c 39 32 63 72 32 00 [0-5] 50 72 6f 79 65 63 74 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 6f 64 75 6c 65 31 00 52 75 6e 50 65 00 00 00 63 6c 73 52 43 34 00 00 50 72 6f 79 65 63 74 6f 31 00}  //weight: 1, accuracy: High
        $x_1_3 = "~||~||~K-I-N-K-I~||~||~" wide //weight: 1
        $x_1_4 = "NPUKPTNIQQWEQFYRBSYWKQRULNCQEBDXVOEDXTVH" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_FT_2147643151_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FT"
        threat_id = "2147643151"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 95 e3 35 69}  //weight: 1, accuracy: High
        $x_1_2 = {68 d0 37 10 f2}  //weight: 1, accuracy: High
        $x_1_3 = {66 b9 c3 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {c7 04 81 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_5 = {b8 75 bb db fb f7 d8 b9 3e 37 f2 3c 83 d1 00 f7 d9}  //weight: 1, accuracy: High
        $x_1_6 = {66 33 0c 42 e8 ?? ?? ?? ?? 8a d8}  //weight: 1, accuracy: Low
        $x_1_7 = {c8 63 db 63 c8 63 91 63 d7 63 c8 63 d1 63 d7 63 d2 63 c5}  //weight: 1, accuracy: High
        $x_1_8 = {8b 91 a4 00 00 00 8b 85 ?? ?? ff ff 83 c2 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_FU_2147643190_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FU"
        threat_id = "2147643190"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 a4 4e 0e ec 50 e8 43 00 00 00 83 c4 08 ff 74 24 04 ff d0 ff 74 24 08 50 e8 30 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_NS_2147643211_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.NS"
        threat_id = "2147643211"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 a4 56 00 00 00 c7 45 9c 02 00 00 00 8d 75 9c 6a 00 ff 75 ac e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? c7 45 94 57 00 00 00 c7 45 8c 02 00 00 00 8d 75 8c 6a 01 ff 75 ac e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? c7 45 84 8b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {05 f8 00 00 00 0f 80 ?? ?? ?? ?? 8b [0-6] 6b c9 28}  //weight: 1, accuracy: Low
        $x_1_3 = {89 45 c0 8b 45 08 8b 40 78 8b 4d dc c7 04 88 88 6a 3f 24 c7 45 fc 05 00 00 00 c7 45 dc 01 00 00 00 83 7d dc 12 73 06 83 65 bc 00 eb 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_FV_2147643345_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FV"
        threat_id = "2147643345"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 06 ff 75 b4 e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? c7 85 3c ff ff ff 4e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 c2 8c 10 c5}  //weight: 1, accuracy: High
        $x_1_3 = "77,90,144,0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_OD_2147643560_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OD"
        threat_id = "2147643560"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "[*Load_Stub_Here*]" wide //weight: 4
        $x_2_2 = "RtlMoveMemory" ascii //weight: 2
        $x_1_3 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_3_5 = "\\VB\\Pandoras Box\\" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OK_2147644221_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OK"
        threat_id = "2147644221"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 8d 45 e8 ff 75 d0 56 6a 08 50 6a 04 68 80 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7d 08 8b d0 f7 da ff 37 1b d2 f7 da 56 89 95 78 ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 8d 45 8c 5b c7 45 8c 58 59 59 59 53 50 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_OL_2147644299_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OL"
        threat_id = "2147644299"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "66666666.vbp" wide //weight: 1
        $x_1_2 = "blabla soft" wide //weight: 1
        $x_1_3 = "All Files |*.*|Executable Files|*.exe|Shortcut Files|*.lnk|Picture Files|*.jpg;*.bmp;*.gif|DLL Files|*.dll" wide //weight: 1
        $x_1_4 = "pwnedstb.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_FZ_2147644547_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!FZ"
        threat_id = "2147644547"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 80 20 01 00 00 8b 4d 10 8b 09 8a 55 0c 88 14 08 8b 45 10 8b 00 8b 4d 08 03 81 a8 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 78 f7 d9 8b 40 7c 83 d0 00 f7 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OS_2147644582_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OS"
        threat_id = "2147644582"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 45 8d 85 ?? fa ff ff 50 e8 ?? ?? ?? ff 6a 78 8d 85 ?? fa ff ff 50 e8 ?? ?? ?? ff 6a 00 6a 04 6a 01 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GA_2147644583_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GA"
        threat_id = "2147644583"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b c2 7f 0e c6 04 07 cc ?? ?? ?? ?? ?? 89 45 ec eb ee}  //weight: 2, accuracy: Low
        $x_1_2 = {c7 45 a8 e8 00 00 00 89 7d a0}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 a8 c3 00 00 00 89 7d a0}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 a8 58 00 00 00 89 7d a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_OU_2147644647_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OU"
        threat_id = "2147644647"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e2 00 68 64 12 40 00 e8 c1 fa ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OV_2147644648_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OV"
        threat_id = "2147644648"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 05 ec 19 40 00 6f c6 05 57 19 40 00 6f c6 05 89 1a 40 00 6f c6 05 2c 12 40 00 00 ff 25 3c 10 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OX_2147644756_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OX"
        threat_id = "2147644756"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 8b 45 08 8b 00 ff 75 08 ff 50 28 89 45 ?? 83 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 e8 50 8b 45 08 05 80 01 00 00 50 8b 45 08 05 7c 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 02 58 6b c0 0d 8b 4d 08 8b 49 6c 66 c7 04 01}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 e8 8b 00 ff 75 e8 ff 50 28 db e2 89 45 e4 83 7d e4 00 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_OY_2147644810_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OY"
        threat_id = "2147644810"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 56 6a ff ff d3 8b f0 8d 55 ?? f7 de 1b f6 8d 45 ?? 52 46 50 6a 02}  //weight: 1, accuracy: Low
        $x_1_2 = {85 f6 74 47 8b 7d 0c 8b 07 50 8d 4d c4 51 ff d3 50 56 ff 15 ?? ?? ?? ?? 8b f0 8b 55 c4 52 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OZ_2147644844_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OZ"
        threat_id = "2147644844"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 b0 02 00 00 00 8d 45 b0 50 8d 45 c4 50 e8 ?? ?? ?? ff 50 ff 75 d4}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 48 02 00 00 2b 48 14}  //weight: 1, accuracy: High
        $x_1_3 = {b9 89 78 00 00 2b 48 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GB_2147644969_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GB"
        threat_id = "2147644969"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c7 f8 00 00 00 ba ?? ?? ?? ?? 0f 80 ?? ?? 00 00 6b c9 28 0f 80 ?? ?? 00 00 03 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 58 00 00 00 89 45 ?? ff d6 50 e8 ?? ?? ?? ?? 8d 45 ?? b9 5b 00 00 00 50 ff d6 50 e8 ?? ?? ?? ?? 8d 4d ?? 51 b9 50 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 02 07 00 01 00 ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_GC_2147645012_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GC"
        threat_id = "2147645012"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f0 81 ee 4d 5a 00 00 f7 de 1b f6 46 f7 de 8d 85}  //weight: 1, accuracy: High
        $x_1_2 = {2d 50 45 00 00 f7 d8 1b c0 40 f7 d8 23 f0 66 85 f6 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GD_2147645039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GD"
        threat_id = "2147645039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 6a 01 6a 01 8d 95 ?? ?? ?? ?? 6a 00 52 6a 10 68 80 08 00 00 c7 85 ?? ?? ?? ?? 07 00 01 00 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 03 40 00 00 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 83 c4 1c 8d 95 ?? ?? ?? ?? 8b 48 ?? c1 e1 04 89 8d ?? ?? ?? ?? 8b 48 ?? 8b 85 ?? ?? ?? ?? 2b c8 ff d7 8d 8d ?? ?? ?? ?? 51 ff d3}  //weight: 5, accuracy: Low
        $x_5_2 = {8d 4d c8 ff d7 8d 45 c8 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 4d c8 8d 55 e8 51 52 ff 15 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 b9 ?? ?? ?? ?? ff d3 8d 4d e8 ff 15 ?? ?? ?? ?? 8d 4d c8 ff d7 8b 45 ec 3b c6 75}  //weight: 5, accuracy: Low
        $x_3_3 = {41 00 43 00 3a 00 5c 00 41 00 74 00 61 00 72 00 69 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 3, accuracy: High
        $x_1_4 = {66 72 6d 4f 44 42 43 4c 6f 67 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 44 53 4e 73 41 6e 64 44 72 69 76 65 72 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {5f 5f 76 62 61 53 74 6f 70 45 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {5f 5f 76 62 61 53 65 74 53 79 73 74 65 6d 45 72 72 6f 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_GG_2147645506_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GG"
        threat_id = "2147645506"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc 14 f3 ff 00 fb 12 fc 0d}  //weight: 1, accuracy: High
        $x_1_2 = {f5 07 00 01 00 71}  //weight: 1, accuracy: High
        $x_1_3 = {f5 40 00 00 00 f5 00 30 00 00 6c ?? ?? 6c ?? ?? 6c ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {f5 f8 00 00 00 aa f5 28 00 00 00 6c ?? ?? b2 aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_PN_2147645661_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PN"
        threat_id = "2147645661"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4d b8 8b 49 0c 8b 3d ?? ?? 40 00}  //weight: 2, accuracy: Low
        $x_2_2 = "YaleHistorico.vbp" wide //weight: 2
        $x_1_3 = {ff d6 6a 35 ff d7 8b d0 8d 8d b0 fe ff ff ff d6 68 a0 00 00 00 ff d7 8b d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_GI_2147645968_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GI"
        threat_id = "2147645968"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6d 41 6e 74 69 44 65 62 75 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 6d 53 61 6e 64 62 6f 78 69 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "Users\\David\\Desktop\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GJ_2147646022_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GJ"
        threat_id = "2147646022"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f5 58 59 59 59}  //weight: 1, accuracy: High
        $x_1_2 = {6c 70 fe 6c 64 fe aa 71 9c fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GM_2147646228_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GM"
        threat_id = "2147646228"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 82 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 c3 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {0f bf d0 8b 85 ?? ?? ?? ?? 33 c2 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GN_2147646962_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GN"
        threat_id = "2147646962"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 32 00 4d 6f 64 75 6c 65 33 00 4d 6f 64 75 6c 65 34 00 4d 6f 64 75 6c 65 35 00 4d 6f 64 75 6c 65 36 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 6e 66 6f 20 7a 75 20 6d 65 69 6e 65 72 20 41 6e 77 65 6e 64 75 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GO_2147647137_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GO"
        threat_id = "2147647137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 68 ff f5 28 00 00 00 aa 5e ?? ?? ?? ?? aa f5 2c 00 00 00 04 0c ff a3}  //weight: 1, accuracy: Low
        $x_1_2 = {fb 12 fc 0d 6c 6c ff 80 0c 00 fc a0 [0-3] 6c 6c ff 6c 5c ff e0 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_QH_2147647385_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.QH"
        threat_id = "2147647385"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\AC:\\Stub1\\" wide //weight: 2
        $x_2_2 = {75 08 dc 35 a8 11 40 00 eb 11 ff 35 ac 11 40 00 ff 35 a8 11 40 00 e8}  //weight: 2, accuracy: High
        $x_1_3 = {c7 85 f0 fd ff ff 08 00 00 00 c7 45 98 54 00 00 00 c7 45 90 02 00 00 00 8d 45 90 50 8d 45 80 50 e8}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 f0 00 00 00 00 c7 45 f4 00 00 00 00 8b 45 08 8b 00 ff 75 08 ff 50 04 c7 45 fc 01 00 00 00 8b 45 14 83 20 00 c7 45 fc 02 00 00 00 6a ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_QI_2147647393_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.QI"
        threat_id = "2147647393"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "byTEARRAy" ascii //weight: 1
        $x_1_2 = "chupetin" wide //weight: 1
        $x_1_3 = "damajuana" wide //weight: 1
        $x_1_4 = {8b 49 0c 8b 14 01 52 68 28 22 40 00 ff 15 9c 10 40 00 85 c0 0f 85 48 01 00 00 8b 45 d8 85 c0 75 0f 8d 45 d8 50 68 18 1b 40 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b 49 0c 8b 14 01 52 68 0c 24 40 00 ff 15 9c 10 40 00 85 c0 0f 85 35 01 00 00 8b 45 e4}  //weight: 1, accuracy: High
        $x_1_6 = {57 89 39 8d 45 b8 68 80 00 00 00 8d 4d cc 50 89 7d b8 51 89 7d e8 89 7d e4 89 7d cc 89 7d c8 89 55 c0 c7 45 b8 08 40 00 00 ff d3 8d 55 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_VBInject_QF_2147647538_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.QF"
        threat_id = "2147647538"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "5B75566A6C6373526867744B67516667756B6C6A" wide //weight: 4
        $x_4_2 = "56706A706452716B626770774C676E6B737B" wide //weight: 4
        $x_1_3 = "RtlMoveMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GP_2147647548_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GP"
        threat_id = "2147647548"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 37 46 4b 31 58 43 53 6e 6e 54 33 00 00 00 00 74 68 53 6c 47 62 48 55 4e 39 50 67 57 39 00 00 6f 71 4b 31 62 63 00 00 4b 33 43 45 68 70 00 00 79 37 53 43 38 7a 78 35 4a 34 4e 53 6e 00 00 00 54 59 6b 67 49 00 00 00 62 42 4b 6b 7a 79 52 57 5a 00 00 00 52 42 73 39 4f 52 66 4e 00 00 00 00 58 39 4f 34 7a 7a 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GP_2147647548_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GP"
        threat_id = "2147647548"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 01 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 95 e3 35 69}  //weight: 1, accuracy: High
        $x_1_3 = {89 90 b0 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GQ_2147647596_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GQ"
        threat_id = "2147647596"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c1 f8 1f 33 45 ?? 8b (4d ??|8d ?? ?? ?? ??) c1 f9 1f 33 (4d ??|8d ?? ?? ?? ??) 3b c1 0f 8f}  //weight: 4, accuracy: Low
        $x_4_2 = {8a 10 8b 45 ?? 56 32 10 ff 37 88 55}  //weight: 4, accuracy: Low
        $x_2_3 = {8b 4d 08 03 81 f8 00 00 00 50 8b 45 08 8b 00 ff 75 08 ff 50}  //weight: 2, accuracy: High
        $x_2_4 = {83 c0 01 0f 80 0c 00 81 7d ?? ?? ?? ?? ?? 7f ?? 8b 45}  //weight: 2, accuracy: Low
        $x_2_5 = {83 c6 01 0f 80 08 00 81 fe ?? ?? ?? ?? 7f}  //weight: 2, accuracy: Low
        $x_2_6 = {df e0 9e 0f 87 ?? ?? 00 00 d9 45 ?? d8 05 ?? ?? ?? ?? d9 5d ?? df e0 a8 0d 0f 85}  //weight: 2, accuracy: Low
        $x_1_7 = {8a 1e 32 18 ff 75 ?? 8b 45 ?? ff 30}  //weight: 1, accuracy: Low
        $x_1_8 = {c1 f9 1f 8b d1 33 c8 33 [0-7] 3b ca 0f 8f}  //weight: 1, accuracy: Low
        $x_1_9 = {c7 00 e8 00 00 00 8b 45 08 8b 80 ?? ?? ?? ?? c7 40 04 22 00 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {66 c7 00 e8 00 8b 45 08 8b 80 ?? ?? ?? ?? 66 c7 40 02 22 00}  //weight: 1, accuracy: Low
        $x_1_11 = {bf 98 3a 00 00 8b de 57 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 2b f3 68 ?? ?? ?? ?? 70 ?? 33 c0 3b f7 0f 9d c0 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_QG_2147647671_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.QG"
        threat_id = "2147647671"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "47dp7yTOcywaBIU6tE7+Y0SG4g==" wide //weight: 4
        $x_3_2 = "reg add hkcu\\software\\microsoft\\windows\\currentversion\\policies\\system /v disabletaskmgr /t reg_dword /d \"1\" /f" wide //weight: 3
        $x_1_3 = "DecryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_QL_2147647721_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.QL"
        threat_id = "2147647721"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d7 56 6a 02 6a 01 8d 4d 90 56 51 6a 10 68 80 08 00 00 ff d7 8b 55 dc 83 c4 38 8d 45 d4 52 50}  //weight: 1, accuracy: High
        $x_1_2 = {89 85 68 ff ff ff 8b 45 90 89 9d 60 ff ff ff b9 02 00 00 00 8b 58 14 8d 95 60 ff ff ff 2b cb 8b 58 0c c1 e1 04 03 cb}  //weight: 1, accuracy: High
        $x_1_3 = {8b 85 3c ff ff ff 89 b5 34 ff ff ff c7 85 2c ff ff ff 02 00 00 00 83 c4 1c 8b 48 14 8d 95 2c ff ff ff c1 e1 04}  //weight: 1, accuracy: High
        $x_1_4 = {89 85 a4 fe ff ff 8b 85 3c ff ff ff b9 09 00 00 00 c7 85 9c fe ff ff 03 00 00 00 2b 48 14 8d 95 9c fe ff ff c1 e1 04 03 48 0c ff d6}  //weight: 1, accuracy: High
        $x_1_5 = {81 e1 ff 00 00 00 ff d3 8b 0d 88 d0 40 00 c1 e6 08 03 f1 88 04 3e 66 8b 0d 4c d0 40 00 66 a1 4e d0 40 00 66 83 c1 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_VBInject_GR_2147647768_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GR"
        threat_id = "2147647768"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 44 ff 38 00 04 34 ff 0a ?? 00 08 00 04 34 ff fb ef 14 ff 28 f4 fe 42 00}  //weight: 2, accuracy: Low
        $x_1_2 = {fb 12 fc 0d 6c ?? ?? 6c ?? ?? fc a0}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 03 00 00 00 6c ?? ?? 52 fe c1 ?? ?? 40 00 00 00 08 00 fe c1 ?? ?? 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_GS_2147647782_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GS"
        threat_id = "2147647782"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 81 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "&H59595958" wide //weight: 1
        $x_1_3 = {03 82 a4 00 00 00 0f 80 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 03 00 00 00 8b 48 14 c1 e1 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GT_2147647884_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GT"
        threat_id = "2147647884"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 bb db fb c7 80 ?? ?? ?? ?? 3e 37 f2 3c}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Program Files (x86)\\JOKER-VAIO\\Joker2\\VB6.OLB" ascii //weight: 1
        $x_1_3 = {8b 1e 8d 85 ?? ?? ?? ?? 50 68 b0 00 00 00 ff b5 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GU_2147647891_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GU"
        threat_id = "2147647891"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c1 f8 1f 33 45 ?? 8b (4d|8d) [0-4] c1 f9 1f 33 (4d|8d) [0-4] 3b c1}  //weight: 3, accuracy: Low
        $x_3_2 = {8a 1e 32 18 ff 75 ?? 8b 45 ?? ff 30 e8 ?? ?? ?? ?? 88 18}  //weight: 3, accuracy: Low
        $x_3_3 = {77 69 6e 73 70 6f 6f 6c 2e 64 72 76 ?? ?? ?? ?? ?? ?? ?? ?? 43 6f 6e 66 69 67 75 72 65 50 6f 72 74 41}  //weight: 3, accuracy: Low
        $x_10_4 = "\\Darkeye\\VB6.OLB" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_QM_2147647904_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.QM"
        threat_id = "2147647904"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 6a 01 6a ff 68 20 01 00 00 ff 15 ?? ?? 40 00 8b 55 dc 52 ff 15 ?? ?? 40 00 50 8d 45 bc 50 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_2_2 = {57 51 53 ff 52 2c 3b c6 db e2 7d}  //weight: 2, accuracy: High
        $x_1_3 = {88 04 3a 8b 45 dc e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_2_4 = {b9 b8 00 00 00 89 45 ec 89 45 e8 89 45 e4 ff d3 50 e8 ?? ?? 00 00 8b 45 08}  //weight: 2, accuracy: Low
        $x_1_5 = {b9 68 00 00 00 ff 15 ?? ?? 40 00 50 e8 ?? ?? ?? 00 6a 04 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_GV_2147648047_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GV"
        threat_id = "2147648047"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 8b 00 fc 0d f5 00 00 00 00 04 4c ff fc a0 f4 4c fc 0d f5 01 00 00 00 04 4c ff fc a0 f4 24 fc}  //weight: 1, accuracy: High
        $x_1_2 = {f5 03 00 00 00 6c ?? ?? 52 fe c1 ?? ?? 40 00 00 00 08 00 fe c1 ?? ?? 00 30 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_QO_2147648092_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.QO"
        threat_id = "2147648092"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 09 02 00 00 33 c0 8d bd b8 f7 ff ff 33 f6 f3 ab b9 09 01 00 00 8d bd 0c f3 ff ff f3 ab b9 09 01 00 00 8d bd e8 ee ff ff 56 6a 02 f3 ab 89 75 e4}  //weight: 1, accuracy: High
        $x_1_2 = {8b d0 8d 8d b4 f7 ff ff ff d7 8d 8d b4 f7 ff ff 8d 95 88 f7 ff ff 6a 01 8d 85 98 f7 ff ff 89 8d 40 f7 ff ff 52 50 8d 8d 78 f7 ff ff 56}  //weight: 1, accuracy: High
        $x_1_3 = {8b 95 4c f7 ff ff 89 55 c8 c7 45 fc 06 00 00 00 83 7d c8 00 0f 84 ?? ?? ?? ?? c7 45 fc 07 00 00 00 c7 85 98 f7 ff ff 24 04 00 00 c7 45 fc 08 00 00 00 8d 85 98 f7 ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 fc 0d 00 00 00 8b 85 a0 f7 ff ff 89 45 c4 c7 45 fc 0e 00 00 00 8b 55 d4 8d 4d c0 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_GY_2147648398_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GY"
        threat_id = "2147648398"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 52 8b 45 10 ff 30 e8 ?? ?? ?? ?? 8a 1e 32 18}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f8 2b 45 ?? 70 19 3d 98 3a 00 00 7d 07 66 83 4d fc ff eb 05}  //weight: 1, accuracy: Low
        $x_1_3 = {7f 63 66 8b 45 ?? 66 05 01 00 0f 80 06 00 66 81 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_QV_2147648428_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.QV"
        threat_id = "2147648428"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 59 59 59 06 00 c7 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {66 85 f6 7f ?? 66 81 c6 ff 00 0f ?? ?? 00 00 00 eb ee}  //weight: 1, accuracy: Low
        $x_1_3 = {59 50 00 00 e8 ?? ?? ?? ff 06 00 c7 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {ff e8 00 00 00 09 00 6a 01 ?? ?? c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_QW_2147648515_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.QW"
        threat_id = "2147648515"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff c3 00 6a 01 05 00 66 c7 85}  //weight: 1, accuracy: Low
        $x_1_2 = {58 59 59 59 6a 04 06 00 c7 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 59 50 6a 02 05 00 66 c7 85}  //weight: 1, accuracy: Low
        $x_1_4 = {e8 00 6a 01 07 00 66 c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_GZ_2147648528_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!GZ"
        threat_id = "2147648528"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 85 84 fe ff ff [0-6] 89 85 40 fe ff ff 06 00 8b 85 90 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 85 a0 fe ff ff 03 85 94 fe ff ff [0-6] 89 85 4c fe ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {9c fe ff ff 03 ?? 90 fe ff ff 89 ?? 48 fe ff ff}  //weight: 1, accuracy: Low
        $x_10_4 = {07 00 01 00 06 00 c7 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_QY_2147648605_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.QY"
        threat_id = "2147648605"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {56 b9 b8 00 00 00 89 45 ec 89 45 e8 e9 c9 ce ff ff 50 e8 85 03 00 00 8b 45 08}  //weight: 2, accuracy: High
        $x_2_2 = {8b 0e 8d 55 dc 8d 45 e0 52 50 68 ec 41 40 00 56 ff 51 38 3b c7 7d 0f 6a 38 68 84 31 40 00 56 50 ff 15 4c 10 40 00}  //weight: 2, accuracy: High
        $x_2_3 = {0f 80 c0 37 00 00 6a 04 50 57 89 45 dc ff 51 24 81 bd 48 fd ff ff 50 45 00 00 0f 85 4b 34 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HB_2147648647_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HB"
        threat_id = "2147648647"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 1c 8b 8d ?? ?? ff ff 03 41 10 8b 4d 08 89 81 48 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 81 98 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 80 3c 02 00 00 83 c0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_RA_2147648670_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.RA"
        threat_id = "2147648670"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 51 53 ff 52 2c 3b c6 db e2 7d}  //weight: 1, accuracy: High
        $x_1_2 = {42 00 6f 00 74 00 65 00 6c 00 6c 00 5c 00 [0-64] 42 00 6f 00 74 00 [0-32] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = "BotellaBo tell.scr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_RC_2147648723_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.RC"
        threat_id = "2147648723"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E82200000068A44E0EEC50E84300000083C408FF742404FFD0FF74240850E83000000083C408C3565531C0648B70308B760C8B761C8B6E0" wide //weight: 1
        $x_1_2 = "PUSHES>B8<API_PTR>FFD0C3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HF_2147648773_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HF"
        threat_id = "2147648773"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 40 1c 03 41 10}  //weight: 1, accuracy: High
        $x_1_2 = {89 81 90 02 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 81 e0 01 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 80 84 02 00 00 83 c0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HI_2147648863_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HI"
        threat_id = "2147648863"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 1c 8b 8d ?? ?? ff ff 03 41 10 8b 4d 08 89 81 24 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 89 41 74}  //weight: 1, accuracy: High
        $x_1_3 = {8b 80 18 01 00 00 83 c0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HJ_2147649101_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HJ"
        threat_id = "2147649101"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 40 1c 03 41 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b 80 1c 01 00 00 83 c0 08}  //weight: 1, accuracy: High
        $x_1_3 = {89 81 28 01 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4d 08 89 81 a8 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_RY_2147649457_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.RY"
        threat_id = "2147649457"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 51 53 ff 52 2c 3b c6 db e2 7d}  //weight: 1, accuracy: High
        $x_1_2 = {88 04 3a 8b 45 dc e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 01 52 56 ff 15 ?? ?? 40 00 6a 01 ff 15 ?? ?? 40 00 8d 55 98 8d 4d bc c7 45 a0 ?? ?? 40 00 c7 45 98 08 00 00 00 ff 15 ?? ?? 40 00 8b 4d ec 56}  //weight: 1, accuracy: Low
        $x_1_4 = {b9 b8 00 00 00 89 45 ec 89 45 e8 ?? ?? ?? ?? ?? 50 e8 ?? ?? 00 00 8b 45 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HK_2147649469_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HK"
        threat_id = "2147649469"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b c9 28 8d 84 08 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 45 e0 50 8b 45 08 8b 00 ff 75 08 ff 50 1c 89 45 d8 83 7d d8 00 7d 17}  //weight: 1, accuracy: High
        $x_1_3 = {2b c1 83 e8 05 50 8b 45 08 8b 00 ff 75 08 ff 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HL_2147649536_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HL"
        threat_id = "2147649536"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 45 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 6a 4c 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 6a 33 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 6a 32}  //weight: 1, accuracy: Low
        $x_1_2 = {66 b9 e8 00 e8 ?? ?? ?? ?? 8b 4d ?? 03 8d ?? ?? ff ff 88 01 8b 45 ?? 83 c0 01}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 74 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 6a 65 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 6a 56 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 6a 69 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 6a 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HM_2147649708_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HM"
        threat_id = "2147649708"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 81 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {58 59 59 59 6a 04}  //weight: 1, accuracy: High
        $x_1_3 = {03 c8 0f 80 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8b 55 ?? 89 0c 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HN_2147649728_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HN"
        threat_id = "2147649728"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "aCroneaCr.vbp" wide //weight: 2
        $x_2_2 = {4c 00 65 00 78 00 75 00 73 00 4c 00 65 00 78 00 75 00 [0-8] 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_2_3 = {61 00 6d 00 62 00 6f 00 4c 00 61 00 65 00 76 00 79 00 [0-8] 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_2_4 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50}  //weight: 2, accuracy: Low
        $x_1_5 = {89 81 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {89 8a b0 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_HO_2147649774_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HO"
        threat_id = "2147649774"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 48 56 00 [0-64] 66 c7 04 48 57 00 [0-64] 66 c7 04 48 8b 00 [0-64] 66 c7 04 48 (7c|6c) 00 [0-64] 66 c7 04 48 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 42 1a 14 00 [0-16] 66 c7 42 1c f3 00 [0-16] 66 c7 42 1e a4 00 [0-16] 66 c7 42 20 5f 00 [0-16] 66 c7 42 22 5e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 43 1a 14 00 [0-16] 66 c7 43 1c f3 00 [0-16] 66 c7 43 1e a4 00 [0-16] 66 c7 43 20 5f 00 [0-16] 66 c7 43 22 5e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_VBInject_HP_2147649808_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HP"
        threat_id = "2147649808"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 02 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {89 8a b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 91 a4 00 00 00 [0-5] c7 85 ?? ?? ff ff 03 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_HQ_2147649831_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HQ"
        threat_id = "2147649831"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0f 8d 95 20 ff ff ff 52 57 ff 51 14 db e2 3b c6 7d ?? 6a 14 68 ?? ?? ?? ?? 57 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = ":\\Projekt1.vbp" wide //weight: 1
        $x_1_3 = "VBMsoStdCompMgr" ascii //weight: 1
        $x_1_4 = "RtlMoveMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HR_2147649882_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HR"
        threat_id = "2147649882"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3b cf 74 1f 66 83 39 01 75 19 0f bf f3 2b 71 14 3b 71 10 72 09}  //weight: 2, accuracy: High
        $x_1_2 = "&H5A4D" wide //weight: 1
        $x_1_3 = "&H3C" wide //weight: 1
        $x_1_4 = "&H4550" wide //weight: 1
        $x_1_5 = "&HF8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_HT_2147649996_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HT"
        threat_id = "2147649996"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 04 82 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {03 c2 89 81 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {3b c2 7f 0e c6 04 07 cc e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HT_2147649996_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HT"
        threat_id = "2147649996"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb e9 00 00 00 8b c1 83 c4 1c 99 f7 fb 8b c1}  //weight: 1, accuracy: High
        $x_1_2 = {05 f8 00 00 00 6a 28 0f 80 ?? ?? 00 00 6b c9 28}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 85 30 fd ff ff 50 56 56 6a 04 56 56 56 8d 8d 14 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HU_2147650441_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HU"
        threat_id = "2147650441"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 00 00 00 00 14 00 00 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "398432n5jm34n 5m345k34j6348   i34534568" wide //weight: 1
        $x_1_3 = {6a 00 34 00 35 00 36 00 35 00 35 00 36 00 37 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "ui34534 56 456 456456 457 " wide //weight: 1
        $x_1_5 = {6e 00 35 00 6d 00 37 00 6e 00 36 00 36 00 37 00 38 00 37 00 36 00 38 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_HV_2147650464_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HV"
        threat_id = "2147650464"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RtlMoveMemory" ascii //weight: 1
        $x_1_2 = {8d 4d ec e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 4d ec e8 ?? ?? ?? ?? 8d 45 ec 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HW_2147650537_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HW"
        threat_id = "2147650537"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 8b 8d ?? ff ff ff 0f 80 ?? ?? ?? ?? 89 81 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {07 00 01 00 02 00 c7}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 91 a4 00 00 00 8b 85 ?? ?? ff ff 83 c2 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HX_2147651028_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HX"
        threat_id = "2147651028"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 88 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {07 00 01 00 06 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_3 = {89 81 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {b9 c3 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_4_5 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_SW_2147651044_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.SW"
        threat_id = "2147651044"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 6b ff d7 8b d0 8d 8d 80 fc ff ff ff d6 6a 65 ff d7 8b d0 8d 8d 7c fc ff ff ff d6 6a 72 ff d7 8b d0 8d 8d 78 fc ff ff ff d6 6a 6e ff d7 8b d0 8d 8d 74 fc ff ff ff d6 6a 65 ff d7 8b d0 8d 8d 70 fc ff ff ff d6 6a 6c ff d7 8b d0 8d 8d 6c fc}  //weight: 1, accuracy: High
        $x_1_2 = {6a 35 ff d3 8b d0 8d 8d c8 fe ff ff ff d6 6a 6e ff d3 8b d0 8d 8d c4 fe ff ff ff d6 6a 67 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HY_2147651116_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HY"
        threat_id = "2147651116"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 86 a4 01 00 00 03 ca 8b 96 fc 00 00 00 89 0c 90}  //weight: 1, accuracy: High
        $x_1_2 = {89 04 8a 8b 07 06 00 8b 86 38 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_HZ_2147651374_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!HZ"
        threat_id = "2147651374"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7d 0f 6a 1c 68 3c 33 40 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 10 68 bc d5 40 00 68 f8 37 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {3b c7 db e2 7d 12 68 c4 00 00 00 68 98 39 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IA_2147651430_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IA"
        threat_id = "2147651430"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c7 f8 00 00 00 ba ?? ?? ?? ?? 0f 80 ?? ?? ?? ?? 6b c9 28 0f 80 ?? ?? ?? ?? e9 40 00 [0-32] 6a 02 83 c2 06 0f 80}  //weight: 2, accuracy: Low
        $x_2_2 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50}  //weight: 2, accuracy: Low
        $x_1_3 = {c7 02 07 00 01}  //weight: 1, accuracy: High
        $x_1_4 = {89 8a b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "MANYCREAM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_TC_2147651515_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.TC"
        threat_id = "2147651515"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50}  //weight: 3, accuracy: Low
        $x_1_2 = {03 d1 0f 80 ?? ?? ?? ?? 52 50 e8 [0-21] 8b 8d ?? ?? ff ff b8 01 00 00 00 03 c1 0f 80 ?? ?? ?? ?? 89 85 ?? ?? ff ff e9}  //weight: 1, accuracy: Low
        $x_1_3 = "UD_tools_@" wide //weight: 1
        $x_1_4 = {3b c7 7d 0b 6a 28 68 ?? ?? ?? ?? 56 50 ff d3 8b 0e 8d 55 ?? 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 ff 51 ?? 3b c7 7d 0b}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 51 44 81 bd ?? ?? ?? ?? 50 45 00 00 0f 85 ?? ?? ?? ?? 8b 55 ?? 8b 06 8d 8d ?? ?? ?? ?? 83 c2 34 51 6a 04 0f 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_TE_2147651566_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.TE"
        threat_id = "2147651566"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8B4C2408565531C0648B70308B760C8B761C8B6E088B7E208B3638471875F3803F6B7407803F4B7402EBE789295D5EC3" wide //weight: 1
        $x_1_2 = {34 00 42 00 37 00 34 00 00 00 00 00 08 00 00 00 30 00 32 00 45 00 42 00 00 00 00 00 08 00 00 00 45 00 37 00 38 00 39 00 00 00 00 00 08 00 00 00 32 00 39 00 35 00 44 00 00 00 00 00 08 00 00 00 35 00 45 00 43 00 33 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_VBInject_TG_2147651606_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.TG"
        threat_id = "2147651606"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d6 6a 35 ff d7 8b d0 8d 8d b0 fe ff ff ff d6 68 a0 00 00 00 ff d7 8b d0}  //weight: 2, accuracy: High
        $x_1_2 = "\\Kadabr\\Alaka" wide //weight: 1
        $x_1_3 = {5c 00 62 00 72 00 61 00 4b 00 61 00 [0-16] 41 00 6c 00 61 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Establecer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_TJ_2147651856_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.TJ"
        threat_id = "2147651856"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 bd bc fe ff ff 50 45 00 00 0f 85 ?? ?? ?? ?? 8b 0e 8b c3 8d 95 bc fe ff ff 83 c0 34 52 6a 04 0f 80 ?? ?? ?? ?? 50 56 ff 51 24}  //weight: 2, accuracy: Low
        $x_1_2 = "\\sDem.vbp" wide //weight: 1
        $x_1_3 = "SabadoSabado" wide //weight: 1
        $x_1_4 = "Establecer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_TK_2147651899_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.TK"
        threat_id = "2147651899"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 00 3a 00 5c 00 70 00 72 00 65 00 63 00 61 00 5c 00 75 00 63 00 69 00 6f 00 6e 00 2e 00 [0-64] 2e 00 5c 00 63 00 61 00 6c 00 69 00 45 00 6e 00 54 00 65 00 2e 00 76 00 62 00 70 00}  //weight: 10, accuracy: Low
        $x_1_2 = "VmlydHVhbEFsbG9jRXg=" wide //weight: 1
        $x_1_3 = "TnRVbm1hcFZpZXdPZlNlY3Rpb24=" wide //weight: 1
        $x_1_4 = ".blogspot.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_IB_2147651923_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IB"
        threat_id = "2147651923"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c1 06 50 6a 02 0f 80 ?? ?? ?? ?? 51 56 ff 52 ?? 8b 85 ?? ?? ff ff 83 e8 01 0f 80 ?? ?? ?? ?? 33 c9 89 85 ?? ?? ff ff 89 4d b4 3b c8 0f 8f ?? ?? ?? ?? 81 c3 f8 00 00 00 ba ?? ?? ?? ?? 0f 80 ?? ?? ?? ?? 6b c9 28}  //weight: 2, accuracy: Low
        $x_2_2 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50}  //weight: 2, accuracy: Low
        $x_1_3 = "edaz.vbp" wide //weight: 1
        $x_1_4 = "scRV1uKaO" wide //weight: 1
        $x_1_5 = {ff ff 50 45 00 00 0f 85 04 00 81 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_TM_2147651972_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.TM"
        threat_id = "2147651972"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "crybter" ascii //weight: 2
        $x_1_2 = "RtlMoveMemory" ascii //weight: 1
        $x_3_3 = "\\crybter.vbp" wide //weight: 3
        $x_2_4 = "C:\\Users\\asry\\Desktop\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IC_2147652020_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IC"
        threat_id = "2147652020"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@*\\AC:\\PiElcestial-udtools-net-indetectables.vbp" wide //weight: 1
        $x_1_2 = "SHDocVwCtl.WebBrowser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ID_2147652023_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!ID"
        threat_id = "2147652023"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "phapoeskeezm.vbp" wide //weight: 2
        $x_1_2 = {68 c2 8c 10 c5 68 [0-2] 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 d0 37 10 f2 68 [0-2] 40 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 c8 46 4a c5 68 [0-2] 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_IF_2147652034_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IF"
        threat_id = "2147652034"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 79 74 49 6e 00 00 00 62 79 74 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: High
        $x_1_2 = {00 44 65 63 72 79 70 74 46 69 6c 65 00 44 65 63 72 79 70 74 42 79 74 65 00 45 6e 63 72 79 70 74 42 79 74 65 00 45 6e 63 72 79 70 74 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_5_3 = {00 30 f5 04 00 00 00 6c ?? ?? 52 28 ?? ?? 40 00 f5 05 00 00 00 6c 03 00 28}  //weight: 5, accuracy: Low
        $x_5_4 = {f5 f8 00 00 00 aa f5 28 00 00 00 6c ?? ?? b2 aa}  //weight: 5, accuracy: Low
        $x_5_5 = {f5 95 e3 35 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_IG_2147652046_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IG"
        threat_id = "2147652046"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8d 88 fd ff ff 8b 95 94 fd ff ff 03 ca}  //weight: 1, accuracy: High
        $x_1_2 = {07 00 01 00 06 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 9c 58 59 59 59}  //weight: 1, accuracy: High
        $x_1_4 = {8b 85 20 ff ff ff [0-2] 03 85 2c ff ff ff [0-6] 89 85 20 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 01 50 0f 80 8b 00 00 00 56 c7 45 a0 c3 00 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_TS_2147652685_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.TS"
        threat_id = "2147652685"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mod_By_The_ProDiGy///Indetectables.net" ascii //weight: 1
        $x_1_2 = "#$$##" wide //weight: 1
        $x_1_3 = "demonio666vip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_II_2147652770_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!II"
        threat_id = "2147652770"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hideproc.sys" wide //weight: 2
        $x_2_2 = "RDGSoFT" ascii //weight: 2
        $x_1_3 = "EncryptString" ascii //weight: 1
        $x_3_4 = "w21m01m7wnqw" wide //weight: 3
        $x_2_5 = "*VMWARE*" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_UG_2147653258_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.UG"
        threat_id = "2147653258"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 d0 37 10 f2}  //weight: 5, accuracy: High
        $x_5_2 = {68 88 fe b3 16}  //weight: 5, accuracy: High
        $x_5_3 = {68 c2 8c 10 c5}  //weight: 5, accuracy: High
        $x_1_4 = {ff ff c1 00 00 00 04 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_5 = {ff ff cf 00 00 00 04 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_6 = {ff ff 0d 00 00 00 04 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_7 = {ff ff 0d 00 00 90 04 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_8 = {ff ff e7 00 00 00 04 00 c7 85}  //weight: 1, accuracy: Low
        $x_1_9 = {ff ff 4e 00 00 00 04 00 c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_UI_2147653293_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.UI"
        threat_id = "2147653293"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Marvel\\Wolverine\\Projekt1.vbp" wide //weight: 1
        $x_1_2 = "MarioBrossMarioBrossMarioBross" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IJ_2147653440_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IJ"
        threat_id = "2147653440"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 0f 80 ?? ?? ?? ?? 89 81 b0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 01 07 00 01 90}  //weight: 1, accuracy: High
        $x_1_3 = {68 95 e3 35 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_UN_2147653476_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.UN"
        threat_id = "2147653476"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Offset Locator V3 Mod By Dr.G3NIUS" ascii //weight: 1
        $x_1_2 = "AVFucker Method" ascii //weight: 1
        $x_1_3 = "FUDSOnly.com.ar" ascii //weight: 1
        $x_1_4 = "Indetectables.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_UQ_2147653535_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.UQ"
        threat_id = "2147653535"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\Client shit\\Project11.vbp" wide //weight: 1
        $x_1_2 = "ELPUTO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_UV_2147653624_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.UV"
        threat_id = "2147653624"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\Naruto\\Udtools\\Udtools\\Project1.vbp" wide //weight: 1
        $x_1_2 = "[NarutoVSsasuke]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_UW_2147653638_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.UW"
        threat_id = "2147653638"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3c d3 8d 95 50 ff ff ff 8d 45 94 52 8d 4d d4 50 51 ff d7 50 8d 55 b4 8d 45 d8 52 50 ff d7 50 33 00 ff ff b0 ff 15 ?? ?? 40 00 89 85 08 ff ff ff 8b 85 50 ff ff ff b9 04 00 00 00 c7 85 00 ff ff ff 03 00 00 00 2b 48 14 8d 95 00 ff ff ff c1 e1 04 03 48 0c}  //weight: 2, accuracy: Low
        $x_2_2 = "&H595" wide //weight: 2
        $x_2_3 = "&H68" wide //weight: 2
        $x_2_4 = "&HE8" wide //weight: 2
        $x_2_5 = "&HC3" wide //weight: 2
        $x_1_6 = "5958" wide //weight: 1
        $x_1_7 = {26 00 48 00 35 00 00 00 35 00 39 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_UX_2147653674_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.UX"
        threat_id = "2147653674"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 85 74 ff ff ff 58 59 59 59 ff d3}  //weight: 1, accuracy: High
        $x_1_2 = {c7 85 78 ff ff ff e8 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 85 78 ff ff ff 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 85 78 ff ff ff c3 00 00 00}  //weight: 1, accuracy: High
        $x_5_5 = "&H4550" wide //weight: 5
        $x_5_6 = "&H5A4D" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_UY_2147653685_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.UY"
        threat_id = "2147653685"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 80 08 00 00 e8 ?? ?? ?? ff 83 c4 1c 68 ?? ?? 40 00 e8 ?? ?? ?? ff 57 89 45 b4 ff 75 bc 89 75 ac 8d 5d ac e8 ?? ?? ?? ff 8b c8 8b d3 e8 ?? ?? ?? ff 68 ?? ?? 40 00 e8 ?? ?? ?? ff 6a 01 89 45 a4 ff 75 bc 89 75 9c 8d 5d 9c e8 ?? ?? ?? ff 8b c8 8b d3}  //weight: 1, accuracy: Low
        $x_1_2 = "&H59595958" wide //weight: 1
        $x_1_3 = "&H68" wide //weight: 1
        $x_1_4 = "&HE8" wide //weight: 1
        $x_1_5 = "&HC3" wide //weight: 1
        $x_1_6 = "NtUnmapViewOfSection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IL_2147653926_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IL"
        threat_id = "2147653926"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "SIMPLE AUTO INJECKTOR" ascii //weight: 100
        $x_10_2 = "CmdInjecktor" ascii //weight: 10
        $x_10_3 = "modinjection" ascii //weight: 10
        $x_1_4 = "Dll Injection Successful!" wide //weight: 1
        $x_1_5 = "Failed to Write DLL to Process! - try again" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_VI_2147654200_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.VI"
        threat_id = "2147654200"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 e8 22 00 00 00 68 a4 4e}  //weight: 1, accuracy: High
        $x_1_2 = {f6 0e ec 50 e8 4b 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {f6 a1 6a 3d d8 51 e8 56 01}  //weight: 1, accuracy: High
        $x_1_4 = {f6 84 c0 74 07 c1 cf 0d 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_VM_2147654276_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.VM"
        threat_id = "2147654276"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b cf 74 1f 66 83 39 01 75 19 0f bf f3 2b 71 14 3b 71 10 72 09}  //weight: 1, accuracy: High
        $x_1_2 = {8b 85 3c ff ff ff 89 b5 34 ff ff ff c7 85 2c ff ff ff 02 00 00 00 83 c4 1c 8b 48 14 8d 95 2c ff ff ff c1 e1 04}  //weight: 1, accuracy: High
        $x_1_3 = "\\Avi\\Roper\\oRo\\pe\\rone\\taAvi.onet.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IM_2147654338_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IM"
        threat_id = "2147654338"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 04 81 07 00 01 90}  //weight: 1, accuracy: High
        $x_1_2 = {68 95 e3 35 69}  //weight: 1, accuracy: High
        $x_1_3 = {68 c8 46 4a c5}  //weight: 1, accuracy: High
        $x_1_4 = {68 c2 8c 10 c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_VR_2147654984_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.VR"
        threat_id = "2147654984"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Base de Datos a Respaldar/Restaurar:" ascii //weight: 2
        $x_2_2 = "RtlMoveMemory" ascii //weight: 2
        $x_2_3 = "cmbDatabaseName" ascii //weight: 2
        $x_2_4 = "optSSAuth" ascii //weight: 2
        $x_2_5 = "Data File Name:" wide //weight: 2
        $x_3_6 = "optWinNTAuth" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IN_2147655035_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IN"
        threat_id = "2147655035"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 4d 36 30 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_2 = "D:\\Franky\\" wide //weight: 1
        $x_5_3 = {32 31 41 23 2e 30 40 78 47 72 65 61 74 [0-4] 32 31 41 23 2e 30 40 78 [0-50] 32 31 41 23 2e 30 40 78}  //weight: 5, accuracy: Low
        $x_1_4 = {ff f5 01 00 00 00 6c 74 ff 9e 2a 31 70 ff 32 04 00 ?? ff ?? ff 00 14 f5 00 00 00 00 6c 74 ff 9e fc 33 f4 01 eb c8 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_IN_2147655035_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IN"
        threat_id = "2147655035"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0e 00 00 00 50 72 6f 63 65 73 73 33 32 4e 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff f5 01 00 00 00 6c 74 ff 9e 2a 31 70 ff 32 04 00 ?? ff ?? ff 00 14 f5 00 00 00 00 6c 74 ff 9e fc 33 f4 01 eb c8 1c}  //weight: 1, accuracy: Low
        $x_10_3 = {33 31 42 2a 2e 31 40 79 (?? ?? ?? ?? (61|2d|7a|41|2d|5a) (61|2d|7a|41|2d|5a)|??) (3a|23) 33 31 42 2a 2e 31 40 79 [0-50] (3a|23) 33 31 42 2a 2e 31 40 79}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_IN_2147655035_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IN"
        threat_id = "2147655035"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff f5 01 00 00 00 6c 74 ff 9e 2a 31 70 ff 32 04 00 ?? ff ?? ff 00 14 f5 00 00 00 00 6c 74 ff 9e fc 33 f4 01 eb c8 1c}  //weight: 5, accuracy: Low
        $x_1_2 = {59 6f 75 41 6c 6c 41 76 53 75 63 6b 4d 79 44 69 63 6b 46 69 6e 61 6c 6c 79 3a 29 ?? 59 6f 75 41 6c 6c 41 76 53 75 63 6b 4d 79 44 69 63 6b 46 69 6e 61 6c 6c 79 3a 29 [0-50] 59 6f 75 41 6c 6c 41 76}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 2e 23 23 ae a9 33 32 35 35 39 5e 24 24 ?? 2e 2e 23 23 ae a9 33 32 35 35 39}  //weight: 1, accuracy: Low
        $x_1_4 = {1e 28 32 3c 46 50 5a 64 32 1e 28 32 3c 46 50 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_VU_2147655254_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.VU"
        threat_id = "2147655254"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 65 00 44 65 63 72 79 70 74 00 55 6e 70 61 63 6b 00 00 02 00 00 00 26 00 00 00 02 00 00 00 48 00 00 00 02 00 00 00 34 00 00 00 02 00 00 00 30 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 79 74 49 6e 00 00 00 62 79 74 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_VY_2147655381_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.VY"
        threat_id = "2147655381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F:\\Le!Tj0 U.d\\tst crypter" wide //weight: 1
        $x_1_2 = "_r`ject1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_WA_2147655446_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.WA"
        threat_id = "2147655446"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1c 20 a4 00 a3 00 53 01 d6 00 18 20 d3 00 c6 00 d7 00 7e 01 a4 00 9d 00 1d 20 bc 00 22 20 c6 00 e4 00 d7 00 a8 00 3a 20 00 00 00 00 12 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 43 61 6c 6c 5f 4d 33 00 00 00 00 73 44 65 63 6f 64 65 72 4d 33 00 00 73 49 6e 66 6f 5f 00 00 73 50 61 74 68 43 61 73 65 00 00 00 41 76 69 72 5f 4d 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IP_2147655604_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IP"
        threat_id = "2147655604"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 04 90 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 c2 8c 10 c5}  //weight: 1, accuracy: High
        $x_1_3 = "1765139349" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_WD_2147655634_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.WD"
        threat_id = "2147655634"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 8d 4d d4 ff d6 50 53 6a ff 68 20 01 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 32 00 4d 6f 64 75 6c 65 33 00 4d 6f 64 75 6c 65 34 00 4d 6f 64 75 6c 65 35 00 4d 6f 64 75 6c 65 36 00}  //weight: 1, accuracy: High
        $x_1_3 = "Projekt1" wide //weight: 1
        $x_1_4 = "Executable Files|*.exe|Shortcut Files|*.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IQ_2147655641_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IQ"
        threat_id = "2147655641"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 81 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {07 00 01 00 02 00 c7}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 42 0c 8b 8d ?? ?? ?? ?? 66 0f b6 14 08 8b 85 ?? ?? ?? ?? 8b 4d ?? 66 33 14 41 8b 45 ?? 8b 48 0c 8b 85 ?? ?? ?? ?? 88 14 01}  //weight: 1, accuracy: Low
        $x_1_4 = {ff ff 00 30 00 00 c7 85 ?? ?? ff ff 02 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ff ff 40 00 00 00 c7 85 ?? ?? ff ff 02 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_WE_2147655694_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.WE"
        threat_id = "2147655694"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 68 a1 6a 8b 4d ?? c7 81 ?? ?? 00 00 3d d8 51 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {68 d0 37 10 8b 45 ?? ba ?? ?? ?? ?? c7 80 ?? ?? 00 00 f2 51 e8 d5}  //weight: 1, accuracy: Low
        $x_1_3 = {00 68 88 fe 8b 55 ?? c7 82 ?? ?? 00 00 b3 16 51 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 cf 0d 03 8b 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IR_2147656034_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IR"
        threat_id = "2147656034"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "77|90|128|0|1|0|0|0|" wide //weight: 1
        $x_1_2 = {0f bf c0 33 45 ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d ?? e8 ?? ?? ?? ?? 8d 45 ?? 50 8d 45 ?? 50 6a 02 e8 ?? ?? ?? ?? 83 c4 0c 8d 45 ?? 50 8d 45 ?? 50 6a 02 e8 ?? ?? ?? ?? 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IS_2147656041_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IS"
        threat_id = "2147656041"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 1c 10 03 cb 0f 80 ?? ?? ?? ?? 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 89 4d}  //weight: 2, accuracy: Low
        $x_1_3 = "Projekt1" ascii //weight: 1
        $x_1_4 = "Fra_Backup" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_WN_2147656126_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.WN"
        threat_id = "2147656126"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "O:\\programmiert\\VB\\Fire Crypter\\Stub\\stub.vbp" wide //weight: 1
        $x_1_2 = {45 6e 63 72 79 70 74 44 61 74 61 00 44 65 63 72 79 70 74 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 79 74 4d 65 73 73 61 67 65 00 00 62 79 74 50 61 73 73 77 6f 72 64 00 62 79 74 49 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IT_2147656163_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IT"
        threat_id = "2147656163"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 68 e8 14 00 [0-3] 6a 26 e8 ?? ?? ?? ?? 8b d0 8d (4d ??|8d ?? ?? ?? ??) e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f bf c0 33 45 ?? 50 e8}  //weight: 1, accuracy: Low
        $x_2_3 = {68 a4 4e 0e ec 50 e8 4b 00 00 00 83 c4 08 ff 74 24 04 ff d0 ff 74 24 08 50 e8 38 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_IU_2147656174_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IU"
        threat_id = "2147656174"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NODEMGRLibCtl.TaskSymbol" ascii //weight: 1
        $x_1_2 = {66 83 39 01 75 ?? 8b 41 14 8b 51 10 f7 d8 3b c2 89 (45 ??|85 ?? ?? ?? ??) 72 8b 49 0c 03 c8 51 ff d7 8d (55 ??|95 ?? ?? ?? ??) 8b f8 52 ff 15 ?? ?? ?? ?? 8b (45 ??|85 ?? ?? ?? ??) 56 56 57 50 53 e8 ?? ?? ff ff ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_WS_2147656364_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.WS"
        threat_id = "2147656364"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dedicados Al Malware" wide //weight: 1
        $x_1_2 = "C:\\Cartoo Losa\\CartoonT.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_WX_2147656572_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.WX"
        threat_id = "2147656572"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ProcCallEngine" ascii //weight: 1
        $x_1_2 = {fb 12 fc 0d 6c ?? ?? 80 ?? ?? fc a0}  //weight: 1, accuracy: Low
        $x_1_3 = {e7 aa f5 00 01 00 00 c2 07 00 4a c2 6c ?? ff fc 90}  //weight: 1, accuracy: Low
        $x_1_4 = {f4 02 eb 6b ?? ff eb fb cf e8 c4 [0-10] f5 00 00 00 00 ?? 1c}  //weight: 1, accuracy: Low
        $x_1_5 = {f5 00 00 00 00 f5 ff ff ff ff 04 ?? f7 fe 8e 00 00 00 00 10 00 80 08 04 ?? f7 94 08 00 ?? ?? 94 08 00 ?? ?? 5e ?? ?? ?? ?? 71 ?? f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IW_2147656604_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IW"
        threat_id = "2147656604"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c6 1c 1d 00 04 70 ff 6c 0c 00}  //weight: 1, accuracy: High
        $x_1_2 = {f5 f8 00 00 00 aa f5 28 00 00 00 6c ?? ?? b2 aa}  //weight: 1, accuracy: Low
        $x_1_3 = {f3 00 01 c1 e7 04 ?? ff 9d fb 12 fc 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_WZ_2147656686_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.WZ"
        threat_id = "2147656686"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 00 3a 00 5c 00 64 00 72 00 75 00 6e 00 6b 00 64 00 72 00 75 00 [0-32] 5c 00 63 00 6f 00 62 00 72 00 61 00 74 00 6f 00 78 00 5c 00 [0-96] 5c 00 55 00 64 00 74 00 6f 00 6f 00 6c 00 73 00 73 00 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_1_2 = "[micronet]" wide //weight: 1
        $x_1_3 = {5c 00 00 00 08 00 00 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IX_2147656717_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IX"
        threat_id = "2147656717"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 80 00 05 00 00 5a 5d c3 c3 a1 ?? ?? ?? ?? 89 b0}  //weight: 1, accuracy: Low
        $x_1_2 = {66 8b 04 08 66 03 04 0b 66 8b ce 0f 80 ?? ?? 00 00 66 99 66 f7 f9 0f bf fa 3b fe 72 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_XD_2147656823_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.XD"
        threat_id = "2147656823"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "c.R.Y.P.7.3.R" ascii //weight: 10
        $x_10_2 = "(PUTATAN)" wide //weight: 10
        $x_1_3 = "strup el puto amo xDDDDD" ascii //weight: 1
        $x_1_4 = "Del maquina strup xD" ascii //weight: 1
        $x_1_5 = "mala puta quien lo lea" ascii //weight: 1
        $x_1_6 = "me cago en putatan digo  matatan xDDD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_IY_2147657572_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IY"
        threat_id = "2147657572"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8B0981C1B000000089116A00E8" ascii //weight: 1
        $x_1_2 = "8B098B5128035134" ascii //weight: 1
        $x_1_3 = "8B318BB6A400000083C608" ascii //weight: 1
        $x_1_4 = "68D3C7A7E8" ascii //weight: 1
        $x_1_5 = "68A16A3DD8" ascii //weight: 1
        $x_1_6 = "68883F4A9E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_XU_2147657702_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.XU"
        threat_id = "2147657702"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 59 59 59 6a 04 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_2 = {59 50 6a 02 04 00 66 c7 45}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 2e 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 24 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 61 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 74}  //weight: 1, accuracy: Low
        $x_1_4 = {47 00 65 00 74 00 46 00 69 00 6c 00 65 00 00 00 53 00 69 00 7a 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_IZ_2147658144_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!IZ"
        threat_id = "2147658144"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 75 bb db fb f7 d8 b9 3e 37 f2 3c 83 d1 00 f7 d9}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c 50}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0c 1a 8b 5d ?? 8b d3 33 c1 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42}  //weight: 1, accuracy: Low
        $x_1_4 = {07 00 01 00 06 00 c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_JA_2147658224_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JA"
        threat_id = "2147658224"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 70 fe 6c 64 fe aa 30 9c fd}  //weight: 1, accuracy: High
        $x_1_2 = {f5 58 59 59 59}  //weight: 1, accuracy: High
        $x_1_3 = {04 70 fe 4d c0 fc 03 40 fc 8f e0 fc 01 00 04 8c fe}  //weight: 1, accuracy: High
        $x_1_4 = {f5 07 2e 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_AAM_2147658300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AAM"
        threat_id = "2147658300"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {68 d0 37 10 f2}  //weight: 5, accuracy: High
        $x_5_2 = {68 c2 8c 10 c5}  //weight: 5, accuracy: High
        $x_1_3 = {c7 85 70 f7 ff ff 0d 00 90 00 c7 85 68 f7 ff ff 02 00 00 00 8d 95 68 f7 ff ff 8b 45 d8 b9 86 00 00 00 2b 48 14 c1 e1 04 8b 45 d8 8b 40 0c 03 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AAN_2147658351_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AAN"
        threat_id = "2147658351"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 d0 37 10 f2}  //weight: 5, accuracy: High
        $x_5_2 = {68 88 fe b3 16}  //weight: 5, accuracy: High
        $x_5_3 = {68 c2 8c 10 c5}  //weight: 5, accuracy: High
        $x_1_4 = {68 86 00 00 00 c7 85 4c f7 ff ff 0d 00 00 00 ff 75 b4 89 b5 44 f7 ff ff 8d 9d 44 f7 ff ff e8 ?? ?? ff ff 8b c8 8b d3 e8 ?? ?? ff ff 68 87 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {68 a0 00 00 00 ff b5 c0 fe ff ff e8 ?? ?? ?? ?? 8b c8 8b d6 e8 ?? ?? ?? ?? c7 85 a8 f4 ff ff 8b 00 00 00 c7 85 a0 f4 ff ff 02 00 00 00 8d b5 a0 f4 ff ff 68 a1 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_JB_2147658463_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JB"
        threat_id = "2147658463"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 3c 00 00 00 aa 59 ?? ?? 5e ?? ?? ?? 00 71 ?? ?? f5 02 00 00 00 59 ?? ?? 04 ?? ?? 5e ?? ?? ?? 00 f5 4d 5a 00 00 c7 f5 04 00 00 00 59 ?? ?? 6c ?? ?? 6c ?? ?? aa 59 ?? ?? 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JC_2147658485_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JC"
        threat_id = "2147658485"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e6 ff 00 00 00 66 89 34 01 8b 45 e0 83 c0 01 0f 80 ?? ?? 00 00 99 f7 7d d8 b8 01 00 00 00 03 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 04 c1 eb e7 8b c5 8b 55 cc 8d 8d ?? ?? ff ff c7 44 c2 04 5f 5e 5b 59}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 88 08 80 00 00 ff 15 ?? ?? ?? ?? 8d 4d d0 66 8b f0 ff 15 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 8d 45 ac 8d 4d bc 50 51 6a 02 ff d3 83 c4 0c 66 85 f6 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_YA_2147658562_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.YA"
        threat_id = "2147658562"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 14 78 66 03 14 58 66 81 e2 ff 00 79 09 66 4a 66 81 ca 00 ff 66 42 0f bf da}  //weight: 1, accuracy: High
        $x_1_2 = {81 ff 00 01 00 00 66 8b 0c 78 66 89 0c 58 72 02 ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {8a 14 11 32 14 5e 88 14 01 [0-24] db 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JD_2147658784_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JD"
        threat_id = "2147658784"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 04 f2 89 4c f2 04 b8 ?? ?? ?? ?? f7 d8 b9 ?? ?? ?? ?? 83 d1 00 f7 d9 8b 15 ?? ?? ?? ?? 6a ?? 5e 2b 72 14 8b 15 ?? ?? ?? ?? 8b 52 0c 89 04 f2 89 4c f2 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 48 14 a1 ?? ?? ?? ?? 8b 40 0c c7 04 c8 ?? ?? ?? ?? c7 44 c8 04}  //weight: 1, accuracy: Low
        $x_2_3 = {b8 04 07 00 00 8b 3c 24 [0-64] 83 e8 04 0f 6e 07 0f 6e ce 0f ef c1 0f 7e 07 83 c7 04 85 c0 75 ea c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_JD_2147658784_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JD"
        threat_id = "2147658784"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 d8 42 e8 bb 03 a1 ?? ?? ?? ?? c7 44 d8 04 00 00 8b 54}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 04 d8 e8 5c 03 00 a1 ?? ?? ?? ?? c7 44 d8 04 00 8b 09 c7}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 0c c7 04 88 eb f2 c3 00 8b 45}  //weight: 1, accuracy: High
        $x_1_4 = {8b 40 0c c7 04 88 02 eb 07 29 8b 45}  //weight: 1, accuracy: High
        $x_2_5 = {b8 00 77 ba 0f f7 d8 b9 44 6c ca 20 83 d1 00 f7 d9 8b 95 ?? ?? ff ff 8b b5 ?? ?? ff ff 89 04 d6 89 4c d6 04}  //weight: 2, accuracy: Low
        $x_1_6 = {6a 04 58 6b c0 03 8b (4d ??|0d ?? ?? ?? ??) c7 04 01 02 eb 07 29}  //weight: 1, accuracy: Low
        $x_1_7 = {6a 04 58 6b c0 05 8b (4d ??|0d ?? ?? ?? ??) c7 04 01 eb f2 c3 00}  //weight: 1, accuracy: Low
        $x_2_8 = {c7 01 60 e8 4e 00 8b 55 ?? c7 42 04 00 00 6b 00 8b 45 00 c7 40 08 65 00 72 00 8b 4d 00 c7 41 0c 6e 00 65 00}  //weight: 2, accuracy: Low
        $x_2_9 = {6a 04 58 c1 e0 02 8b 0d ?? ?? ?? ?? c7 04 01 c2 04 eb f4 6a 04 58 (6b|d1 e0) 8b 0d ?? ?? ?? ?? c7 04 01 (07 29|83 3a)}  //weight: 2, accuracy: Low
        $x_2_10 = {c7 04 81 c2 04 eb f4 c7 45 ?? ?? 00 00 00 83 7d ?? ?? 73 06 83 65 ?? 00 eb 08 e8 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 8b 0d ?? ?? ?? ?? c7 04 81 07 29 0a 83}  //weight: 2, accuracy: Low
        $x_1_11 = {f5 07 29 0a 83 f5 03 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_12 = {f5 c2 04 eb f4 f5 04 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_13 = {f5 8b 4c 24 08 f5 01 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_JD_2147658784_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JD"
        threat_id = "2147658784"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 c9 74 02 eb f5 04 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 8b 54 24 08 f5 01 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 83 c0 04 eb f5 04 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_4 = {f5 04 eb f3 c3 f5 05 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_5 = {f5 29 10 83 c0 f5 04 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_6 = {f5 fc eb f1 c3 f5 04 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_7 = {f5 74 05 29 50 f5 04 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_8 = {f6 55 ec 64 a1 30 00 00 00 f5 2d 00 00 00 04 ?? ?? a4}  //weight: 1, accuracy: Low
        $x_1_9 = {f6 8b 40 0c 8b 40 14 8b 40 f5 2e 00 00 00 04 ?? ?? a4}  //weight: 1, accuracy: Low
        $x_1_10 = {f5 fc eb f1 c3 f5 05 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_11 = {f5 74 05 31 50 f5 04 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_12 = {f5 e0 f2 c3 00 f5 05 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_13 = {f5 8b 44 24 04 f5 00 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_14 = {f5 83 c0 04 e0 f5 05 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_15 = {f5 e0 f0 c3 00 f5 06 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_16 = {f5 74 08 31 10 f5 04 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_17 = {f5 00 74 07 31 f5 03 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_18 = {f5 e0 f2 c2 10 f5 05 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_19 = {f5 8b 5c 24 04 f5 00 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_20 = {f5 c3 04 e0 f1 f5 05 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_21 = {f5 08 31 13 83 f5 04 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_22 = {f5 f0 c2 10 00 f5 06 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_23 = {f5 31 18 83 c0 f5 04 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
        $x_1_24 = {f5 04 e0 f2 c9 f5 05 00 00 00 (07|94) 08 00 ?? 00 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_JD_2147658784_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JD"
        threat_id = "2147658784"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 04 59 2b 48 ?? a1 ?? ?? ?? ?? 8b 40 ?? c7 04 88 c2 04 eb f4 a1 ?? ?? ?? ?? 6a 03 59 2b 48 ?? a1 ?? ?? ?? ?? 8b 40 ?? c7 04 88 07 29 0a 83}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 04 c2 24 28 89 11 8b 0d ?? ?? ?? ?? 8d 55 ?? c7 44 c1 04 8b 54 24 2c 8d 45 01 52 8d 4d ?? 50}  //weight: 2, accuracy: Low
        $x_2_3 = {c7 80 30 02 00 00 64 a1 30 00 8b (85 ?? ??|45 ??) c7 80 34 02 00 00 00 00 8b 40}  //weight: 2, accuracy: Low
        $x_2_4 = "00012CD5CE98B5E5F50C135E57101C38A0409841D5B83057103C3801D" wide //weight: 2
        $x_2_5 = {c7 80 bc 01 00 00 68 00 30 00 c7 80 c0 01 00 00 00 ff 72 50 c7 80 c4 01 00 00 ff 77 34 ff}  //weight: 2, accuracy: High
        $x_2_6 = {c7 00 10 83 c0 04 6a 05 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 00 e0 f2 c3 00 8b 45 08}  //weight: 2, accuracy: Low
        $x_1_7 = {c7 04 d8 00 ff 72 50 c7 44 d8 04 ff 77 34 ff}  //weight: 1, accuracy: High
        $x_1_8 = {c7 04 d8 31 ff d0 6a c7 44 d8 04 36 e8 47 02}  //weight: 1, accuracy: High
        $x_1_9 = {8b 40 0c c7 04 88 e0 f0 c3 00 a1}  //weight: 1, accuracy: High
        $x_1_10 = {8b 40 0c c7 04 88 74 08 31 13 a1}  //weight: 1, accuracy: High
        $x_1_11 = {6b c0 05 8b 0d ?? ?? ?? ?? c7 04 01 (e0 f2|90 83)}  //weight: 1, accuracy: Low
        $x_1_12 = {6b c0 03 8b 0d ?? ?? ?? ?? c7 04 01 (00 74|0b 83)}  //weight: 1, accuracy: Low
        $x_1_13 = {c7 04 81 18 83 c0 04 c7 45 ?? ?? 00 00 00 83 7d ?? 07 73 06}  //weight: 1, accuracy: Low
        $x_1_14 = {c7 04 81 e0 f0 c9 c3 c7 45 ?? ?? 00 00 00 83 7d ?? 07 73 06}  //weight: 1, accuracy: Low
        $x_1_15 = {c7 04 c1 00 00 00 83 c7 44 c1 04 c4 08 c3 55}  //weight: 1, accuracy: High
        $x_1_16 = {c7 04 c1 01 00 00 6a c7 44 c1 04 28 52 ff 31}  //weight: 1, accuracy: High
        $x_1_17 = {c7 04 01 04 83 38 00 a1 ?? ?? ?? ?? c7 40 04 8b 4c 24 08}  //weight: 1, accuracy: Low
        $x_1_18 = {c7 04 01 75 f6 c3 00 a1 ?? ?? ?? ?? c7 00 8b 44 24 04}  //weight: 1, accuracy: Low
        $x_1_19 = {8b 40 0c c7 04 88 8b 44 24 04 a1}  //weight: 1, accuracy: High
        $x_1_20 = {8b 40 0c c7 04 88 31 08 83 c0 a1}  //weight: 1, accuracy: High
        $x_2_21 = {6b c0 03 8b 0d ?? ?? ?? ?? c7 04 01 04 83 38 00 a1 ?? ?? ?? ?? c7 40 04 8b 4c 24 08 a1 ?? ?? ?? ?? c7 00 8b 44 24 04}  //weight: 2, accuracy: Low
        $x_1_22 = {c7 04 81 31 1a 83 c2 c7 45 ?? ?? 00 00 00 83 7d ?? 07 73 06}  //weight: 1, accuracy: Low
        $x_1_23 = {c7 04 81 75 f6 c3 00 c7 45 ?? ?? 00 00 00 83 7d ?? 07 73 06}  //weight: 1, accuracy: Low
        $x_1_24 = {c7 04 81 83 c2 04 31 c7 45 ?? ?? 00 00 00 83 7d ?? 07 73 06}  //weight: 1, accuracy: Low
        $x_1_25 = {c7 04 81 8b 54 24 04 c7 45 ?? ?? 00 00 00 83 7d ?? 07 73 06}  //weight: 1, accuracy: Low
        $x_1_26 = {c7 04 c8 30 83 78 28 c7 44 c8 04 00 74 0a 0f}  //weight: 1, accuracy: High
        $x_1_27 = {c7 04 c8 64 a1 18 00 c7 44 c8 04 00 00 8b 40}  //weight: 1, accuracy: High
        $x_1_28 = {c7 04 81 85 db 74 07 c7 45 ?? ?? 00 00 00 83 7d ?? 06 73 06}  //weight: 1, accuracy: Low
        $x_1_29 = {c7 04 81 31 c0 8b 44 c7 45 ?? ?? 00 00 00 83 7d ?? 06 73 06}  //weight: 1, accuracy: Low
        $x_1_30 = {c7 04 c8 f3 a4 60 ff c7 44 c8 04 75 18 ff 75}  //weight: 1, accuracy: High
        $x_1_31 = {c7 04 c8 10 50 6a 40 c7 44 c8 04 68 00 10 00}  //weight: 1, accuracy: High
        $x_1_32 = {c7 04 c8 55 89 e5 8b c7 44 c8 04 5d 08 8b 43}  //weight: 1, accuracy: High
        $x_1_33 = {c7 04 c8 08 80 3b 08 c7 44 c8 04 75 02 8b 00}  //weight: 1, accuracy: High
        $x_1_34 = {c7 00 83 c3 04 eb c7 40 04 51 59 89 0b}  //weight: 1, accuracy: High
        $x_1_35 = {c7 00 f3 a4 60 ff c7 40 04 75 18 ff 75}  //weight: 1, accuracy: High
        $x_1_36 = {c7 00 0c 31 37 83 0d 00 6a 03 ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_37 = {c7 00 c7 04 83 3f 0d 00 6a 04 ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_38 = {c7 04 c8 75 14 ff 75 c7 44 c8 04 10 ff 75 0c}  //weight: 1, accuracy: High
        $x_1_39 = {c7 04 c8 6a 00 ff d0 c7 44 c8 04 83 f8 00 74}  //weight: 1, accuracy: High
        $x_1_40 = {c7 04 c8 75 0c ff d0 c7 44 c8 04 c9 c3 00 00}  //weight: 1, accuracy: High
        $x_1_41 = {c7 04 c8 6a 40 68 00 c7 44 c8 04 10 00 00 68}  //weight: 1, accuracy: High
        $x_1_42 = {c7 04 c8 0b 83 eb 0c c7 44 c8 04 53 ff 10 50}  //weight: 1, accuracy: High
        $x_1_43 = {c7 00 6a 40 68 00 c7 40 04 10 00 00 68}  //weight: 1, accuracy: High
        $x_1_44 = {c7 00 00 60 ff 75 c7 40 04 18 ff 75 14}  //weight: 1, accuracy: High
        $x_1_45 = {c7 00 ff 75 14 ff c7 40 04 75 10 ff 75}  //weight: 1, accuracy: High
        $x_1_46 = {c7 00 00 00 68 00 c7 40 04 08 00 00 6a}  //weight: 1, accuracy: High
        $x_1_47 = {c7 04 01 75 18 ff 75 c7 44 01 04 14 ff 75 10}  //weight: 1, accuracy: High
        $x_1_48 = {c7 04 01 40 68 00 10 c7 44 01 04 00 00 68 00}  //weight: 1, accuracy: High
        $x_1_49 = {c7 04 c1 00 6a 40 68 c7 44 c1 04 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_50 = {c7 04 c1 0f 0f 82 e0 c7 44 c1 04 00 00 00 0f}  //weight: 1, accuracy: High
        $x_1_51 = {c7 04 c1 55 8b ec 83 c7 44 c1 04 75 f7 81 78}  //weight: 1, accuracy: High
        $x_1_52 = {c7 04 01 68 00 00 04 c7 44 01 04 00 52 51 54}  //weight: 1, accuracy: High
        $x_1_53 = {c7 04 01 00 00 68 00 c7 44 01 04 08 00 00 6a}  //weight: 1, accuracy: High
        $x_1_54 = {c7 04 81 00 ff d0 85 (c7 45 f8 ?? 00|83 65) 83 7d f8}  //weight: 1, accuracy: Low
        $x_1_55 = {c7 04 81 75 0c ff d0 c7 45 f8 ?? 00 00 00 83 7d f8}  //weight: 1, accuracy: Low
        $x_1_56 = {c7 04 81 10 ff 75 0c c7 45 ?? ?? 00 00 00 83 7d ?? 4c}  //weight: 1, accuracy: Low
        $x_1_57 = {c7 04 81 ff 75 18 ff c7 45 ?? ?? 00 00 00 83 7d ?? 4c}  //weight: 1, accuracy: Low
        $x_1_58 = {c7 04 01 8b 43 08 80 6a 04}  //weight: 1, accuracy: High
        $x_1_59 = {c7 40 04 e5 8b 5d 08 6a 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_YJ_2147659102_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.YJ"
        threat_id = "2147659102"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 74 24 0c 57 8b 3e 81 ff 00 01 00 00 72 06 ff 15 ?? ?? ?? 00 8b 0d ?? ?? ?? ?? 8a 44 24 0c 68 ?? ?? ?? ?? 88 04 39 ff 15 ?? ?? ?? ?? 8b 0e 5f 03 c1 70 06 89 06 5e c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = "ZNWlXGoKPwKAt/HS18yQNPoQV8PTdF5xfJNs6/N9VDY=" wide //weight: 1
        $x_1_3 = "+gsDSxoqDDGwXGcYdutwo3PukPVhusWYxPagX22CGNA=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_YK_2147659230_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.YK"
        threat_id = "2147659230"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 bb 17 44 ac f7 d8 b9 ec 3e 87 74 83 d1 00 f7 d9 8b 95 b0 f9 ff ff 8b 75 e0 89 04 d6 89 4c d6 04 c7 85 b0 f9 ff ff 10 00 00 00 83 bd b0 f9 ff ff 58 73 09 83 a5 58 f9 ff ff 00 eb 0b}  //weight: 1, accuracy: High
        $x_1_2 = {b8 1b ff ff ff f7 d8 b9 97 2d 38 58 83 d1 00 f7 d9 8b 95 ?? ?? ?? ?? 8b ((b5|35) ?? ?? ?? ??|75 ??) 89 04 d6 89 4c d6 04 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_VBInject_JF_2147661437_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JF"
        threat_id = "2147661437"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 70 fe 6c 64 fe aa 30 9c fd}  //weight: 1, accuracy: High
        $x_1_2 = {f5 58 59 59 59}  //weight: 1, accuracy: High
        $x_1_3 = {01 00 71 ec fc 03 00 f5 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_YZ_2147661496_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.YZ"
        threat_id = "2147661496"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 c1 84 c0 74 07 c7 44 c1 04 c1 cf 0d 03 e9 ?? ?? 00 00 c7 85 1c ff ff ff 6e 00 00 00 81 bd 1c ff ff ff a1 00 00 00 73 ?? 83 a5 f0 fe ff ff 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ZM_2147662349_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ZM"
        threat_id = "2147662349"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 50 f7 ff ff cf 00 89 bd 48 f7 ff ff 8d 95 48 f7 ff ff 8b 45 a8 b9 85 00 00 00 2b 48 14 c1 e1 04 03 48 0c ff d6 8b 45 a8 b9 86 00 00 00 c7 85 40 f7 ff ff 0d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ZN_2147662381_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ZN"
        threat_id = "2147662381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 80 dc 04 00 00 c1 cf 0d 03 8b 0d ?? ?? ?? ?? c7 81 e0 04 00 00 f8 eb f4 3b 8b 15 ?? ?? ?? ?? c7 82 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 82 dc 04 00 00 c1 cf 0d 03 a1 ?? ?? ?? ?? c7 80 e0 04 00 00 f8 eb f4 3b 8b 0d ?? ?? ?? ?? c7 81 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 82 dc 04 00 00 c1 cf 0d 03 8b ?? ?? c7 81 e0 04 00 00 f8 eb f4 3b 8b ?? ?? c7 82 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 82 dc 04 00 00 c1 cf 0d 03 8b 15 ?? ?? ?? ?? c7 82 e0 04 00 00 f8 eb f4 3b 8b 15 ?? ?? ?? ?? c7 82 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 04 f9 f8 eb f4 3b 8b 15 ?? ?? ?? ?? c7 44 fa 04 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_6 = {c7 80 dc 04 00 00 c1 cf 0d 03 8b 0d ?? ?? ?? ?? c7 81 e0 04 00 00 f8 eb f4 3b a1 ?? ?? ?? ?? c7 80 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_7 = {c7 80 dc 04 00 00 c1 cf 0d 03 a1 ?? ?? ?? ?? c7 80 e0 04 00 00 f8 eb f4 3b a1 ?? ?? ?? ?? c7 80 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_8 = {c7 81 dc 04 00 00 c1 cf 0d 03 8b ?? ?? c7 82 e0 04 00 00 f8 eb f4 3b 8b ?? ?? c7 81 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_9 = {c7 80 dc 04 00 00 c1 cf 0d 03 8b ?? ?? ?? ?? ?? c7 81 e0 04 00 00 f8 eb f4 3b a1 ?? ?? ?? ?? c7 80 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_10 = {c7 81 dc 04 00 00 c1 cf 0d 03 8b ?? ?? ?? ?? ?? c7 82 e0 04 00 00 f8 eb f4 3b 8b ?? ?? ?? ?? ?? c7 81 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_11 = {c7 82 dc 04 00 00 c1 cf 0d 03 8b 0d ?? ?? ?? ?? c7 81 e0 04 00 00 f8 eb f4 3b 8b 15 ?? ?? ?? ?? c7 82 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_12 = {c7 82 dc 04 00 00 c1 cf 0d 03 8b 0d ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? c7 81 e0 04 00 00 f8 eb f4 3b 8b 15 ?? ?? ?? ?? c7 82 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_13 = {c7 81 dc 04 00 00 c1 cf 0d 03 8b 0d ?? ?? ?? ?? c7 81 e0 04 00 00 f8 eb f4 3b 8b 0d ?? ?? ?? ?? c7 81 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
        $x_1_14 = {c7 83 dc 04 00 00 c1 cf 0d 03 8b 1d ?? ?? ?? ?? c7 83 e0 04 00 00 f8 eb f4 3b 8b 1d ?? ?? ?? ?? c7 83 e4 04 00 00 7c 24 20 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_VBInject_JJ_2147665039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JJ"
        threat_id = "2147665039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 55 89 e5 8b a1 ?? ?? ?? ?? c7 40 04 75 08 8b 4d 6a 04 58 d1 e0 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 1c a1 ?? ?? ?? ?? 33 c9 2b 48 14 a1 ?? ?? ?? ?? 8b 40 0c c7 04 c8 fd 0a b7 01 83 64 c8 04 00 a1 ?? ?? ?? ?? 6a 01 59 2b 48 14 a1 ?? ?? ?? ?? 8b 40 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JK_2147665040_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JK"
        threat_id = "2147665040"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 60 00 00 00 ff d6 8b 0d ?? ?? ?? ?? 8b 51 0c 8b 79 14 2b d7 b9 e8 00 00 00 88 02 ff d6 8b 0d ?? ?? ?? ?? 8b 51 0c 8b 79 14 2b d7 b9 4e 00 00 00 88 42 01 ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {00 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 e1 01 89 4d fc 24 fe 50 89 45 08 8b 10 ff 52 04 b9 04 00 02 80 33 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JL_2147666617_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JL"
        threat_id = "2147666617"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 01 00 (0b 00 c7|0a 00)}  //weight: 1, accuracy: Low
        $x_1_2 = {0b c0 74 02 ff e0 68 ?? ?? 40 00 b8 ?? ?? 40 00 ff d0 ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = "doandwiadnio" ascii //weight: 1
        $x_1_4 = "ACTIVESKINLibCtl.Skin" ascii //weight: 1
        $x_1_5 = ".vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ABD_2147669167_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ABD"
        threat_id = "2147669167"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 04 04 04 04 49 0f 85 ?? ?? ?? ?? 33 c0 8b 7d 08 33 db 8b 75 0c 8a 91 ?? ?? ?? ?? 02 04 3b 02 c2 8a b0 ?? ?? ?? ?? 88 b1 ?? ?? ?? ?? 88 90 ?? ?? ?? ?? fe c1}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 77 54 eb 00 00 ff 77 54 56 53 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d 47 18}  //weight: 1, accuracy: Low
        $x_1_3 = {66 3b 77 06 (eb 00 00|0f 82 00 00) 6b c6 28 03 45 f0 bb 00 00 40 00 03 58 0c 8b 15 ?? ?? ?? ?? 03 50 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JN_2147678610_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JN"
        threat_id = "2147678610"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 ff d8 ff e0 20 10 4a 46 49 46}  //weight: 1, accuracy: High
        $x_1_2 = {b9 58 00 00 00 ff d6 8d 55 d4 88 45 d4 52 e8 ?? ?? ?? ?? b9 59 00 00 00 ff d6 88 45 d4 8d 45 d4 50 e8 ?? ?? ?? ?? b9 59 00 00 00 ff d6}  //weight: 1, accuracy: Low
        $x_1_3 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 45 ?? 66 33 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JP_2147678649_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JP"
        threat_id = "2147678649"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 ff 50 6a 00 6a 00 6a 04 f5 25 00 00 00 04 ?? ff a4}  //weight: 1, accuracy: Low
        $x_1_2 = {f6 77 54 ff 75 fc ff b5 74 f5 35 00 00 00 04 ?? ff a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JQ_2147678827_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JQ"
        threat_id = "2147678827"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {68 d0 37 10 f2}  //weight: 50, accuracy: High
        $x_50_2 = {68 88 fe b3 16}  //weight: 50, accuracy: High
        $x_10_3 = "vbaStrVarMove" ascii //weight: 10
        $x_1_4 = {b9 84 00 00 00 c7 85 ?? ?? ?? ?? c1 00 00 90 89 bd ?? ?? ?? ?? 2b 48 14 8d 95 ?? ?? ?? ?? c1 e1 04}  //weight: 1, accuracy: Low
        $x_1_5 = {b9 85 00 00 00 2b 48 14 c1 e1 04 03 48 0c ff d6 8b 45 ?? c7 85 ?? ?? ?? ?? 0d 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {b9 84 00 00 00 c7 85 ?? ?? ?? ?? c1 00 0d 00 c7 85 ?? ?? ?? ?? 02 00 00 00 2b 48 14 8d 95 ?? ?? ?? ?? c1 e1 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_JR_2147678854_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JR"
        threat_id = "2147678854"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 00 00 00 59 00 6f 00 75 00 20 00 67 00 6f 00 74 00 20 00 6f 00 77 00 6e 00 65 00 64 00 20 00 62 00 79 00 20 00 44 00 45 00 20 00 74 00 65 00 61 00 6d 00 20 00 3d 00 29 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 3a 5c 55 73 65 72 73 5c 73 5c 44 65 73 6b 74 6f 70 5c 44 5c 56 42 36 2e 4f 4c 42 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JT_2147678940_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JT"
        threat_id = "2147678940"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dE5yV3RpVmVyaXV0bGFlTW9teXI=" wide //weight: 1
        $x_1_2 = "WVNUU01FQ1xub3J0bG9lUzB0MTBTXHJlaXZlY1xzaURrc0VcdW5t" wide //weight: 1
        $x_1_3 = "SCYzQw==" wide //weight: 1
        $x_1_4 = "dFJEbGNlbW9ycHNlQnNmdWVmcg==" wide //weight: 1
        $x_1_5 = "ZEF1anRzb1Rla1BuaXJpdmVsZWdz" wide //weight: 1
        $x_1_6 = "T1NURkFXRVJNXGNpb3Jvc3RmU1xjZXJ1dGkgeWVDdG5yZQ==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_VBInject_JV_2147679097_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JV"
        threat_id = "2147679097"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 d2 00 00 00 ff d7 8b 56 44 b9 c7 00 00 00 88 82 35 03 00 00 ff d7 8b 4e 44 88 81 36 03 00 00 b9 a7 00 00 00 ff d7 8b 56 44 b9 68 00 00 00 88 82 37 03 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 d2 00 00 00 ff d6 8b 15 ?? ?? ?? ?? b9 c7 00 00 00 88 82 35 03 00 00 ff d6 8b 0d ?? ?? ?? ?? 88 81 36 03 00 00 b9 a7 00 00 00 ff d6 8b 15 ?? ?? ?? ?? b9 68 00 00 00 88 82 37 03 00 00 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_VBInject_ABL_2147679105_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ABL"
        threat_id = "2147679105"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 33 34 66 32 65 34 00 6e 76 6d 66 63 30 30 00 6c 79 31 31 61 77 67 00 6d 6a 6e 79 33 31 30 00 75 6e 6b 6e 69 78 00 00 0d 00 00 00 4b 65 72 6e}  //weight: 1, accuracy: High
        $x_1_2 = {6b 6e 69 78 00 00 75 6e 6b 6e 69 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "D4S5F56SD1F1" wide //weight: 1
        $x_1_5 = {43 00 68 00 69 00 73 00 74 00 00 00 0a 00 00 00 72 00 75 00 6e 00 61 00 73 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JX_2147679365_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JX"
        threat_id = "2147679365"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 ?? 0f 80 ?? 00 00 00 89 45 08 8b 45 08 3b 45 ?? 7f ?? c7 45 ?? ?? 00 00 00 ff 75 ?? ff 75 08 e8 ?? ?? ?? ff 8b d0}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 76 62 61 6d 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 00 40 08 75 02 c7 40 04 8b 00 c2 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_JZ_2147680248_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!JZ"
        threat_id = "2147680248"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6.2.66.106" wide //weight: 1
        $x_1_2 = "Skype Technologies S.A." wide //weight: 1
        $x_2_3 = "Manijeh Ardene" wide //weight: 2
        $x_3_4 = "C:\\Users\\s\\Desktop\\Must Use Different Name\\Folder Name\\" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ABS_2147681299_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ABS"
        threat_id = "2147681299"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b 0d ?? ?? ?? ?? c7 04 c1 43 61 6c 6c c7 44 c1 04 57 69 6e 64}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 8b 0d ?? ?? ?? ?? c7 04 c1 56 69 72 74 c7 44 c1 04 75 61 6c 50}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 fc 8b 0d ?? ?? ?? ?? c7 04 c1 6f 77 50 72 c7 44 c1 04 6f 63 57 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 fc 8b 0d ?? ?? ?? ?? c7 04 c1 6c 73 74 72 c7 44 c1 04 6c 65 6e 57}  //weight: 1, accuracy: Low
        $x_4_5 = "MSVBVM60.DLL" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_KX_2147681852_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!KX"
        threat_id = "2147681852"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 72 50 8b (1d|0d|15) ?? ?? ?? ?? c7 (80|81|82|83)}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 77 34 ff 04 02 02 02 01 8b 1d 8b 0d 8b 15 a1 0a 00 c7 (80|81|82|83)}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 30 00 04 02 02 02 01 8b 1d 8b 0d 8b 15 a1 0a 00 c7 (80|81|82|83)}  //weight: 1, accuracy: Low
        $x_1_4 = {c2 f8 00 00 04 02 02 02 01 8b 1d 8b 0d 8b 15 a1 0a 00 c7 (80|81|82|83)}  //weight: 1, accuracy: Low
        $x_2_5 = {01 07 00 01 04 02 02 02 01 8b 1d 8b 0d 8b 15 a1 0a 00 c7 (80|81|82|83)}  //weight: 2, accuracy: Low
        $x_1_6 = {c1 b0 00 00 04 02 02 02 01 8b 1d 8b 0d 8b 15 a1 0a 00 c7 (80|81|82|83)}  //weight: 1, accuracy: Low
        $x_2_7 = {68 d0 37 10 04 02 02 02 01 8b 1d 8b 0d 8b 15 a1 0a 00 (c7 (80|81|82|83)|?? ?? ?? c7)}  //weight: 2, accuracy: Low
        $x_2_8 = {a1 6a 3d d8 04 02 02 02 01 8b 1d 8b 0d 8b 15 a1 0a 00 c7 (80|81|82|83)}  //weight: 2, accuracy: Low
        $x_2_9 = {c7 a7 e8 51 04 02 02 02 01 8b 1d 8b 0d 8b 15 a1 0a 00 c7 (80|81|82|83)}  //weight: 2, accuracy: Low
        $x_2_10 = {c7 04 c2 00 ff 72 50 8b 0d ?? ?? ?? ?? 8d 55 ?? c7 44 c1 04 ff 77 34 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_KY_2147682249_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!KY"
        threat_id = "2147682249"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 a7 e8 51 06 00 c7 (80|81|82|83)}  //weight: 2, accuracy: Low
        $x_1_2 = {c1 b0 00 00 06 00 c7 (80|81|82|83)}  //weight: 1, accuracy: Low
        $x_2_3 = {01 07 00 01 06 00 c7 (80|81|82|83)}  //weight: 2, accuracy: Low
        $x_1_4 = {68 00 30 00 06 00 c7 (80|81|82|83)}  //weight: 1, accuracy: Low
        $x_1_5 = {c2 f8 00 00 06 00 c7 (80|81|82|83)}  //weight: 1, accuracy: Low
        $x_2_6 = {c7 04 c8 00 ff 72 50 c7 44 c8 04 ff 77 34 ff}  //weight: 2, accuracy: High
        $x_2_7 = {ff 77 34 ff 10 00 c7 (80|81|82|83) ?? ?? ?? ?? 00 ff 72 50 c7 (80|81|82|83)}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_ACC_2147682660_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACC"
        threat_id = "2147682660"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 50 41 40 00 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {68 98 47 40 00 ff d6}  //weight: 1, accuracy: High
        $x_1_3 = {50 65 70 65 72 6f 6e 69 26 50 72 65 73 69 64 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "BrokenHearth" wide //weight: 1
        $x_1_5 = "Motown" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_LA_2147682729_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!LA"
        threat_id = "2147682729"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 ab 76 1a 74 f7 d8 b9 ba f7 7c 3f 83 d1 00 f7 d9}  //weight: 1, accuracy: High
        $x_1_2 = {c7 40 08 08 8b 00 31 c7 40 0c c9 3b 4d 0c}  //weight: 1, accuracy: High
        $x_1_3 = {c7 04 01 74 02 8b 00 c7 44 01 04 c9 c3 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_LB_2147682755_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!LB"
        threat_id = "2147682755"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 0c c7 04 c8 55 89 e5 31 c7 44 c8 04 c0 31 db 31}  //weight: 1, accuracy: High
        $x_1_2 = {68 f8 00 00 00 ff 75 08 8d 45 ec 50 e8 ?? ?? ff ff 68 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 0c c7 04 c8 89 0b 83 c3 c7 44 c8 04 04 eb 64 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_LC_2147682864_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!LC"
        threat_id = "2147682864"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 55 89 e5 eb 6a 04 58 6b c0 03 8b 0d ?? ?? ?? 00 c7 04 01 00 75 f6 c9 a1 ?? ?? ?? 00 c7 40 04 0c 31 37 83 6a 04 58 6b c0 06 8b 0d ?? ?? ?? 00 c7 04 01 ec 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACD_2147682939_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACD"
        threat_id = "2147682939"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 5c 00 41 00 4c 00 3a 00 5c 01 4a 00 61 00 63 00 6b 00 69 00 6e 00 74 00 68 00 5c 01 4a 00 61 00 63 00 6b 00 69 00 6e 00 74 00 68 00 31 00 2e 00 76 00 62 00 70}  //weight: 1, accuracy: High
        $x_1_2 = {48 4f 53 54 41 4c 68 6f 48 4f 53 54 41 4c 68 6f 21 5c 48 4f 53 54 41 4c 68 6f 00 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_3 = "Jackinth.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_LD_2147683922_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!LD"
        threat_id = "2147683922"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 65 72 4f 63 78 00 [0-10] 46 75 63 6b 42 69 74 44 65 66}  //weight: 1, accuracy: Low
        $x_10_2 = {f5 00 00 00 00 f5 00 00 00 00 6c ?? (fe|ff) 6c ?? (fe|ff) 6c ?? (fe|ff) 0a ?? 00 14 00 3c 14}  //weight: 10, accuracy: Low
        $x_1_3 = {4d 73 5f 6c 6f 6c 00 [0-10] 46 75 63 6b 4d 73 61 6e 64 4d 73 6e 64 4d 73}  //weight: 1, accuracy: Low
        $x_1_4 = "scrwAvstanduall" ascii //weight: 1
        $x_1_5 = {75 5f 6d 5f 73 5f 70 6f 6f 72 5f 74 68 69 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = "ilbalwaysthebes" ascii //weight: 1
        $x_1_7 = "ayastbesilbhelw" ascii //weight: 1
        $x_1_8 = "stbayaelwesilbh" ascii //weight: 1
        $x_1_9 = "astllesbwaybeih" ascii //weight: 1
        $x_1_10 = "tbbswyseihalel" ascii //weight: 1
        $x_1_11 = "eslehbsiatbwyl" ascii //weight: 1
        $x_1_12 = "tuikidnicn" ascii //weight: 1
        $x_1_13 = "altblssyeeibwh" ascii //weight: 1
        $x_1_14 = "lssbeialtbwyeh" ascii //weight: 1
        $x_1_15 = "tlssbbeyehialw" ascii //weight: 1
        $x_1_16 = "sbbieehltlaysw" ascii //weight: 1
        $x_1_17 = "iltbeayshelsbw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_LE_2147684353_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!LE"
        threat_id = "2147684353"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "snxhk.dll" wide //weight: 1
        $x_1_2 = {64 a1 30 00 00 00 8a 40 68 24 70 3c 70 0f 84 ?? ?? ?? ?? b8 01 00 00 00 0f a2}  //weight: 1, accuracy: Low
        $x_1_3 = {64 a1 18 00 00 00 8b 40 30 80 78 02 01 0f 84}  //weight: 1, accuracy: High
        $x_12_4 = {81 38 55 8b ec 83 [0-1] 75 [0-2] 81 78 04 ec 0c 56 8d}  //weight: 12, accuracy: Low
        $x_1_5 = {8b 04 0a 01 f3 0f 6e c0 0f 6e 0b 0f ef c1 51 0f 7e c1}  //weight: 1, accuracy: High
        $x_1_6 = {41 66 8b 14 08 66 81 fa 42 4d 75 f4 51 83 c1 0e 8b 14 08 59 83 fa 28 75 e7}  //weight: 1, accuracy: High
        $x_1_7 = {89 4f 04 89 f9 83 c1 48 89 4f 0c 83 c1 44 89 4f 08 83 c1 10 89 4f 10 81 c1 d0 00 00 00 89 4f 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_12_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_LF_2147684387_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!LF"
        threat_id = "2147684387"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 04 c1 64 a1 18 00 c7 44 c1 04 00 00 8b 40}  //weight: 2, accuracy: High
        $x_2_2 = {c7 04 c1 55 89 e5 90 c7 44 c1 04 31 f6 90 31}  //weight: 2, accuracy: High
        $x_2_3 = {c7 04 c1 c0 8b 75 08 c7 44 c1 04 90 8b 46 08}  //weight: 2, accuracy: High
        $x_1_4 = {c7 00 07 0f 6e ce c7 40 04 0f ef c1 0f}  //weight: 1, accuracy: High
        $x_1_5 = {c7 00 65 72 6e 65 c7 40 04 6c 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_LG_2147684429_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!LG"
        threat_id = "2147684429"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 18 00 00 00 8b 40 30 80 78 02 01}  //weight: 1, accuracy: High
        $x_1_2 = {64 8b 1d 18 00 00 00 8b 5b 30 80 7b 02 01}  //weight: 1, accuracy: High
        $x_1_3 = {64 8b 0d 18 00 00 00 [0-1] 8b 49 30 [0-1] 80 79 02 01}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 6e c8 0f 6e c2 [0-4] 0f f8 c8 0f d7 d8 0f 77 01 de 01 d9 81 f9}  //weight: 1, accuracy: Low
        $x_1_5 = {0f f8 c8 0f 64 c1 0f d7 d8 01 d9 81 f9}  //weight: 1, accuracy: High
        $x_1_6 = {83 c1 02 83 e9 02 41 83 c6 02 83 ee 02 46 81 f9 ?? ?? ?? ?? 72 ea 81 fe}  //weight: 1, accuracy: Low
        $x_1_7 = {0f 31 25 ff 00 00 00 01 c6 81 fe b0 ab 5f 0d 72 ee}  //weight: 1, accuracy: High
        $x_1_8 = {0f 6e 07 0f 6e ce 0f ef c1 0f 7e 07}  //weight: 1, accuracy: High
        $x_12_9 = {81 38 55 8b ec 83 [0-1] 75 [0-2] 81 78 04 ec 0c 56 8d}  //weight: 12, accuracy: Low
        $x_12_10 = {81 78 04 ec 0c 56 8d [0-1] 75 [0-2] 81 38 55 8b ec 83}  //weight: 12, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_12_*) and 2 of ($x_1_*))) or
            ((2 of ($x_12_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_LH_2147684450_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!LH"
        threat_id = "2147684450"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 b9 24 00 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 c7 45 ?? ?? 00 00 00 81 7d d4 ?? ?? 00 00 73 09 83 a5 ?? ?? ?? ?? 00 eb 0b e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 66 b9 28 00 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 c7 45 ?? ?? 00 00 00 81 7d d4 ?? ?? 00 00 73 09 83 a5 ?? ?? ?? ?? 00 eb 0b e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 66 b9 89 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_LL_2147684592_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!LL"
        threat_id = "2147684592"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\REeB.vbp" wide //weight: 1
        $x_1_2 = "\\ffzefzefz.vbp" wide //weight: 1
        $x_1_3 = "\\gugu.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_VBInject_LN_2147686119_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!LN"
        threat_id = "2147686119"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 6e 45 00 [0-32] 66 0f 6e cc [0-48] 66 0f ef c1 [0-48] 66 0f 7e 45 fc [0-32] 81 7d fc 90 90 90 90 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 6e 4c 24 08 [0-32] 0f ef c1 [0-32] 0f 7e 45 00 83 c5 04 [0-32] 83 7c 24 0c 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {6c 74 00 00 ?? ?? ?? ?? 42 4d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 28 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_MC_2147687012_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!MC"
        threat_id = "2147687012"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fb 12 fc 0d 04 ?? ?? fc 22 80 ?? ?? fc a0}  //weight: 2, accuracy: Low
        $x_2_2 = {4a f5 b8 0b 00 00 db 1c ?? 00 6c 70 ff 6c 6c ff 2a 31 70 ff f5 00 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {6b 72 ff e7 80 10 00 4a c2 f5 01 00 00 00 aa 6c 10 00 4d 5c ff 08 40 04 ?? ?? 0a ?? 00 10 00}  //weight: 1, accuracy: Low
        $x_1_4 = {80 0c 00 2e ?? ff 40 5e ?? 00 04 00 71 ?? ff 2d ?? ff f5 00 00 00 00 f5 00 00 00 00 6c ?? ff 6c ?? ff 6c ?? ff 0a ?? 00 14 00 (3c 14|14)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_ME_2147687053_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!ME"
        threat_id = "2147687053"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 0f 6e c0 55 6a ?? ff 35}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 0f 6e cb 89 6a ?? ff 35}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 00 e5 0f 6e d1 6a ?? ff 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_MJ_2147688123_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!MJ"
        threat_id = "2147688123"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0e 6c 0c 00 43 74 ff 6c 10 00 43 70 ff 00 05 4b ff ff 00 0f 6c 70 ff 4a f5 00 00 00 00 c7 1c 25 00 00 03 14 00 02 00 0f 6c 74 ff 4a f5}  //weight: 1, accuracy: High
        $x_1_2 = {ec fe 35 2c ff 00 1f 6c 4c ff 6c 50 ff 04 58 ff 9d e7 aa 04 ec fe fc 22 6c 44 ff fc 90 e7 aa fb}  //weight: 1, accuracy: High
        $x_1_3 = {4c ff 04 58 ff 9d fc 0d fc f0 3e ff 00 10 6c 48 ff 04 58 ff 9d 6c 4c ff 04 58 ff a2 00 0f fc e0}  //weight: 1, accuracy: High
        $x_1_4 = {ae 04 70 ff fe 8e 01 00 11 00 01 00 80 00 f5 00 00 00 00 04 74 ff 6c 6c ff f4 01 fc cb fe 64 64}  //weight: 1, accuracy: High
        $x_1_5 = {0b 28 ec fe 05 00 fc f6 0c ff 00 1b 28 cc fe 00 00 04 3c ff 80 10 00 f4 01 fc cb fd 69 dc fe fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADI_2147688562_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADI"
        threat_id = "2147688562"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d be 00 f0 ff ff bb 00 10 00 00 50 54 6a 04 53 57 ff d5 8d 87 df 01 00 00 80 20 7f 80 60 28 7f 58 50 54 50 53 57 ff d5 58 61 8d 44 24 80 6a 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 8b 00 ff 75 08 ff 50 08 8b 45 fc 8b 4d ec 64 89 0d 00 00 00 00 5f 5e 5b c9 c2 04 00}  //weight: 1, accuracy: High
        $x_2_3 = {ff 15 00 43 6f 6d 63 74 6c 4c 69 62 2e 50 72 6f 67 72 65 73 73 42 61 72 00 03 ?? ?? ?? ?? ?? ?? ?? ?? 0f 00 00 2d 4c 42 09 00 4c 00 00 00 21 43 34 12 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADJ_2147688843_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADJ"
        threat_id = "2147688843"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fc fd fe ff}  //weight: 1, accuracy: High
        $x_1_2 = {2d 04 04 04 04}  //weight: 1, accuracy: High
        $x_1_3 = "norton" ascii //weight: 1
        $x_1_4 = {0f b7 47 14}  //weight: 1, accuracy: High
        $x_1_5 = {bb 00 00 40 00}  //weight: 1, accuracy: High
        $x_1_6 = {66 3b 77 06}  //weight: 1, accuracy: High
        $x_1_7 = {0b c0 74 02 ff e0 68 ?? ?? 40 00 b8 ?? ?? 40 00 ff d0 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_MO_2147691911_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!MO"
        threat_id = "2147691911"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 6a 30 5e 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {64 ad 8b 40 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_3 = {56 51 31 c0 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_4 = {64 8b 70 30 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_5 = {80 39 6e 74 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_6 = {eb ec 59 5e 03 00 c7}  //weight: 1, accuracy: Low
        $n_100_7 = "Netlux Systems Private Limited" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (4 of ($x*))
}

rule VirTool_Win32_VBInject_MP_2147691922_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!MP"
        threat_id = "2147691922"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f b6 0c 08 8b 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 66 33 0c 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {0b c0 74 02 ff e0 68 ?? ?? 40 00 b8 ?? ?? 40 00 ff d0 ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 [0-96] 0b c0 74 02 ff e0}  //weight: 1, accuracy: Low
        $x_1_4 = "Biteropest" ascii //weight: 1
        $x_1_5 = "Meterolob" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_MS_2147695416_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!MS"
        threat_id = "2147695416"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 11 8b 4d d8 8b 42 0c 8b 95 58 ff ff ff 8a 0c 11 8b 95 2c ff ff ff 32 0c 10 8b 95 28 ff ff ff 88 0c 10 8b 4d a8 b8 01 00 00 00 03 c1}  //weight: 1, accuracy: High
        $x_1_2 = "Vix POLEMD KI\\Benixvix.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_2147695482_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.gen!MT"
        threat_id = "2147695482"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "MT: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e0 72 ff fb 11 e7 6c 6c ff f5 26 00 00 00 0b 00 00 04 00 23 58 ff f5 48 00 00 00 0b 00 00 04 00 23 54 ff 2a 23 50 ff f5 46 00 00 00 0b 00 00 04 00 23 4c ff 2a 23 48 ff}  //weight: 1, accuracy: High
        $x_1_2 = "Neriopert\\Kolidert.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADU_2147696224_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADU"
        threat_id = "2147696224"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "54P1DP00P83PC3P04P81P7CP1DPFCP42P42P42P42P75PC1P66P0FPEFP" wide //weight: 1
        $x_1_2 = {3b fb 7f 57 68 ?? ?? ?? ?? 8b cf 8b 45 d4 2b 48 14 8b 40 0c ff 34 88 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADV_2147696577_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADV"
        threat_id = "2147696577"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "817C1DFC4242424275" wide //weight: 1
        $x_1_2 = "89541D0083C304817C1D" wide //weight: 1
        $x_2_3 = {74 7b 6a 00 ff 75 1c ff 75 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 50 ff 75 ?? 6a ff e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_ADX_2147696968_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADX"
        threat_id = "2147696968"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 3d 45 02 00 00 89 45 e0 0f 8c 95 14 00 00 6a 02 5f 33 f6}  //weight: 2, accuracy: High
        $x_1_2 = {8b 52 10 d1 f8 88 0c 02 8d 45 a8 50 8d 45 a8 50 8d 45 b8 50 8d 45 c8 50 6a 04 e8 ?? ?? fa ff 83 c4 14 6a 02 58 03 f0 8b 45 e0 e9 65 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADY_2147697682_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADY"
        threat_id = "2147697682"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 be 48 60 17 f5 ?? 00 00 00 04 ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 60 8b 3c 24 f5 ?? 00 00 00 04 ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_3 = {f5 b8 a4 03 00 f5 ?? 00 00 00 04 ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_4 = {f5 00 83 e8 04 f5 ?? 00 00 00 04 ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_5 = {f5 31 37 83 c7 f5 ?? 00 00 00 04 ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_6 = {f5 04 85 c0 75 f5 ?? 00 00 00 04 ?? ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADZ_2147697683_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADZ"
        threat_id = "2147697683"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fd 21 ff 21 ff 75 0c 00 66 0f ?? ?? 66 0f ?? ?? 66 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {81 78 fc 10 10 10 10 75 ?? 66 0f ?? ?? 66 0f ?? ?? 66 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEA_2147697717_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEA"
        threat_id = "2147697717"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {dd 1c 01 6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 c7 85 ?? ?? ff ff 70 17 00 00 c7 85 ?? ?? ff ff 01 00 00 00 83 25 ?? ?? ?? 00 00 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {00 1c 25 00 00 6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 6a 08 58 69 c0 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {50 6a 04 e8 ?? ?? ?? ff 83 c4 14 a1 ?? ?? ?? 00 8b 4d ?? dd 04 c1 e8 ?? ?? ?? ff 8b 1b 00 8d 85 ?? ff ff ff 50 8d 85 ?? ff ff ff 50 8d 85 ?? ff ff ff 50 8d 85 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEB_2147697741_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEB"
        threat_id = "2147697741"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 74 ff 6c 74 ff 1b 06 00 2a 31 74 ff 6c 74 ff 1b 07 00 2a 31 74 ff 6c 74 ff 1b 08 00 2a 31 74 ff 6c 74 ff 1b 09 00 2a 31 74 ff 6c 74 ff 1b 0a 00 2a 31 74 ff 6c 74 ff 1b 0b 00 2a 31 74 ff 6c 74 ff 1b 0c 00 2a 31 74 ff 6c 74 ff 1b 0d 00 2a 31 74 ff}  //weight: 1, accuracy: High
        $x_1_2 = "817C1DFC4343" wide //weight: 1
        $x_1_3 = "81F985C085C0" wide //weight: 1
        $x_1_4 = "4031C1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEB_2147697741_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEB"
        threat_id = "2147697741"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "4031C181F989D889D875CE" wide //weight: 1
        $x_1_2 = "434383C302817C1DFC4E4E" wide //weight: 1
        $x_1_3 = "8B541D00660FF" wide //weight: 1
        $x_1_4 = {ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 09 00 68 ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEB_2147697741_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEB"
        threat_id = "2147697741"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 09 00 68 ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 8b d0 8b 4d ?? e8 ?? ?? ?? ff 8b 45 ?? ff 30 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8b 4d 0c e8 ?? ?? ?? ff 8b 45 ?? ff 30 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8b 4d ?? e8 ?? ?? ?? ff 8b 45 ?? ff 30 68 ?? ?? ?? 00 09 00 68 ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "4031C1" wide //weight: 1
        $x_1_4 = "434383C302817C1D" wide //weight: 1
        $x_1_5 = "8B541D00" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_VBInject_AED_2147705773_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AED"
        threat_id = "2147705773"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 01 58 03 c8 0f 80 ?? ?? ?? ?? 89 4b ?? e9 ?? ?? ?? ff 03 00 8b 4b}  //weight: 2, accuracy: Low
        $x_1_2 = {00 be d0 07 00 00 b8 ?? ?? ?? ?? 39 43 ?? 0f 8f ?? ?? 00 00 06 00 c7 43 ?? 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEE_2147705804_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEE"
        threat_id = "2147705804"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 3c 0a 66 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-10] 8a 1c 0e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-10] 80 f3 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-10] 38 fb 75}  //weight: 2, accuracy: Low
        $x_1_2 = {81 fd 29 f6 29 f6 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEE_2147705804_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEE"
        threat_id = "2147705804"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 6a 02 ff 15 ?? ?? ?? 00 83 c4 0c c7 45 fc 08 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {00 eb 0f 8b 55 ?? 03 55 ?? 0f 80 ?? ?? ?? 00 89 55 ?? 8b 45 ?? 3b 45 ?? 7f 14 00 c7 45 ?? ?? ?? ?? ?? c7 45 ?? 01 00 00 00 c7 45 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEE_2147705804_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEE"
        threat_id = "2147705804"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff c5 f1 44 00 c7 85 ?? ?? ff ff 01 00 00 00 83 65 ?? 00 eb 0c 8b 45 ?? 03 85 ?? ?? ff ff 89 45 ?? 8b 45 ?? 3b 85 ?? ?? ff ff 0f 8f ?? ?? 00 00 d9 e8 51 51 dd 1c 24 e8 04 00 c7 85}  //weight: 1, accuracy: Low
        $x_2_2 = {dd 58 34 d9 e8 51 51 dd 1c 24 e8 ?? ?? ?? ?? 8b 45 08 dd 58 34 d9 e8 51 51 dd 1c 24 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEE_2147705804_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEE"
        threat_id = "2147705804"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0b 6a 79 6a 79 ff d7 50 56 ff 53 64 85 c0 db e2 7d 0f}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 00 fa 43 68 00 00 c8 43 68 00 00 48 43 68 00 00 c8 42 6a 04 56 ff ?? ?? ?? ?? 00 85 c0 db e2 7d 0e 68 c8 02 00 00 68 ?? ?? ?? 00 56 50 ff d7 8b ?? 6a 00 68 00 00 fa 43 68 00 00 c8 43 68 00 00 48 43 68 00 00 c8 42 6a 04 56 ff ?? ?? ?? ?? 00 85 c0 db e2 7d 0e 68 c8 02 00 00 68 ?? ?? ?? 00 56 50 ff d7 8b 0e 6a 00 68 00 00 fa 43 68 00 00 c8 43 68 00 00 48 43 68 00 00 c8 42}  //weight: 1, accuracy: Low
        $x_2_3 = {00 00 8b 50 14 2b ca 8b 50 0c c7 04 ca ?? ?? ?? ?? c7 44 ca 04 ?? ?? ?? ?? 8b 06 b9 ?? ?? 00 00 8b 50 14 2b ca 8b 50 0c c7 04 ca ?? ?? ?? ?? c7 44 ca 04 ?? ?? ?? ?? 8b 06 b9 ?? ?? 00 00 8b 50 14 2b ca 8b 50 0c c7 04 ca ?? ?? ?? ?? c7 44 ca 04 ?? ?? ?? ?? 8b 06 b9 ?? ?? 00 00 8b 50 14 2b ca 8b 50 0c c7 04 ca ?? ?? ?? ?? c7 44 ca 04 ?? ?? ?? ?? 8b 06 b9 ?? ?? 00 00 8b 50 14 2b ca 8b 50 0c c7 04 ca ?? ?? ?? ?? c7 44 ca 04 ?? ?? ?? ?? 8b 06 b9 ?? ?? 00 00 8b 50 14 2b ca 8b 50 0c c7 04 ca ?? ?? ?? ?? c7 44 ca 04 13 00 ba ?? ?? ?? 00 8d ?? ?? ff 15 ?? ?? ?? ?? 8b 06 b9}  //weight: 2, accuracy: Low
        $x_2_4 = {00 00 8b 50 14 2b ca 8b 50 0c c7 04 ca ?? ?? ?? ?? c7 44 ca 04 ?? ?? ?? ?? 8b 06 b9 ?? ?? 00 00 8b 50 14 2b ca 8b 50 0c c7 04 ca ?? ?? ?? ?? c7 44 ca 04 ?? ?? ?? ?? 8b ?? 3c 50 e8 ?? ?? ff ff 89 85 ?? ?? ff ff ff 15 ?? ?? ?? 00 05 00 8b 06 b9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AEE_2147705804_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEE"
        threat_id = "2147705804"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba b6 0f 3e fb 53 55 8b 48 ?? 56 be 3d 28 3b ed bd d8 04 52 61 c7 81 c8 08 00 00 b6 9a a8 78 8b 48}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 81 a8 0b 00 00 3a 51 19 29 8b 50 54 b9 af 50 5b aa 89 8a 54 08 00 00 8b 50 54}  //weight: 1, accuracy: High
        $x_1_3 = {ba 59 0b 40 0b 53 55 8b 48 54 bd c4 0a 40 51 bb 5a 7a 41 0b 56 c7 81 58 0c 00 00 80 0e a9 ff 8b 48 54}  //weight: 1, accuracy: High
        $x_1_4 = {83 a5 60 fe ff ff 00 c7 45 fc 51 00 00 00 c7 45 98 c4 09 00 00 c7 45 9c 01 00 00 00 83 65 d8 00 eb 0f 8b 45 d8 03 45 9c 0f 80 ?? 01 00 00 89 45 d8 8b 45 d8 3b 45 98 7f 2b c7 45 fc 52 00 00 00 e8 ?? ?? ff ff e8 ?? ?? fc ff c7 45 fc 53 00 00 00 e8 ?? ?? ff ff e8 ?? ?? fc ff c7 45 fc 54 00 00 00 eb be}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 46 44 bf e2 fe 68 a7 c7 80 ec 02 00 00 e3 77 2d 78 8b 46 44 c7 80 a4 03 00 00 6a ab 64 0f}  //weight: 1, accuracy: High
        $x_1_6 = {b9 6d 00 00 00 c7 04 d0 73 37 7f 35 c7 44 d0 04 2b df c0 fd 8b 06 8b 50 14 2b ca 8b 50 0c c7 04 ca 5f d5 c2 29 c7 44 ca 04 23 56 55 22}  //weight: 1, accuracy: High
        $x_1_7 = {31 32 0f db ?? 66 0f 63 ?? 0f df ?? 66 0f fd ?? 83 c2 04 66 0f e9 ?? 0f 64 ?? 0f f5 ?? 0f fd ?? 66 0f e1 ?? 39 5a fc 75 d7}  //weight: 1, accuracy: Low
        $x_1_8 = {ac 30 0e 00 c7 45 ?? 01 00 00 00 83 65 dc 00 eb 0f 8b 45 dc 03 45 ?? 0f 80 ?? 20 00 00 89 45 dc 8b 45 dc 3b 45 ?? 0f 8f bb 00 00 00 c7 45 fc 06 00 00 00 8d 45 ?? 50 8b 45 08 8b 00 ff 75 08 ff 90 d8 00 00 00 db e2 89 45 ?? 83 7d ?? 00 7d 1d 68 d8 00 00 00 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_9 = {bf 92 67 18 2f c7 ?? ?? ?? 00 00 61 44 44 b8 8b ?? ?? c7 ?? ?? ?? 00 00 3a 92 70 63 8b ?? ?? c7 ?? ?? ?? 00 00 e6 10 13 43 8b}  //weight: 1, accuracy: Low
        $x_1_10 = {00 00 03 93 4d 47 8b ?? ?? c7 ?? ?? ?? 00 00 ea 13 16 af 8b ?? ?? c7 ?? ?? ?? 00 00 92 67 18 2f 8b ?? ?? c7 ?? ?? ?? 00 00 ad 76 38 04 04 00 c7}  //weight: 1, accuracy: Low
        $x_1_11 = {ff ac 30 0e 00 c7 85 ?? ?? ff ff 01 00 00 00 83 65 dc 00 eb 12 8b 45 dc 03 85 ?? ?? ff ff 0f 80 ?? 20 00 00 89 45 dc 8b 45 dc 3b 85 ?? ?? ff ff 0f 8f bb 00 00 00 c7 45 fc 06 00 00 00 8d 45 ?? 50 8b 45 08 8b 00 ff 75 08 ff 90 d8 00 00 00 db e2 89 45 ?? 83 7d ?? 00 7d 1d 68 d8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_12 = {75 e1 83 c6 04 70 57 b8 96 cd 10 03 2b f0 70 4e 57 03 f0 57 70 48 56 e8 ?? ?? ff ff 89 45 cc e8 ?? ?? fc ff ff 75 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_VBInject_AEF_2147705843_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEF"
        threat_id = "2147705843"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 69 74 7a 67 65 72 61 6c 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 61 63 6b 33 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 72 67 6f 6b 33 00}  //weight: 1, accuracy: High
        $x_1_4 = {3a 5c 5a 67 72 61 67 67 65 6e 38 5c 41 62 73 6f 72 62 65 64 31 5c 4c 61 6b 6f 76 69 63 38 5c 55 6e 74 69 6d 65 6f 75 73 5c 4d 75 73 69 74 69 61 6e 73 5c 56 42 36 2e 4f 4c 42 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 75 6e 73 74 6f 6f 6c 73 35 00}  //weight: 1, accuracy: High
        $x_1_6 = {56 61 6c 6c 6f 7a 7a 69 33 00}  //weight: 1, accuracy: High
        $x_1_7 = {4e 6f 6e 62 6f 75 72 67 65 6f 69 73 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule VirTool_Win32_VBInject_AER_2147706111_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AER"
        threat_id = "2147706111"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 31 c1 81 f9 89 d8 89 d8 75}  //weight: 1, accuracy: High
        $x_1_2 = {40 31 c1 81 f9 89 d9 89 d9 75}  //weight: 1, accuracy: High
        $x_2_3 = {43 43 83 c3 02 81 7c 1d fc 4e 4e 4e 4e}  //weight: 2, accuracy: High
        $x_2_4 = {43 83 c3 03 81 7c 1d fc 4c 4c 4c 4c 75}  //weight: 2, accuracy: High
        $x_2_5 = {43 83 c3 03 81 7c 1d fc 91 91 91 91 75}  //weight: 2, accuracy: High
        $x_2_6 = {43 83 c3 03 81 7c 1d fc 92 92 92 92}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AES_2147706117_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AES"
        threat_id = "2147706117"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {40 31 c1 81 f9 85 c0 85 c0 75}  //weight: 4, accuracy: High
        $x_1_2 = {43 43 83 c3 02 81 7c 1d fc 43 43 43 43 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {43 43 83 c3 02 81 7c 1d fc 43 43 43 43 75}  //weight: 1, accuracy: High
        $x_1_4 = {31 c2 89 54 1d 00 83 c3 04 81 7c 1d fc 43 43 43 43 75}  //weight: 1, accuracy: High
        $x_1_5 = {31 c2 89 54 1d 00 83 c3 04 81 7c 1d fc 42 42 42 42 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AEQ_2147706145_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEQ"
        threat_id = "2147706145"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 0c bf 74 23 11 00 c7 46 34 04 00 00 00 39 7e 34 7f 35}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 54 c7 80 c0 03 00 00 16 9e 8d 57 8b 46 54 c7 80 50 0b 00 00 9d d6 77 34 8b 46 54 c7 80 6c 10 00 00 6a 51 1c 3e 8b 46 54 c7 80 04 0d 00 00 4b 2f 9c 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AET_2147706166_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AET"
        threat_id = "2147706166"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 a0 58 e7 0d 00 c7 45 a4 01 00 00 00 c7 45 d0 00 00 00 00 eb 0f 8b 45 d0 03 45 a4 0f 80 d6 0f 00 00 89 45 d0 8b 4d d0 3b 4d a0 0f 8f cc 0d 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 04 ca d3 dd d1 79 c7 44 ca 04 4a 25 d4 78 8b 50 14 b9 3f 02 00 00 2b ca 8b 50 0c c7 04 ca f7 43 66 0f c7 44 ca 04 fd c4 66 0f 8b 58 14 8b 50 0c b9 e5 01 00 00 2b cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEL_2147706370_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEL"
        threat_id = "2147706370"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e5 e8 8b 45 ?? 66 c7 40 ?? a4 03 04 00 66 c7 40}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 66 89 83 ?? ?? 00 00 8b 5d cc 66 89 83 ?? ?? 00 00 04 00 b8 90 90 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {00 00 31 37 8b 45 ?? 66 c7 80 ?? ?? 00 00 83 c7 8b 45 ?? 66 c7 80 ?? ?? 00 00 04 85 05 00 66 c7 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEU_2147706447_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEU"
        threat_id = "2147706447"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Kakaba\\Unwell\\Trimmings\\Ikale\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "Metamorphous0" ascii //weight: 1
        $x_1_3 = "Husbandless6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEU_2147706447_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEU"
        threat_id = "2147706447"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 45 fc 05 00 00 00 c7 85 5c ff ff ff 38 d5 03 00 c7 85 60 ff ff ff 01 00 00 00 c7 45 c4 00 00 00 00 eb 12 8b 45 c4 03 85 60 ff ff ff 0f 80 d2 03 00 00 89 45 c4 8b 4d c4 3b 8d 5c ff ff ff 0f 8f 20 01 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {c7 04 ca 8c 63 23 82 c7 44 ca 04 65 16 a4 ba 8b 58 14 8b 50 0c b9 ea 01 00 00 2b cb c7 04 ca 0d 2b 4b ee c7 44 ca 04 39 21 57 e7}  //weight: 1, accuracy: High
        $x_1_3 = {c7 04 d7 f6 c2 d4 3d c7 44 d7 04 fe a0 4c b9 8b 58 14 8b 78 0c ba 7e 01 00 00 2b d3 c7 04 d7 37 4b 5d 4f c7 44 d7 04 f6 3c 31 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AEV_2147706472_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEV"
        threat_id = "2147706472"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf 74 23 11 00 c7 43 34 04 00 00 00 39 7b 34 0f 8f 1f 01 00 00 51 51 d9 e8 dd 1c 24 e8 d2 a1 fe ff dd d8}  //weight: 1, accuracy: High
        $x_1_2 = {c7 81 98 09 00 00 2d 51 a4 3b 8b 48 54 c7 81 68 13 00 00 f1 b9 66 0f 8b 48 54 c7 81 dc 13 00 00 74 c7 0f d8 8b 48 54 c7 81 98 11 00 00 d6 ae a4 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEV_2147706472_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEV"
        threat_id = "2147706472"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "saklcsnakjcnsalkmkl324fs" wide //weight: 1
        $x_1_2 = {64 a1 30 00 8b ?? ?? c7 ?? ?? 00 00 8b 40 8b ?? ?? c7 ?? ?? 10 8b 70 3c 8b ?? ?? c7 ?? ?? 0f b7 48 38 8b ?? ?? c7 ?? ?? 8b 7c 24 04 8b ?? ?? c7 ?? ?? 51 fc f3 a4 8b ?? ?? c7 ?? ?? 59 8b 74 24 8b ?? ?? c7 ?? ?? 04 89 4e fc 8b ?? ?? c7 ?? ?? c3 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEW_2147706476_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEW"
        threat_id = "2147706476"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 84 80 b5 01 00 c7 45 88 01 00 00 00 8b 55 08 c7 42 58 00 00 00 00 eb 15 8b 45 08 8b 48 58 03 4d 88 0f 80 ?? ?? 00 00 8b 55 08 89 4a 58 8b 45 08 8b 48 58 3b 4d 84 0f 8f}  //weight: 10, accuracy: Low
        $x_1_2 = {c7 81 e8 0a 00 00 91 51 e5 d2 c7 81 ec 0a 00 00 3b 0e 50 d5 8b 56 4c c7 82 a8 13 00 00 ec d0 0f 6a c7 82 ac 13 00 00 e9 0f 73 f2 8b 46 4c}  //weight: 1, accuracy: High
        $x_1_3 = {c7 81 c8 02 00 00 76 d6 fd ea c7 81 cc 02 00 00 2c 3e b2 a8 8b 56 4c c7 82 48 06 00 00 2b 3e 3b b7 c7 82 4c 06 00 00 c4 7d 3f ed 8b 46 4c}  //weight: 1, accuracy: High
        $x_1_4 = {c7 81 90 08 00 00 c1 b2 b2 3e c7 81 94 08 00 00 56 27 a4 c1 8b 56 4c c7 82 20 0f 00 00 a9 9c d6 59 c7 82 24 0f 00 00 19 be d6 50}  //weight: 1, accuracy: High
        $x_1_5 = {c7 81 68 0e 00 00 83 29 7f d9 c7 81 6c 0e 00 00 90 34 74 df 8b 56 4c c7 82 80 0c 00 00 c0 46 71 bc c7 82 84 0c 00 00 aa 46 71 bf 8b 46 4c}  //weight: 1, accuracy: High
        $x_1_6 = {c7 81 08 0c 00 00 f1 43 40 51 c7 81 0c 0c 00 00 35 2e a5 13 8b 56 4c c7 82 80 10 00 00 02 5b 2f ad c7 82 84 10 00 00 0e 5b 1b d8 8b 46 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AEX_2147706661_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEX"
        threat_id = "2147706661"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 74 23 11 00 c7 46 34 04 00 00 00 8b 46 34 3b c3 89 85 44 fe ff ff 0f 8f 05 01 00 00 dd 05 e8 10 40 00 8b 0e d9 e1 df e0 a8 0d 0f 85 c5 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 54 c7 81 ?? ?? 00 00 07 a8 5d e3 8b 48 54 c7 81 ?? ?? 00 00 6f cf 2e 86 8b 48 54 c7 81 ?? ?? 00 00 da 66 0f 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEY_2147706663_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEY"
        threat_id = "2147706663"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 74 23 11 00 c7 43 34 04 00 00 00 8b 43 34 3b c7 89 85 54 fe ff ff 0f 8f 08 01 00 00 dd 05 ?? ?? 40 00 8b 0b d9 e1 df e0 a8 0d 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 54 c7 81 ?? ?? 00 00 f9 40 3a ba 8b 48 54 c7 81 ?? ?? 00 00 bd a8 e4 bd 8b 48 54 c7 81 ?? ?? 00 00 8d 25 59 ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AEZ_2147706664_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEZ"
        threat_id = "2147706664"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 74 23 11 00 c7 43 34 04 00 00 00 5f 39 73 34 0f 8f 22 01 00 00 dd 05 f0 10 40 00 51 51 dd 1c 24 e8 7c ab fe ff dd d8 51 51 d9 e8 dd 1c 24}  //weight: 1, accuracy: High
        $x_1_2 = {bf 70 07 31 c7 c7 81 ?? ?? 00 00 70 07 31 ca 8b 48 54 c7 81 ?? ?? 00 00 02 6e d8 ff 8b 48 54 c7 81 ?? ?? 00 00 20 75 d5 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFA_2147706823_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFA"
        threat_id = "2147706823"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 46 34 04 00 00 00 8b 46 34 b9 74 23 11 00 3b c1 89 85 48 fe ff ff 0f 8f 05 01 00 00 dd 05 e8 10 40 00 8b 0e d9 e1 df e0 a8 0d 0f 85 ab 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 54 c7 81 ?? ?? 00 00 66 0f 66 e8 8b 48 54 c7 81 ?? ?? 00 00 b2 40 40 24 8b 48 54 c7 81 ?? ?? 00 00 6d 47 40 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFB_2147706825_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFB"
        threat_id = "2147706825"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c be 74 23 11 00 c7 43 34 04 00 00 00 8b 43 34 3b c6 89 85 50 fe ff ff 0f 8f 05 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 54 c7 81 ?? ?? 00 00 ae 92 76 a8 8b 48 54 c7 81 ?? ?? 00 00 f0 c3 61 93 8b 48 54 c7 81 ?? ?? 00 00 93 16 1d 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFC_2147706826_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFC"
        threat_id = "2147706826"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 04 00 00 00 c7 45 90 f8 fc 0c 00 c7 45 94 01 00 00 00 83 65 d4 00 eb 0f 8b 45 d4 03 45 94 0f 80 15 3d 00 00 89 45 d4 8b 45 d4 3b 45 90 7f 69}  //weight: 1, accuracy: High
        $x_1_2 = {2b 78 14 c7 04 fb 5a 7e 7d 74 c7 44 fb 04 4e 81 83 1f 8b 58 0c bf ?? ?? ?? ?? 2b 78 14 c7 04 fb 2e 62 7d 6c c7 44 fb 04 2a 14 f4 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFD_2147706983_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFD"
        threat_id = "2147706983"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f8 fc 0c 00 c7 45 ?? 01 00 00 00 83 65 d4 00 eb 0f 8b 45 d4 03 45 ?? 0f 80 ?? 16 00 00 89 45 d4 8b 45 d4 3b 45 ?? 7f 69 03 00 c7 45}  //weight: 2, accuracy: Low
        $x_1_2 = {c7 04 ca 3d 84 f6 3e c7 44 ca 04 68 ae c0 02 8b 50 0c 59 2b 48 14 6a 04 c7 04 ca 3d ee e9 36 c7 44 ca 04 59 4f 39 c1}  //weight: 1, accuracy: High
        $x_1_3 = {c7 04 ca 54 fc ed fc c7 44 ca 04 66 03 7a 05 8b 50 0c b9 69 01 00 00 2b 48 14 c7 04 ca 38 03 7a 8c c7 44 ca 04 ee cb 23 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_AFI_2147707207_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFI"
        threat_id = "2147707207"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 c1 5b 0c 8b 5b 8b 95 ?? ?? ff ff 8d 8d ?? ?? ff ff c7 44 c2 04 0c 31 c0 66}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 10 66 2b 01 0f 80 ?? ?? ?? ?? 0f bf d0}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 6e 51 ff d7 8d ?? ?? 6a 78 52 ff d7 8d ?? ?? 6a 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_AEN_2147707653_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AEN"
        threat_id = "2147707653"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 00 68 8b 35 ?? ?? ?? 00 c6 86 ?? 01 00 00 88 8b 35 ?? ?? ?? 00 c6 86 ?? 01 00 00 fe 8b 35 ?? ?? ?? 00 c6 86 ?? 01 00 00 b3 8b 35 ?? ?? ?? 00 c6 86 ?? 01 00 00 16 8b 35 ?? ?? ?? 00 c6 86 ?? 01 00 00 51 8b 35 ?? ?? ?? 00 88 86 ?? 01 00 00 8b 35 ?? ?? ?? 00 c6 86 ?? 01 00 00 14 8b 35 ?? ?? ?? 00 c6 86 ?? 01 00 00 03 03 00 c6 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFL_2147707679_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFL"
        threat_id = "2147707679"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 08 8b ?? 44 6a 40 68 00 10 00 00 68 d0 17 00 00 ?? 6a ff e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 99 83 e2 03 03 c2 8b f0 c1 fe 02 81 fe 01 19 00 00 72 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFM_2147707713_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFM"
        threat_id = "2147707713"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb c2 41 00 00 c7 00 ?? ?? ?? ?? 53 6a 08 c7 40 04 ?? ?? ?? ?? ff 77 3c e8}  //weight: 1, accuracy: Low
        $x_1_2 = {89 47 38 8b 07 ff 90 ?? ?? 00 00 8b 07 57 ff 90 ?? ?? 00 00 85 c0 7d 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFN_2147707780_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFN"
        threat_id = "2147707780"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 41 40 75 05 e9 ?? ?? ?? ?? c7 45 fc 12 00 00 00 e8 ?? ?? ?? ?? c7 45 fc 13 00 00 00 c7 85 ?? ff ff ff ?? ?? ?? ?? 6a 04 8b 45 08 ff 70 50 8d 85 ?? ff ff ff 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 89 41 50 c7 45 fc 0b 00 00 00 8b 45 08 c7 40 40 04 00 00 00 c7 45 fc 0c 00 00 00 8b 45 08 c7 40 34 39 05 00 00 c7 45 fc 0e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFO_2147707892_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFO"
        threat_id = "2147707892"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 81 fb 45 02 00 00 0f 8c ?? ?? 00 00 6a 02 5e 3b fb 7f}  //weight: 1, accuracy: Low
        $x_1_2 = {66 8b c8 8b c7 99 2b c2 8b 15 ?? ?? ?? ?? 8b 52 10 d1 f8 88 0c 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFQ_2147708021_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFQ"
        threat_id = "2147708021"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 a4 58 e7 0d 00 c7 45 a8 01 00 00 00 c7 45 d4 00 00 00 00 eb 0f 8b 45 d4 03 45 a8 0f 80 96 01 00 00 89 45 d4 8b 4d d4 3b 4d a4 7f 57}  //weight: 1, accuracy: High
        $x_1_2 = {89 0c d6 c7 44 d6 04 5d f2 f3 18 8b 78 14 8b 70 0c ba 25 00 00 00 2b d7 c7 04 d6 66 0f 71 d2 c7 44 d6 04 fc 0f e2 c1 8b 70 14 ba 2f 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFS_2147708163_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFS"
        threat_id = "2147708163"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f d8 d1 66 0f 65 ed 0f fd d3 31 c1 81 f9 89 d9 89 d9 0f 85 78 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {41 0f d5 ff 66 0f fd f3 0f e2 f1 0f 62 da 0f db eb 66 0f 69 ef 66 0f ec ed 83 c1 03}  //weight: 1, accuracy: High
        $x_1_3 = {0f dc ec 66 0f 66 f3 0f f5 ce 0f 6a e8 81 7c 0d fc 95 95 95 95 0f 85 5c ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFT_2147708228_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFT"
        threat_id = "2147708228"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 73 8d 55 ?? 52 ff 15 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 6a 6e 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 6a 78 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 6a 68 8d 95 ?? ?? ff ff 52 ff 15 ?? ?? ?? ?? 6a 6b}  //weight: 1, accuracy: Low
        $x_1_2 = "FlawlessTicTacToe.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFU_2147708353_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFU"
        threat_id = "2147708353"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 07 58 3b f8 0f 8f ?? 00 00 00 c7 45 ?? 01 00 00 00 b8 ?? ?? 00 00 39 45 01 0f 8f}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 6a 01 58 03 f8 e9 ?? ff ff ff ff 35 ?? ?? ?? 00 e8 1c 00 50 8d 45 ?? 50 6a ?? e8 ?? ?? ?? ff 83 c4 ?? ff 45 ?? 6a ?? 58 01 45 ?? e9}  //weight: 1, accuracy: Low
        $x_1_3 = {88 04 11 8d 0e 00 e8 ?? ?? ?? ff 8b 0d ?? ?? ?? 00 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFV_2147708843_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFV"
        threat_id = "2147708843"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 80 2f 01 00 00 8b ?? eb d1 ?? c2 41 00 00 ?? 6a 08 ff ?? 70 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 b8 0b 00 00 3b ?? 7f 26 8b ?? c1 e0 04 03 ?? 44 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFW_2147708848_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFW"
        threat_id = "2147708848"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db 90 43 e0 fc ff d3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 84 24 20 01 00 00 [0-15] 5d [0-15] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFY_2147709403_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFY!bit"
        threat_id = "2147709403"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 01 8d 45 ?? 89 45 ?? c7 45 ?? 11 20 00 00 8d 45 ?? 50 e8 18 00 8b 45 ?? 03 85 ?? ff ff ff 0f b6 00 2b 45 ?? 8b 4d ?? 03 8d ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AFZ_2147709686_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AFZ!bit"
        threat_id = "2147709686"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 35 00 35 00 38 00 39 00 45 00 35 00 45 00 38 00}  //weight: 1, accuracy: High
        $x_1_2 = {38 00 42 00 33 00 43 00 32 00 34 00 42 00 38 00 41 00 34 00 30 00 33 00 30 00 30 00 30 00 30 00 38 00 33 00 45 00 38 00 30 00 34 00 33 00 31 00 33 00 37 00 38 00 33 00 43 00 37 00 30 00 34 00 38 00 35 00 43 00 30 00 37 00 35 00 46 00 34 00 43 00 33 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGA_2147710754_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGA!bit"
        threat_id = "2147710754"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a6 f3 55 89 eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3}  //weight: 1, accuracy: Low
        $x_1_2 = {a6 f3 89 e5 eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3}  //weight: 1, accuracy: Low
        $x_1_3 = {a6 f3 54 0d eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3}  //weight: 1, accuracy: Low
        $x_1_4 = {a6 f3 89 54 eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3}  //weight: 1, accuracy: Low
        $x_1_5 = {a6 f3 31 c1 eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3}  //weight: 1, accuracy: Low
        $x_1_6 = {a6 f3 c1 39 eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3}  //weight: 1, accuracy: Low
        $x_1_7 = {a6 f3 39 d9 eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3}  //weight: 1, accuracy: Low
        $x_1_8 = {a6 f3 d9 0f eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3 ?? ?? eb f5 ?? ?? 00 00 6c 74 ff a6 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_VBInject_AGG_2147712626_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGG!bit"
        threat_id = "2147712626"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {58 ff 30 46 5b 31 f3 3b 9c ?? ?? ?? 00 00 75 f1}  //weight: 2, accuracy: Low
        $x_1_2 = {0b 0c 1e 60 [0-32] 61 31 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGH_2147712628_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGH!bit"
        threat_id = "2147712628"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 01 55 89 e5 e8 8b 4d ?? c7 41 04 ?? ?? 00 00 8b 4d ?? c7 81 ?? ?? 00 00 ?? ?? ?? ?? 8b 4d ?? c7 81 ?? ?? 00 00 ?? ?? ?? ?? 8b 4d ?? c7 81 ?? ?? 00 00 ?? ?? ?? ?? 8b 4d ?? c7 81 ?? ?? 00 00 ?? ?? ?? ?? 8b 4d ?? c7 81 ?? ?? 00 00 ?? ?? ?? ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_2_2 = {31 37 83 c7 8b 45 ?? c7 80 ?? ?? 00 00 04 85 c0 75 8b 4d ?? c7 41 ?? ?? ?? ?? ?? 8b 45 ?? c7 40 ?? ?? ?? ?? ?? 8b 4d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGF_2147714337_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGF!bit"
        threat_id = "2147714337"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 02 55 89 e5 e8 8b 45 ?? c7 80 ?? ?? 00 00 ?? ?? ?? ?? 8b 4d ?? c7 81 ?? ?? 00 00 ?? ?? ?? ?? 8b 55 ?? c7 82 ?? ?? 00 00 ?? ?? ?? ?? 8b 45 ?? c7 80 ?? ?? 00 00 ?? ?? ?? ?? 8b 4d ?? c7 81 ?? ?? 00 00 ?? ?? ?? ?? 8b 55 ?? c7 82 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 3c 24 8b 4d ?? c7 81 ?? ?? 00 00 31 37 83 c7 8b 55 ?? 89 82 ?? ?? 00 00 8b 4d ?? c7 81 ?? ?? 00 00 ?? ?? ?? ?? 8b 55 ?? c7 82 ?? ?? 00 00 ?? ?? ?? ?? 8b 4d ?? c7 81 ?? ?? 00 00 ?? ?? ?? ?? 8b 55 ?? c7 82 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGI_2147716650_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGI!bit"
        threat_id = "2147716650"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 6e d1 0f 6f c2 0f ef c1 0f fe ca 0f 7e c0 d9 d0 3d ?? ?? ?? ?? 75 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGJ_2147716903_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGJ!bit"
        threat_id = "2147716903"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "36 41 33 30 35 45 36 34 41 44 38 42 34 30 31 30 38 42 37 30 33 43 30 46 42 37 34 38 33 38 38 42 37 43 32 34 30 34 38 39 34 46" wide //weight: 2
        $x_1_2 = "35 35 38 39 45 35 45 38 " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGM_2147717063_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGM!bit"
        threat_id = "2147717063"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 30 46 5b 31 f3 3b 9c 24 ?? ?? ?? ?? 75 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGS_2147718015_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGS!bit"
        threat_id = "2147718015"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 6e 5c 24 04 [0-32] 0f ef d9 [0-32] 0f 7e db [0-32] 81 fb ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 5c 24 08 [0-32] 39 18 75 [0-32] 8b 5c 24 0c [0-32] 39 58 04 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGU_2147718312_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGU"
        threat_id = "2147718312"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {dd 05 f0 10 40 00 d9 e0 dd 1d 3c 10 43 00 df e0 a8 0d 0f 85 50 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 d4 03 00 00 00 8d 45 d4 50 dd 05 07 00 c7 45 dc}  //weight: 1, accuracy: Low
        $x_1_3 = {99 6a 09 59 f7 f9 0f 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
        $x_3_4 = {3d 29 f6 29 f6 75}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGU_2147718409_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGU!bit"
        threat_id = "2147718409"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 6e 5c 24 0c [0-32] 0f ef d9 [0-32] 0f 7e d9 [0-32] 81 f9 00 00 04 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGU_2147718409_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGU!bit"
        threat_id = "2147718409"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 55 00 42 00 [0-32] 40 [0-32] 39 41 04 [0-32] b8 4b 00 53 00 [0-32] 40 [0-32] 40 [0-32] 39 01 [0-32] 59 [0-32] 8b 73 10 [0-32] 89 f7 [0-32] 8b 5e 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGV_2147718889_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGV!bit"
        threat_id = "2147718889"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 6e 5c 24 1c [0-32] 0f ef d9 [0-32] 0f 7e d8 [0-32] 83 f8 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGV_2147718889_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGV!bit"
        threat_id = "2147718889"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 4b 00 53 00 [0-16] 39 33 [0-16] 81 7b 04 56 00 42 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 55 8b ec 83 [0-16] 5b [0-16] 03 04 24 [0-16] 39 18 [0-16] 81 78 04 ec 0c 56 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGW_2147719042_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGW"
        threat_id = "2147719042"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Rkey7RC4modByUr1" wide //weight: 1
        $x_1_2 = {f4 01 f4 ff fe 5d 20 00 6c 74 ff 5e ?? 00 04 00 71 4c ff 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGX_2147719124_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGX!bit"
        threat_id = "2147719124"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 16 dc 2d 00 [0-32] 58 [0-32] 05 40 24 14 00 [0-32] 39 41 04 [0-32] 68 8d a3 3d 00 [0-32] 58 [0-32] 05 c0 5c 15 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGX_2147719124_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGX!bit"
        threat_id = "2147719124"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 58 28 81 3b 4d 00 53 00 75 f3 81 7b 04 56 00 42 00 75 ea 8b 70 10 56 8b 5e 3c 8b 34 24 01 de 8b 5e 78 8b 04 24 01 d8 89 c6 83 c6 28 ad 85 c0 74 fb 03 04 24 81 38 55 8b ec 83 75 f0 81 78 04 ec 0c 56 8d 75 e7}  //weight: 1, accuracy: High
        $x_1_2 = {ff 34 0e 81 34 24 ?? ?? ?? ?? 83 e9 04 7d f1 ff e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGY_2147719290_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGY!bit"
        threat_id = "2147719290"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 08 [0-32] 85 06 74 [0-32] 8b 44 24 0c [0-32] 39 46 04 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGY_2147719290_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGY!bit"
        threat_id = "2147719290"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 8e c8 2d 00 [0-32] 05 c8 37 14 00 [0-32] 39 41 04 [0-32] b8 1d ec 2d 00 [0-32] 05 30 14 25 00 [0-32] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHB_2147719375_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHB!bit"
        threat_id = "2147719375"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 96 39 14 00 [0-32] 58 [0-32] 05 c0 c6 2d 00 [0-32] 39 41 04 [0-32] 68 cd 7b 34 00 [0-32] 58 [0-32] 05 80 84 1e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHB_2147719375_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHB!bit"
        threat_id = "2147719375"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 68 00 43 00 44 00 4d 00 51 00 52 00 76 00 4b 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 6f 00 66 00 56 00 6a 00 75 00 64 00 63 00 50 00 42 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 51 00 75 00 4d 00 5a 00 4d 00 45 00 51 00 54 00 71 00 61 00 6c 00 71 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 71 00 77 00 6b 00 38 00 78 00 69 00 78 00 39 00 4f 00 69 00 47 00 72 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_AGZ_2147719400_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGZ!bit"
        threat_id = "2147719400"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 96 39 14 00 [0-16] 05 c0 c6 2d 00 [0-16] 39 41 04 75 [0-16] 68 cd 7b 34 00 [0-16] 58 [0-16] 05 80 84 1e 00 [0-16] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGZ_2147719400_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGZ!bit"
        threat_id = "2147719400"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 [0-16] 8b 40 0c [0-16] 8b 40 14 [0-16] 8b 40 14 [0-16] 48 66 81 38 ff 25 75 ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {40 81 38 8b 7c 24 0c 75 f7 81 78 04 85 ff 7c 08 75 ee}  //weight: 1, accuracy: High
        $x_1_3 = {5f 81 34 1f [0-21] 66 39 d3 [0-16] 75 [0-16] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_AHC_2147719743_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHC!bit"
        threat_id = "2147719743"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 70 ca 10 00 [0-32] 05 e6 35 31 00 [0-32] 39 41 04 [0-32] 68 cd 7b 34 00 [0-32] 58 [0-32] 05 80 84 1e 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHC_2147719743_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHC!bit"
        threat_id = "2147719743"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 75 e0 [0-32] 41 [0-32] 0f 6e d9 [0-32] 0f fe e3 [0-32] 8b 40 2c [0-32] 0f 6e e8 [0-32] 0f ef ec [0-32] 0f 7e eb [0-32] 83 fb 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fb 00 75 [0-64] ff 34 1c [0-32] 58 [0-32] e8 ?? ?? ?? 00 [0-32] 89 04 1c [0-32] 83 fb 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_VBInject_VJ_2147720062_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.VJ!bit"
        threat_id = "2147720062"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6A305E64AD8B40108B703C0FB748388B7C2404894FFCF3A4C3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_VK_2147720214_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.VK!bit"
        threat_id = "2147720214"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 08 00 00 00 00 [0-32] 11 14 08 [0-64] 3b 8d 9a 00 00 00 75 [0-32] ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {81 38 55 8b ec 83 75 ?? [0-32] 81 78 04 ec 0c 56 8d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_VL_2147720236_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.VL!bit"
        threat_id = "2147720236"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 78 04 ec 0c 56 8d 0f 85 ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
        $x_2_2 = {83 f8 00 74 [0-32] 81 38 ?? ?? ?? ?? 75 ?? e9 ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_1_3 = {3b 7d 3c 0f 85 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 20 00 00 8f 45 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_VO_2147720332_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.VO!bit"
        threat_id = "2147720332"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f9 00 75 [0-64] 0f fe f8 [0-32] 8b 40 2c [0-32] 0f ef d7 [0-32] 0f 7e d1 [0-32] 83 f9 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OP_2147720484_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OP!bit"
        threat_id = "2147720484"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 75 [0-32] 0f 6e d1 [0-32] 0f fe ca [0-32] 8b 40 2c [0-32] 0f 6e f0 [0-32] 0f ef f1 [0-32] 0f 7e f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OQ_2147720960_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OQ!bit"
        threat_id = "2147720960"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 75 [0-32] 0f 6e [0-32] 0f fe [0-32] 8b 40 2c [0-32] 0f 6e [0-32] 0f ef}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fb 00 75 [0-32] 0f 7e [0-64] ff 34 1c [0-32] 58 [0-32] e8 ?? ?? ?? 00 [0-32] 89 04 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHI_2147732926_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHI"
        threat_id = "2147732926"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 65 b0 00 8d 45 b0 50 6a 08 8d 45 e4 50 ff 75 0c 6a ff e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 10 00 00 00 8b c4 50 8d 44 24 0c 50 b9 ad 14 4a 73 ff d1 59 0b c0 78 0c 8b 44 24 04 8b 00 ff a0 40 00 00 00 5a 03 e1 52 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHI_2147732926_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHI"
        threat_id = "2147732926"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 6e 00 49 00 4a 00 69 00 20 00 00 00 44 00 1c 00 01 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 70 00 49 00 52 00 69 00 66 00 4f 00 72 00 6d 00 20 00 6c 00 54 00 64 00 20 00 00 00 38 00 14 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 48 00 50 00 2c 00 20 00 49 00 4e 00 63 00 2e 00 20 00 00 00 4c 00 22 00 01 00 4c 00 65 00 67 00 61 00 6c 00 54 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 73 00 00 00 00 00 4c 00 69 00 54 00 43 00 4f 00 69 00 6e 00 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 20 00 00 00 00 00 3c 00 1a 00 01 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 79 00 41 00 48 00 4f 00 6f 00 2c 00 20 00 69 00 4e 00 63 00 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OS_2147732958_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OS!bit"
        threat_id = "2147732958"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 8b 0d 18 00 00 00 [0-64] 8b 49 30 [0-64] 02 51 02 [0-64] ff e2}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 43 2c eb [0-64] 0f 6e e0 [0-64] 0f ef e6 [0-64] 0f 7e e0 [0-64] 83 f8 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OS_2147732958_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OS!bit"
        threat_id = "2147732958"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 35 30 00 00 00 [0-48] 58 [0-48] 8b 40 0c [0-48] 8b 40 14}  //weight: 1, accuracy: Low
        $x_2_2 = {81 3b 4d 00 53 00 75 [0-48] 81 7b 04 56 00 42 00 75 [0-48] 8b 70 10 [0-48] 8b 5e 3c [0-48] 01 de [0-48] [0-48] 8b 5e 78}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OT_2147732959_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OT!bit"
        threat_id = "2147732959"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 35 18 00 00 00 [0-48] 8b ?? 30 [0-48] 02 ?? 02 [0-48] ff}  //weight: 1, accuracy: Low
        $x_2_2 = {83 f9 00 0f 85 [0-64] 0f 6e [0-64] 8b ?? 2c [0-48] 0f 6e [0-48] 0f ef [0-48] 0f 7e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_OU_2147732961_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OU!bit"
        threat_id = "2147732961"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 75 [0-32] 0f 6e [0-32] 0f fe [0-32] 8b ?? 28 [0-32] 0f ef [0-32] 0f 7e}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 48 00 00 00 [0-32] 83 eb 04 [0-32] ff 34 1c [0-32] 58 [0-32] e8 [0-32] 89 04 1c [0-32] 85 db 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OV_2147732962_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OV!bit"
        threat_id = "2147732962"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 0f 85 ?? ?? ?? 00 [0-48] 8b 43 2c [0-48] 31 c8 [0-48] 83 f8 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 00 75 [0-48] 6a 48 [0-48] 58 [0-48] 8b 14 03 [0-48] 31 f2 [0-48] 52}  //weight: 1, accuracy: Low
        $x_1_3 = {64 ff 35 18 00 00 00 [0-48] 8b ?? 30 [0-48] 02 ?? 02 [0-48] ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_OW_2147732964_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OW!bit"
        threat_id = "2147732964"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 0f 85 [0-48] 41 [0-48] 8b 43 2c [0-48] 31 c8 [0-48] 83 f8 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OZ_2147732966_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OZ!bit"
        threat_id = "2147732966"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 [0-32] 8b 40 0c [0-32] 8b 40 14 [0-32] 8b 00 [0-32] 8b 58 28 [0-32] 81 3b 4d 00 53 00 75 [0-32] 81 7b 04 56 00 42 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OZ_2147732966_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OZ!bit"
        threat_id = "2147732966"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 35 30 00 00 00 [0-48] 58 [0-48] 8b 40 0c [0-48] 8b 40 14 [0-48] 8b 00 [0-48] 8b 58 28 [0-48] 81 7b 04 56 00 42 00}  //weight: 1, accuracy: Low
        $x_2_2 = {83 f8 00 75 [0-48] 89 e1 [0-48] 83 c1 30 [0-48] 89 ca [0-48] 83 c2 14 [0-48] e8 [0-48] 89 e2 [0-48] 6a 00 [0-48] 8b 1a [0-48] 81 eb 00 10 00 00 [0-48] 53 [0-48] 6a 00 [0-48] 6a 00 [0-48] ff 72 68 [0-48] ff 72 6c [0-48] ff 72 70 [0-48] ff 72 74}  //weight: 2, accuracy: Low
        $x_2_3 = {3b 54 24 10 75 [0-48] b9 [0-48] 83 e9 04 [0-48] ff 34 0f [0-48] 5a [0-48] e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_VBInject_OR_2147732967_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OR!bit"
        threat_id = "2147732967"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 0f 85 [0-48] 41 [0-48] 8b 53 2c [0-48] 31 ca [0-48] 83 fa 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OR_2147732967_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OR!bit"
        threat_id = "2147732967"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ad 83 f8 00 74 fa bb 57 8b ec 83 4b 4b 39 18 75 ef bb ee 0c 56 8d 4b 4b 39 58 04 75 e3}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 01 81 04 24 ?? ?? 00 00 ff d0 89 45 08 89 f9 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OR_2147732967_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OR!bit"
        threat_id = "2147732967"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 30 00 00 00 [0-32] 64 ff 30 [0-48] 58 [0-32] 8b 40 0c [0-32] 8b 40 14}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 83 eb 04 [0-32] 8b 14 1f [0-32] 31 f2 [0-48] 89 14 18 [0-32] 85 db 75 [0-32] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OR_2147732967_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OR!bit"
        threat_id = "2147732967"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ad 83 f8 00 74 ?? bb 57 8b ec 83 4b 4b 39 18 75 ?? bb ee 0c 56 8d 4b 4b 39 58 04}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 04 24 48 [0-16] c6 44 24 01 65 [0-16] c6 44 24 02 61 [0-16] c6 44 24 03 70 [0-16] c6 44 24 04 43 [0-16] c6 44 24 05 72 [0-16] c6 44 24 06 65 [0-16] c6 44 24 07 61 [0-16] c6 44 24 08 74 [0-16] c6 44 24 09 65}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 34 08 e9 ?? ?? ?? ?? 8f 04 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OX_2147732972_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OX!bit"
        threat_id = "2147732972"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 0f 85 [0-48] 41 [0-48] 8b 53 2c [0-48] 31 ca [0-48] 83 fa 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fa 00 75 [0-48] 89 ce [0-48] 6a 78 [0-48] 58 [0-48] 31 d2 [0-80] 33 14 03 [0-48] e8 ?? ?? ?? 00 [0-48] 83 f8 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_OY_2147732977_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.OY!bit"
        threat_id = "2147732977"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 c6 04 24 48 c6 44 24 ?? 65 c6 44 24 ?? 61 c6 44 24 ?? 70 c6 44 24 ?? 43 c6 44 24 ?? 72 c6 44 24 ?? 65 c6 44 24 ?? 61 c6 44 24 ?? 74 c6 44 24 ?? 65 89 e2 e8 ?? ?? ?? 00 6a 00 6a 00 68 00 00 05 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {ad 83 f8 00 74 fa bb 54 8b ec 83 43 39 18 75 f0 bb eb 0c 56 8d 43 39 58 04 75 e5 31 db 53 53 53 54 68 00 50 04 00 52 51 54 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {4b 45 52 4e 45 4c 33 32 00 8b 5c 24 04 31 1c 08 c2 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHD_2147732978_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHD!bit"
        threat_id = "2147732978"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 f6 e7 1e 00 [0-32] 05 60 18 23 00 [0-32] 39 41 04 [0-32] 68 cd 7b 34 00 [0-32] 58 [0-32] 05 80 84 1e 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHD_2147732978_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHD!bit"
        threat_id = "2147732978"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 18 00 00 00 [0-64] 64 8b 00 [0-64] 8b 40 30 [0-64] 5b [0-64] 02 58 02 [0-64] ff e3}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f9 00 75 [0-64] ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {81 eb 00 10 00 00 [0-64] 53 [0-64] 6a 00 [0-64] 6a 00 [0-64] ff 72 68 [0-64] ff 72 6c [0-64] ff 72 70 [0-64] ff 72 74 [0-64] 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_AHE_2147732979_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHE!bit"
        threat_id = "2147732979"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 56 f7 04 00 [0-32] 58 [0-32] 05 00 09 3d 00 [0-32] 39 41 04 [0-32] 68 cd 7b 34 00 [0-32] 58 [0-32] 05 80 84 1e 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHE_2147732979_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHE!bit"
        threat_id = "2147732979"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 0f 85 ?? ?? 00 00 [0-64] 41 [0-64] 8b 53 2c [0-64] 31 ca [0-64] 83 fa 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fa 00 75 [0-64] 89 ce [0-64] 6a 78 [0-64] 58 [0-64] 31 d2 [0-64] 48 [0-64] 48 [0-64] 48 [0-64] 48 [0-64] 33 14 03 [0-64] e8 ?? ?? ?? ff [0-64] 52 [0-64] 83 f8 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_PB_2147732982_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PB!bit"
        threat_id = "2147732982"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 0f 85 [0-64] 41 [0-64] ff 73 2c [0-64] 31 0c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fa 00 75 [0-64] 6a 78 [0-64] 58 [0-64] 31 d2 [0-64] 48 [0-64] 48 [0-64] 48 [0-64] 48 [0-64] 33 14 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_PC_2147732985_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PC!bit"
        threat_id = "2147732985"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {38 00 42 00 33 00 43 00 32 00 34 00 42 00 38 00 41 00 34 00 30 00 33 00 30 00 30 00 30 00 30 00 38 00 33 00 45 00 38 00 30 00 34 00 33 00 31 00 33 00 37 00 38 00 33 00 43 00 37 00 30 00 34 00 38 00 35 00 43 00 30 00 37 00 35 00 46 00 34 00 43 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "5589E5E8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_PD_2147732989_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PD!bit"
        threat_id = "2147732989"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 18 00 00 00 [0-48] 64 8b 1b [0-48] 8b 5b 30 [0-48] e9 ?? ?? 00 00 58 [0-48] 02 43 02 [0-48] ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {81 79 04 56 00 42 00 75 [0-48] 81 39 4d 00 53 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {83 fa 00 75 [0-64] 6a 78 [0-64] 58 [0-64] 31 d2 [0-64] 48 [0-64] 48 [0-64] 48 [0-64] 48 [0-64] 33 14 03}  //weight: 1, accuracy: Low
        $x_1_4 = {85 c9 0f 85 [0-64] 8b 53 2c [0-48] 31 ca [0-96] 6a 78 [0-48] 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_PE_2147732996_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PE!bit"
        threat_id = "2147732996"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 c6 04 24 5a c6 44 24 01 77 c6 44 24 02 53 c6 44 24 03 65 c6 44 24 04 74 c6 44 24 05 49 c6 44 24 06 6e c6 44 24 07 66 c6 44 24 08 6f c6 44 24 09 72 c6 44 24 0a 6d c6 44 24 0b 61 c6 44 24 0c 74 c6 44 24 0d 69 c6 44 24 0e 6f c6 44 24 0f 6e c6 44 24 10 50 c6 44 24 11 72 c6 44 24 12 6f c6 44 24 13 63 c6 44 24 14 65 c6 44 24 15 73 c6 44 24 16 73 89 e2 e8 ?? ?? ?? ?? 83 c4 18 6a 04 68 ?? ?? ?? ?? 6a 22 6a ff ff d0 ff e7 31 34 0f c3}  //weight: 1, accuracy: Low
        $x_1_2 = {ad 83 f8 00 74 fa 81 38 55 8b ec 83 75 f2 81 78 04 ec 0c 56 8d 75 e9 31 db 53 53 53 54 68 00 00 05 00 52 51 54 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_PF_2147732997_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PF!bit"
        threat_id = "2147732997"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 30 00 00 00 [0-48] 64 ff 30 [0-48] 58 [0-48] 8b 40 0c [0-48] eb}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c9 0f 85 [0-48] 41 [0-48] 8b 53 2c [0-48] 31 ca [0-48] 85 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_PG_2147733000_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PG!bit"
        threat_id = "2147733000"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bd 18 00 00 00 [0-32] 64 8b 6d 00 [0-32] 8b 6d 30 [0-32] e9}  //weight: 1, accuracy: Low
        $x_1_2 = {58 02 45 02 [0-32] ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c9 0f 85 [0-32] 41 [0-32] 8b 57 2c [0-32] 31 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_PH_2147733001_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PH!bit"
        threat_id = "2147733001"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bd 18 00 00 00 [0-32] 64 8b 6d 00 [0-32] 8b 6d 30 [0-32] e9}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c9 0f 85 [0-32] 41 [0-32] ff 77 2c [0-32] 31 0c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_PI_2147733002_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PI!bit"
        threat_id = "2147733002"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4assdhgqw" wide //weight: 1
        $x_1_2 = "qwetyasd" wide //weight: 1
        $x_1_3 = "khara" wide //weight: 1
        $x_1_4 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" wide //weight: 1
        $x_1_5 = "ccaqwesadaa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_PJ_2147733003_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PJ!bit"
        threat_id = "2147733003"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 55 89 e5 e8 a1 ?? ?? ?? 00 c7 40 04 a4 03 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {31 37 83 c7 8b 35 ?? ?? ?? 00 c7 86 ?? ?? 00 00 04 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = {f4 c3 00 00 a1 ?? ?? ?? 00 c7 80 ?? ?? 00 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_PK_2147733004_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.PK!bit"
        threat_id = "2147733004"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\0html.lnk" wide //weight: 1
        $x_1_2 = "\\po\\Cdmator.vbp" wide //weight: 1
        $x_1_3 = "5589E55565909042369090909090909090E8A" wide //weight: 1
        $x_1_4 = "D483685240DD9D6D044C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_VBInject_AHV_2147733012_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHV!bit"
        threat_id = "2147733012"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 01 0f 85 [0-48] 59 [0-48] 8b 73 10 [0-48] 89 f7 [0-48] 8b 5e 3c [0-48] 01 de [0-48] 8b 5e 78}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 40 00 00 00 [0-48] 53 [0-48] ba 00 30 00 00 [0-48] 52 [0-48] 68 00 [0-48] 6a 00 [0-48] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHW_2147733013_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHW!bit"
        threat_id = "2147733013"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 f4 66 c7 07 00 66 c7 ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {37 83 66 c7 07 00 66 c7 ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {04 31 66 c7 07 00 66 c7 ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {30 50 66 c7 07 00 66 c7 ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {24 b8 66 c7 07 00 66 c7 ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHX_2147733014_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHX!bit"
        threat_id = "2147733014"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ad 83 f8 00 74 fa bb 59 8b ec 83 4b 4b 4b 4b 39 18 75 ed bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 e0 31 db 53 53 53 54 6a 03 81 04 24 fd 4f 04 00 52 51 54 ff d0}  //weight: 2, accuracy: High
        $x_1_2 = {59 89 c7 51 f3 a4 59 6a 00 e8 ?? ?? ?? 00 7d f7 ff e0 06 00 5e 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAA_2147733065_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAA!bit"
        threat_id = "2147733065"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ce e3 04 00 [0-32] 05 88 1c 3d 00 [0-32] 39 41 04 [0-32] 68 31 d2 15 00 [0-32] 58 [0-32] 05 1c 2e 3d 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAB_2147733066_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAB!bit"
        threat_id = "2147733066"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 50 93 21 00 [0-32] 05 06 6d 20 00 [0-32] 39 01 [0-32] 75 95 [0-32] 83 e9 04 [0-32] 68 53 14 25 00 [0-32] 58 [0-144] 05 fa eb 2d 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAC_2147733067_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAC!bit"
        threat_id = "2147733067"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 7a 0a 14 00 [0-32] 05 dc f5 2d 00 [0-32] 39 01 [0-32] 0f 85 5a ff ff ff [0-32] 83 e9 04 [0-32] 68 3c 9f 24 00 [0-32] 58 [0-32] 05 11 61 2e 00 [0-32] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAD_2147733068_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAD!bit"
        threat_id = "2147733068"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 7a 0a 14 00 [0-32] 05 dc f5 2d 00 [0-32] 39 01 0f 85 69 ff ff ff [0-32] 83 e9 04 [0-32] 68 3c 9f 24 00 [0-32] 58 [0-32] 05 11 61 2e 00 [0-32] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAE_2147733069_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAE!bit"
        threat_id = "2147733069"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 52 c5 21 00 [0-32] 05 04 3b 20 00 [0-32] 39 01 0f 85 29 ff ff ff [0-32] 83 e9 04 [0-32] 68 37 53 43 00 [0-32] 58 [0-32] 05 16 ad 0f 00 [0-32] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAF_2147733070_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAF!bit"
        threat_id = "2147733070"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 7a 0a 14 00 [0-32] 05 dc f5 2d 00 [0-32] 39 01 0f 85 57 ff ff ff [0-32] 83 e9 04 [0-32] 68 3c 9f 24 00 [0-32] 58 [0-32] 05 11 61 2e 00 [0-32] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAG_2147733071_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAG!bit"
        threat_id = "2147733071"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 76 a1 21 00 [0-32] 05 e0 5e 20 00 [0-32] 39 01 0f 85 1d ff ff ff [0-32] 83 e9 04 [0-32] 68 73 0d 34 00 [0-32] 58 [0-32] 05 da f2 1e 00 [0-32] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAH_2147733072_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAH!bit"
        threat_id = "2147733072"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 36 5f 12 00 [0-32] 05 20 a1 2f 00 [0-32] 0f 85 1e ff ff ff 66 3d 3b dd [0-32] 83 e9 04 [0-32] 68 73 0d 34 00 [0-32] 58 [0-32] 05 da f2 1e 00 [0-32] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAI_2147733073_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAI!bit"
        threat_id = "2147733073"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 36 5f 12 00 [0-48] 05 20 a1 2f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 73 0d 34 00 [0-48] 58 [0-48] 05 da f2 1e 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAJ_2147733074_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAJ!bit"
        threat_id = "2147733074"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5e 82 12 00 [0-48] 05 f8 7d 2f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 93 79 2f 00 [0-48] 58 [0-48] 05 ba 86 23 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHB_2147733075_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHB"
        threat_id = "2147733075"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 83 3d 52 d1 31 14 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {0f 77 66 8b 1c 0e 90 66 31 1c 0f 90 49 49 50 58 85 c9 7d ec 51 59 31 c9 0f 77 0f 77 e8 ?? ?? ?? ?? 90 66 41 50 58 66 41 0f 77 66 41 0f 77 66 41 0f 77 90 3b 8d ?? ?? ?? ?? 75 e1 90 ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = "Silvereye" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHP_2147733077_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHP!bit"
        threat_id = "2147733077"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 30 00 00 00 [0-32] 64 ff 30 [0-32] 58 eb [0-32] 8b 40 0c [0-32] 8b 40 14 [0-32] 8b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHQ_2147733083_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHQ!bit"
        threat_id = "2147733083"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 4d 00 53 00 [0-32] 39 3b 75 [0-32] 81 7b 04 56 00 42 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 83 ec 8b 55 ?? ?? 39 18 75 [0-16] 81 78 04 ec 0c 56 8d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHS_2147733090_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHS!bit"
        threat_id = "2147733090"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 58 8b ec 83 4b 4b 4b 39 18 75 ee bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 e1 31 db 53 53 53 54 6a 03 81 04 24 ?? ?? ?? 00 52 51 54 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHT_2147733091_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHT!bit"
        threat_id = "2147733091"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 4c 00 53 00 46 39 33 75 ?? ?? ?? ?? ?? 81 7b 04 56 00 42 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 55 8b ec 83 39 18 75 ?? ?? ?? ?? 81 78 04 ec 0c 56 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHU_2147733092_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHU!bit"
        threat_id = "2147733092"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 59 00 42 00 [0-48] 48 [0-48] 48 [0-48] 39 41 04 75 [0-48] b8 50 00 53 00 [0-48] 48 [0-48] 48 [0-48] 48 [0-48] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHG_2147733095_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHG!bit"
        threat_id = "2147733095"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 30 9f 12 00 [0-32] 05 26 61 2f 00 [0-32] 39 41 04 [0-32] 68 c0 c6 2d 00 [0-32] 58 [0-32] 05 8d 39 25 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHF_2147733096_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHF!bit"
        threat_id = "2147733096"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 54 00 42 00 [0-48] 40 [0-48] 40 [0-48] 39 41 04 [0-48] b8 4a 00 53 00 [0-48] 40 [0-48] 40 [0-48] 40 [0-48] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHH_2147733098_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHH!bit"
        threat_id = "2147733098"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 53 00 42 00 [0-16] 40 [0-16] 40 [0-16] 40 [0-16] 39 41 04 75 [0-16] 68 49 00 53 00 [0-16] 58 [0-16] 40 [0-16] 40 [0-16] 40 [0-16] 40 [0-16] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGP_2147733100_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGP!bit"
        threat_id = "2147733100"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 56 f7 04 00 [0-16] 58 [0-16] 05 00 09 3d 00 [0-16] 39 41 04 75 [0-16] 68 4d f7 15 00 [0-16] 58 [0-16] 05 00 09 3d 00 [0-16] 39 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGQ_2147733101_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGQ!bit"
        threat_id = "2147733101"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 56 f7 04 00 [0-16] 58 [0-16] [0-16] 05 00 09 3d 00 [0-16] 39 41 04 75 [0-16] 68 8d 39 25 00 [0-16] 58 [0-16] 05 c0 c6 2d 00 [0-16] 39 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGR_2147733102_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGR!bit"
        threat_id = "2147733102"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 56 f7 04 00 [0-16] 58 [0-16] 05 00 09 3d 00 [0-16] 39 41 04 75 [0-16] 68 0d be 43 00 [0-16] 58 [0-16] 05 40 42 0f 00 [0-16] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGT_2147733105_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGT!bit"
        threat_id = "2147733105"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 d6 7b 23 00 [0-16] 58 [0-16] 05 80 84 1e 00 [0-16] 39 41 04 [0-16] 68 0d be 43 00 [0-16] 58 [0-16] 05 40 42 0f 00 [0-16] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AGW_2147733106_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AGW!bit"
        threat_id = "2147733106"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 f6 e7 1e 00 [0-16] 05 60 18 23 00 [0-16] 39 41 04 [0-16] 68 8d a3 3d 00 [0-16] 05 c0 5c 15 00 [0-16] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHA_2147733108_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHA!bit"
        threat_id = "2147733108"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 70 ca 10 00 [0-16] 05 e6 35 31 00 [0-16] 39 41 04 75 [0-16] 68 c0 c6 2d 00 [0-16] 58 [0-16] 05 8d 39 25 00 [0-16] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHI_2147733111_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHI!bit"
        threat_id = "2147733111"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 53 00 42 00 [0-48] 40 [0-48] 40 [0-48] 40 [0-48] 39 41 04 [0-48] b8 49 00 53 00 80 [0-48] 40 [0-48] 40 [0-48] 40 [0-48] 40 [0-48] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHJ_2147733115_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHJ!bit"
        threat_id = "2147733115"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 f0 5c 03 00 [0-32] 05 66 a3 3e 00 [0-32] 39 41 04 [0-32] 68 40 42 0f 00 [0-32] 58 [0-32] 05 0d be 43 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHK_2147733116_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHK!bit"
        threat_id = "2147733116"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 2e 92 0f 00 [0-32] 05 28 6e 32 00 [0-32] 39 41 04 75 [0-32] 68 cd 7b 34 00 [0-32] 58 [0-32] 05 80 84 1e 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHL_2147733117_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHL!bit"
        threat_id = "2147733117"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb fd fa 0f 10 [0-48] 81 c3 13 15 00 00 [0-48] 31 30 [0-48] 83 c0 04 [0-48] 39 58 fc 75 [0-48] 58 [0-48] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHL_2147733117_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHL!bit"
        threat_id = "2147733117"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 66 73 73 00 ff 0c 24 68 51 72 6f 63 ff 0c 24 68 75 69 6f 6e ff 0c 24 68 70 72 6d 61 ff 0c 24 68 75 49 6e 66 ff 0c 24 68 5b 77 53 65 ff 0c 24 89 e2 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHM_2147733119_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHM!bit"
        threat_id = "2147733119"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 b0 d7 13 00 [0-32] 05 a6 28 2e 00 [0-32] 39 01 75 [0-32] 83 e9 04 [0-32] 68 31 d2 15 00 [0-32] 58 [0-32] 05 1c 2e 3d 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHO_2147733120_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHO!bit"
        threat_id = "2147733120"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 b0 d7 13 00 [0-48] 05 a6 28 2e 00 [0-48] 39 01 [0-48] 75 [0-48] 83 e9 04 [0-48] 68 53 14 25 00 [0-48] 58 [0-48] 05 fa eb 2d 00 [0-48] 8b 09 [0-48] 39 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AIA_2147733123_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AIA!bit"
        threat_id = "2147733123"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 30 00 00 00 64 8b 00 8b 40 0c 8b 70 14 64 a1 30 00 00 00 8b 40 18 c7 00 00 00 00 00 03 30}  //weight: 1, accuracy: High
        $x_1_2 = {bb 52 8b ec 83 43 43 43 39 18 75 ec bb eb 0c 56 8d 43 39 58 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AIB_2147733124_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AIB!bit"
        threat_id = "2147733124"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 54 8b ec 83 5b 43 39 18 75 ef 81 78 04 ec 0c 56 8d 75}  //weight: 1, accuracy: High
        $x_1_2 = {31 d8 d1 c8 c1 c3 08 e2 f7 05 00 b9}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 0f f8 83 d1 04 81 f9 05 00 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AIC_2147733128_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AIC!bit"
        threat_id = "2147733128"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ca 5c 12 00 [0-48] 05 8c a3 2f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 1e 28 23 00 [0-48] 58 [0-48] 05 2f d8 2f 00 [0-48] 8b 09 [0-48] 39 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AID_2147733129_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AID!bit"
        threat_id = "2147733129"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 59 00 42 00 [0-48] 48 [0-48] 48 [0-48] 48 [0-48] 39 41 04 [0-48] 0f [0-48] b8 50 00 53 00 [0-48] 48 [0-48] 48 [0-48] 48 [0-48] 39 01 [0-48] 0f [0-48] 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AIE_2147733131_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AIE!bit"
        threat_id = "2147733131"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 7a 0a 14 00 [0-48] 05 dc f5 2d 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 3c 9f 24 00 [0-48] 58 [0-48] 05 11 61 2e 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AIF_2147733132_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AIF!bit"
        threat_id = "2147733132"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 52 c5 21 00 [0-48] 05 04 3b 20 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 37 53 43 00 [0-48] 58 [0-48] 05 16 ad 0f 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AIG_2147733133_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AIG!bit"
        threat_id = "2147733133"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 10 4c 23 00 [0-48] 05 46 b4 1e 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 77 c1 21 00 [0-48] 39 d9 [0-48] 58 [0-48] 05 d6 3e 31 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AIH_2147733135_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AIH!bit"
        threat_id = "2147733135"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 54 8b ec 83 [0-32] 43 [0-48] 39 18 75 [0-48] 81 78 04 ec 0c 56 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {31 1c 08 c3 05 00 bb}  //weight: 1, accuracy: Low
        $x_1_3 = {80 4c 24 04 65 80 4c 24 02 72 80 4c 24 07 32 80 4c 24 03 6e 80 4c 24 05 6c 80 4c 24 06 33 80 4c 24 01 65 80 0c 24 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AII_2147733136_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AII!bit"
        threat_id = "2147733136"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 42 9e 21 00 [0-48] 05 14 62 20 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 37 53 43 00 [0-48] 58 [0-48] 05 16 ad 0f 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AIJ_2147733137_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AIJ!bit"
        threat_id = "2147733137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 10 4c 23 00 [0-48] 05 46 b4 1e 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 77 c1 21 00 [0-48] 58 [0-48] 05 d6 3e 31 00 [0-48] 8b 09 [0-48] 39 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AIL_2147733138_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AIL!bit"
        threat_id = "2147733138"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 76 a1 21 00 [0-48] 05 e0 5e 20 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 73 0d 34 00 [0-48] 58 [0-48] 05 da f2 1e 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AIM_2147733139_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AIM!bit"
        threat_id = "2147733139"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 53 00 4d [0-32] 39 33 75 [0-32] 81 7b 04 56 00 42 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 56 8b ec 83 4b 39 18 75 [0-32] 81 78 04 ec 0c 56 8d 75 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_SD_2147733145_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.SD!MTB"
        threat_id = "2147733145"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 ff d9 d0 d9 d0 d9 d0 d9 d0 d9 d0 75 50 00 ff 34 38 [0-16] 5a [0-16] e8 ?? fe ff ff [0-16] 52}  //weight: 1, accuracy: Low
        $x_1_2 = {64 0b 05 30 00 00 00 [0-16] e9 25 00 31 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_SE_2147733146_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.SE!MTB"
        threat_id = "2147733146"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 ff d9 d0 90 90 d9 d0 d9 d0 75 40 00 8b 14 38 [0-16] e8 [0-32] 52 [0-16] 85 ff d9 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 [0-32] e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {83 fb 00 7f ?? [0-16] 83 c4 78 [0-16] ff e0 70 00 8b 14 1f [0-16] 56 [0-16] 33 14 24 [0-16] 5e [0-16] 89 14 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_SF_2147733147_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.SF!MTB"
        threat_id = "2147733147"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 07 bb 01 00 00 00 eb 02 33 db [0-10] 8b 45 fc 03 45 f4 [0-10] 85 db 75 ?? [0-10] 8a 16 [0-10] 80 f2 ?? 88 55 fb [0-10] 8a 55 fb 88 10 [0-10] 8d 45 f4 e8 ?? ?? ?? ?? [0-10] 46 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AHZ_2147733523_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AHZ!bit"
        threat_id = "2147733523"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 55 8b ec 83 5b be 00 10 40 00 [0-16] 83 f8 00 74 [0-16] 18 75 [0-16] 81 78 04 ec 0c 56 8d 75}  //weight: 1, accuracy: Low
        $x_1_2 = {51 b9 dd cc bb aa d9 d0 e2 fc 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACA_2147733526_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACA!bit"
        threat_id = "2147733526"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8b 58 28 bf 4b 00 53 00 47 66 47 39 3b 75 ef 81 7b 04 56 00 42 00 75}  //weight: 1, accuracy: High
        $x_1_2 = {bb 50 8b ec 83 [0-32] 83 c3 05 [0-32] 39 18 75}  //weight: 1, accuracy: Low
        $x_1_3 = {68 eb 0c 56 8d [0-32] 5b [0-32] 43 [0-32] 39 58 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACB_2147733534_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACB!bit"
        threat_id = "2147733534"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5e 82 12 00 [0-48] 05 f8 7d 2f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 53 37 20 00 [0-48] 58 [0-48] 05 fa c8 32 00 [0-48] 8b 09 [0-48] 39 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACD_2147733579_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACD!bit"
        threat_id = "2147733579"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 53 8b ec 83 [0-48] 83 c3 02 [0-48] 39 18 75 [0-48] bb ea 0c 56 8d [0-48] 83 c3 02 [0-48] 39 58 04 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAK_2147733599_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAK!bit"
        threat_id = "2147733599"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5e 82 12 00 [0-48] 05 f8 7d 2f 00 [0-48] 39 01 [0-48] 0f 85 4f fe ff ff [0-48] 83 e9 04 [0-48] 68 21 14 20 00 [0-48] 58 [0-48] 05 2c ec 32 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACE_2147733600_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACE!bit"
        threat_id = "2147733600"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 55 8b ec 83 5b 39 18 75 ?? 81 78 04 ec 0c 56 8d 75 ?? 31 db 53 53 53 54 ff 75 36 52 51 54 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 31 31 f0 4b 0f c8 e2 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACF_2147733601_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACF!bit"
        threat_id = "2147733601"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 04 00 00 00 b8 ?? ?? ?? ?? 31 04 0f f8 19 d1 7d ee 83 c4 0c ff e7}  //weight: 1, accuracy: Low
        $x_1_2 = {be 00 10 40 00 ad 83 f8 00 74 fa 81 38 55 8b ec 83 75 f2 bb eb 0c 56 8d 43 39 58 04 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAL_2147733641_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAL!bit"
        threat_id = "2147733641"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5e 82 12 00 [0-48] 05 f8 7d 2f 00 [0-48] 39 01 [0-48] 0f 85 4e fe ff ff [0-48] 83 e9 04 [0-48] 68 21 14 20 00 [0-48] 58 [0-48] 05 2c ec 32 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACG_2147733705_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACG!bit"
        threat_id = "2147733705"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 54 8b ec 83 5b 43 be 00 10 40 00 [0-32] ad [0-16] 83 f8 00 74 [0-16] 39 18 75 [0-16] 81 78 04 ec 0c 56 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {be 00 10 40 00 ad 83 f8 00 74 [0-16] 68 54 8b ec 83 5b 43 39 18 75 [0-16] 81 78 04 ec 0c 56 8d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_VBInject_ACH_2147733740_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACH!bit"
        threat_id = "2147733740"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5e 82 12 00 [0-48] 05 f8 7d 2f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 21 14 20 00 [0-48] 58 [0-48] 05 2c ec 32 00 [0-48] 8b 09 [0-48] 39 c1 [0-48] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACI_2147733742_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACI!bit"
        threat_id = "2147733742"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 00 00 53 00 [0-48] 83 c7 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {39 3b 0f 85 ?? ?? ff ff [0-48] 81 7b 04 56 00 42 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {81 78 04 ec 0c 56 8d 0f 85 ?? ?? ff ff 5b 31 db 53 53 53 54 6a 00 81 04 24 00 00 04 00 52 51 54 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 34 0e 5b 81 f3 ?? ?? ?? ?? 53 8f 04 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACJ_2147733743_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACJ!bit"
        threat_id = "2147733743"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 10 40 00 ad 83 f8 00 74 ?? bb 54 8b ec 83 43 39 18 75 f0 bb ea 0c 56 8d 43 43 39 58 04 75}  //weight: 1, accuracy: Low
        $x_1_2 = {31 1c 08 83 e9 fc c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACK_2147733768_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACK!bit"
        threat_id = "2147733768"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 53 8b ec 83 [0-48] 83 c3 02 [0-48] 39 18 0f 85 ?? ?? ff ff [0-48] bb ea 0c 56 8d [0-48] 83 c3 02 [0-48] 39 58 04 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACL_2147733771_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACL!bit"
        threat_id = "2147733771"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 58 8b ec 83 4b 4b 4b 39 18 75 ?? bb ef 0c 56 8d 4b 4b 4b 39 58 04 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACM_2147733790_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACM!bit"
        threat_id = "2147733790"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 54 8b ec 83 43 39 18 75 ?? bb 76 06 ab 46 81 c3 76 06 ab 46 39 58 04 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACN_2147733791_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACN!bit"
        threat_id = "2147733791"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 59 8b ec 83 [0-48] 4b [0-48] 4b [0-48] 4b [0-48] 4b [0-48] 39 18 75 [0-48] bb ef 0c 56 8d [0-48] 4b [0-48] 4b [0-48] 4b [0-48] 39 58 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACO_2147733794_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACO!bit"
        threat_id = "2147733794"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 10 40 00 31 c0 0b 06 83 c6 04 bb 52 8b ec 83 83 c3 03 39 18 75 ?? bb e9 0c 56 8d 83 c3 03 39 58 04 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACP_2147733816_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACP!bit"
        threat_id = "2147733816"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db 81 cb 54 8b ec 83 43 52 be 00 10 40 00 ad 83 f8 00 74 ?? 39 18 75 ?? ba ea 0c 56 8d 42 42 39 50 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAM_2147733824_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAM!bit"
        threat_id = "2147733824"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5e 82 12 00 [0-48] 05 f8 7d 2f 00 [0-48] 39 01 0f 85 86 [0-2] ff [0-48] 83 e9 04 [0-48] 68 c1 cf 2d 00 [0-48] 58 [0-48] 05 8c 30 25 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACQ_2147733834_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACQ!bit"
        threat_id = "2147733834"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 42 9e 21 00 [0-48] 05 14 62 20 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 f7 10 34 00 [0-48] 58 [0-48] 05 56 ef 1e 00 [0-48] 8b 09 [0-48] 39 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACR_2147733846_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACR!bit"
        threat_id = "2147733846"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 53 8b ec 83 43 43 39 18 75 ?? bb ea 0c 56 8d 43 43 39 58 04 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACS_2147733872_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACS!bit"
        threat_id = "2147733872"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5e 82 12 00 [0-48] 05 f8 7d 2f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 c1 cf 2d 00 [0-48] 58 [0-48] 05 8c 30 25 00 [0-48] 8b 09 [0-48] 39 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACT_2147733959_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACT!bit"
        threat_id = "2147733959"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ad 83 f8 00 74 fa bb 56 8b ec 83 4b 39 18 75 f0 81 78 04 ec 0c 56 8d 75 e7 31 db 53 53 53 54 68 ?? ?? ?? ?? 52 51 54 89 85 c0 00 00 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACU_2147734008_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACU!bit"
        threat_id = "2147734008"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 59 8b ec 83 66 83 eb 04 39 18 75 ?? bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 ?? 31 db 53 53 53 54 68 ?? ?? ?? ?? 52 51 54 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACV_2147734009_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACV!bit"
        threat_id = "2147734009"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 57 8b ec 83 4b 4b 39 18 75 ?? bb ee 0c 56 8d 4b 4b 39 58 04 75 ?? 31 db 53 53 53 54 6a 02 81 04 24 fe 4f 04 00 52 51 54 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACX_2147734134_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACX!bit"
        threat_id = "2147734134"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 3e d4 30 00 [0-48] 05 18 2c 11 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 57 7e 2f 00 [0-48] 58 [0-48] 05 f6 81 23 00 [0-48] 8b 09 [0-48] 39 c1 [0-48] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACY_2147734187_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACY!bit"
        threat_id = "2147734187"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 10 40 00 [0-32] ad [0-32] 83 f8 00 [0-32] 74 f5 [0-32] 81 38 55 8b ec 83 75 [0-32] 81 78 04 ec 0c 56 8d 75 [0-32] ff 75 3c [0-32] 89 85 c0 00 00 00 [0-32] ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ACZ_2147734235_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ACZ!bit"
        threat_id = "2147734235"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 10 40 00 [0-48] ad [0-48] 74 [0-48] bb 52 8b ec 83 [0-48] 83 c3 03 [0-48] 75 [0-48] bb ea 0c 56 8d [0-48] 83 c3 02 [0-48] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADA_2147734240_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADA!bit"
        threat_id = "2147734240"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 53 8b ec 83 [0-16] 5b [0-16] 43 43 be 00 10 40 00 [0-16] ad [0-16] 83 f8 00 74 [0-16] 39 18 75 [0-16] 81 78 04 ec 0c 56 8d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADB_2147734318_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADB!bit"
        threat_id = "2147734318"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 9e 5e 32 00 [0-48] 05 b8 a1 0f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 57 7e 2f 00 [0-48] 58 [0-48] 05 f6 81 23 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADC_2147734361_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADC!bit"
        threat_id = "2147734361"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 00 00 f0 31 d8 d1 c8 c1 c3 08 e2 f7}  //weight: 1, accuracy: High
        $x_1_2 = {5e 8b 7c 24 0c b9 ?? ?? ?? ?? 57 f3 66 a5 5f b8 04 00 00 00 [0-16] e8 0e 00 00 00 [0-16] 01 c1 81 f9 [0-16] 75 ?? ff e7 81 34 0f ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADD_2147734366_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADD!bit"
        threat_id = "2147734366"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 5a 8b ec 83 [0-48] 66 83 eb 05 [0-48] 39 18 75 [0-48] bb ef 0c 56 8d [0-48] 4b [0-48] 4b [0-48] 4b [0-48] 39 58 04 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADE_2147734367_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADE!bit"
        threat_id = "2147734367"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 ff 81 cf 4c 00 53 00 eb 21 30 00 8b 00 [0-16] 8b 58 28}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 83 ec 8b 54 [0-48] 43 39 18 75 ?? c1 ee 00 81 78 04 ec 0c 56 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADF_2147734494_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADF!bit"
        threat_id = "2147734494"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 5e 8b 7c 24 10 b9 00 20 00 00 07 00 81 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 57 f3 66 a5 5f b8 04 00 00 00 d9 d0 e8 dd ff ff ff d9 d0 01 c1 81 f9 00 20 00 00 75 ed ff e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADG_2147734507_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADG!bit"
        threat_id = "2147734507"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 00 10 40 00 ad 83 f8 00 74 fa 81 38 55 8b ec 83 75 f2 bb eb 0c 56 8d 43 39 58 04 75 e7 31 db 53 53 53 54 6a 00 c7 04 24 00 00 04 00 52 51 54 89 85 c0 00 00 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADH_2147734517_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADH!bit"
        threat_id = "2147734517"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 96 89 32 00 [0-48] 05 c0 76 0f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 77 cc 2f 00 [0-48] 58 [0-48] 05 d6 33 23 00 [0-48] 8b 09 [0-48] 39 c1 [0-48] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADI_2147734583_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADI!bit"
        threat_id = "2147734583"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 5a 8b ec 83 66 83 eb 05 39 18 75 ?? bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 ?? 31 db 53 53 53 54 68 00 30 04 00 52 51 54 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADJ_2147734584_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADJ!bit"
        threat_id = "2147734584"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 10 40 00 ad 83 f8 00 74 fa 81 38 55 8b ec 83 75 ?? bb eb 0c 56 8d 43 39 58 04 75 ?? 31 db 53 53 53 54 68 00 00 04 00 52 51 54 89 85 c0 00 00 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADL_2147734585_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADL!bit"
        threat_id = "2147734585"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 30 00 00 00 64 8b 00 8b 40 0c 8b 40 14 8b 00 8b 58 28 bf 4b 00 53 00 47 47 39 3b 75 f0 be 54 00 42 00 46 46 39 73 04 75 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADM_2147734609_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADM!bit"
        threat_id = "2147734609"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 00 10 40 00 31 c0 0b 06 83 c6 04 bb 51 8b ec 83 83 c3 04 39 18 75 ed bb e9 0c 56 8d 83 c3 03 39 58 04 75 e0 31 db 53 53 53 54 68 00 00 01 00 81 04 24 00 00 03 00 52 51 54 89 85 c0 00 00 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAQ_2147734624_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAQ!bit"
        threat_id = "2147734624"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 83 c6 04 bb 54 8b ec 83 43 39 18 75 f1 bb eb 0c 56 8d 43 39 58 04 75 e6 31 db 53 53 53 54 68 00 00 04 00 52 51 54 ff d0 83 c4 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADN_2147734707_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADN!bit"
        threat_id = "2147734707"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 76 7e 12 00 [0-48] 05 e0 81 2f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 27 63 20 00 [0-48] 58 [0-48] 05 26 9d 32 00 [0-48] 8b 09 [0-48] 39 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADO_2147734810_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADO!bit"
        threat_id = "2147734810"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 00 10 40 00 ad 83 f8 00 74 fa bb 53 8b ec 83 83 c3 02 39 18 75 ee bb ea 0c 56 8d 43 43 39 58 04 75 e2 31 db 53 53 53 54 ff 75 14 52 51 54 89 85 c0 00 00 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAO_2147734900_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAO!bit"
        threat_id = "2147734900"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 53 8b ec 83 [0-48] 5b [0-48] 43 [0-48] 43 [0-48] be 00 10 40 00 [0-48] ad [0-48] 83 f8 00 [0-48] 74 [0-48] 39 18 [0-48] 75 [0-48] 57 [0-48] bf eb 0c 56 8d [0-48] 47 [0-48] 39 78 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAP_2147734901_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAP!bit"
        threat_id = "2147734901"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 10 40 00 [0-48] ad [0-48] 83 f8 00 [0-48] 74 [0-48] bb 51 8b ec 83 [0-48] 83 c3 04 [0-48] 39 18 [0-48] 75 [0-48] bb e9 0c 56 8d [0-48] 83 c3 03 [0-48] 39 58 04 [0-48] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADP_2147734978_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADP!bit"
        threat_id = "2147734978"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 10 40 00 85 d8 ad [0-16] 83 f8 00 74 f5 [0-16] bb 56 8b ec 83 85 d8 4b [0-16] 39 18 75 e5 [0-16] 81 78 04 ec 0c 56 8d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAT_2147735008_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAT!bit"
        threat_id = "2147735008"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 72 a5 12 00 [0-48] 05 e4 5a 2f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 27 63 20 00 [0-48] 58 [0-48] 05 26 9d 32 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADQ_2147735015_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADQ!bit"
        threat_id = "2147735015"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ad 85 c0 74 fb 03 04 24 bb 54 8b ec 83 43 39 18 75 ee 81 78 04 ec 0c 56 8d 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADR_2147735112_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADR!bit"
        threat_id = "2147735112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 72 a5 12 00 [0-48] 05 e4 5a 2f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 34 8a 20 00 [0-48] 58 [0-48] 05 19 76 32 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADS_2147735114_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADS!bit"
        threat_id = "2147735114"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 50 8b ec 83 [0-48] 83 c3 05 [0-48] 39 18 [0-48] 75 [0-48] bb e7 0c 56 8d [0-48] 83 c3 05 [0-48] 39 58 04 [0-48] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAR_2147735174_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAR!bit"
        threat_id = "2147735174"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 10 40 00 [0-48] ad [0-48] bb 50 8b ec 83 [0-48] 83 c3 05 [0-48] 39 18 [0-48] 75 [0-48] bb e8 0c 56 8d [0-48] 83 c3 04 [0-48] 39 58 04 [0-48] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAV_2147735186_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAV!bit"
        threat_id = "2147735186"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 72 a5 12 00 [0-48] 05 e4 5a 2f 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 94 99 06 00 [0-48] 58 [0-48] 05 b9 66 4c 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ADT_2147735221_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ADT!bit"
        threat_id = "2147735221"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 fc ff ff ff 5e 8b 7c 24 08 57 b9 00 08 00 00 f3 a5 bb ?? ?? ?? ?? 5f 31 c9 31 d2 81 f2 00 19 00 00 31 1c 0f 29 c1 29 ca 7d ef ff e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAW_2147735320_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAW!bit"
        threat_id = "2147735320"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 32 63 03 00 [0-48] 05 24 9d 3e 00 [0-48] 39 01 [0-48] 0f [0-48] 83 e9 04 [0-48] 68 94 99 06 00 [0-48] 58 [0-48] 05 b9 66 4c 00 [0-48] 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJC_2147735678_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJC!bit"
        threat_id = "2147735678"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb 59 8b ec 83 4b 4b 4b 4b 39 18 75 ed bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 e0}  //weight: 1, accuracy: High
        $x_1_2 = {50 49 31 c1 85 c9 75 f9 58 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJB_2147735679_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJB!bit"
        threat_id = "2147735679"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 04 57 68 ?? ?? ?? ?? 59 51 f3 a4 59 5f 68 ?? ?? ?? ?? 31 f6 5b 31 1c 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 50 04 00 00 00 81 f9 00 00 00 aa 75 e8 eb 5f}  //weight: 1, accuracy: High
        $x_1_3 = {66 c7 45 50 04 00 81 f9 00 00 00 aa 75 e9 eb 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_AJA_2147735680_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJA!bit"
        threat_id = "2147735680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 53 00 42 00 [0-32] 40 [0-32] 40 [0-32] 40 [0-32] 39 41 04 [0-32] 68 4d f7 15 00 [0-32] 58 [0-32] 05 00 09 3d 00 [0-32] 39 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJK_2147735745_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJK!bit"
        threat_id = "2147735745"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 00 10 40 00 [0-48] 48 [0-48] 81 38 4d 5a [0-48] 75 [0-48] 05 cc 10 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fa 41 41 41 41 75 80 00 8b 17 [0-48] 31 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJL_2147735795_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJL!bit"
        threat_id = "2147735795"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 00 10 40 00 [0-48] 8b 03 [0-48] bb d4 94 7d 00 [0-48] 81 c3 79 c5 12 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fa 41 41 41 41 80 00 33 14 24 [0-48] 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJM_2147735848_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJM!bit"
        threat_id = "2147735848"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 f6 81 ce 00 10 40 00 2b b5 c0 00 00 00 8b 06 83 c6 04 bb 53 8b ec 83 43 66 43 39 18 75 ef bb eb 0c 56 8d 43 39 58 04 75 e4 31 db 53 53 53 54 68 00 00 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJN_2147735859_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJN!bit"
        threat_id = "2147735859"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fa 41 41 41 41 0f 85 ?? ?? ff ff 40 00 5e 40 00 33 14 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 80 cc 10 00 00 [0-48] 6a 47 [0-48] 83 2c 24 07 [0-48] 68 02 10 00 00 [0-48] 83 2c 24 02 [0-48] 68 00 62 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BAZ_2147735928_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BAZ!bit"
        threat_id = "2147735928"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 4f 8b ec 83 [0-48] 83 c3 06 [0-48] 39 18 [0-48] 0f [0-48] bb e6 0c 56 8d [0-48] 83 c3 06 [0-48] 39 58 04 [0-48] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_BBA_2147735929_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.BBA!bit"
        threat_id = "2147735929"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 10 40 00 [0-48] ad [0-48] bb 4f 8b ec 83 [0-48] 83 c3 06 [0-48] 39 18 [0-48] 75 [0-48] bb e6 0c 56 8d [0-48] 83 c3 06 [0-48] 39 58 04 [0-48] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJO_2147735969_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJO!bit"
        threat_id = "2147735969"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 10 40 00 [0-16] ad [0-16] bb 57 8b ec 83 [0-16] 4b 4b [0-16] 39 18 75 ?? 39 f0 81 78 04 ec 0c 56 8d 75 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJP_2147739686_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJP!bit"
        threat_id = "2147739686"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 cb 00 50 40 00 [0-48] 81 eb 00 40 00 00 [0-48] 8b 03 [0-48] bb f4 cb 6c 00 [0-48] 81 c3 59 8e 23 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fa 41 41 41 41 30 00 5e 30 00 33 14 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJQ_2147739708_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJQ!bit"
        threat_id = "2147739708"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 00 10 40 00 [0-48] 48 [0-48] 75 [0-48] 05 cc 10 00 00 [0-48] 8b 00 [0-48] 6a 01 [0-48] 83 04 24 3f [0-48] 6a 01 [0-48] 81 04 24 ff 0f 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f ef d1 c3 83 ec 1c [0-48] 8b 74 24 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJR_2147739732_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJR!bit"
        threat_id = "2147739732"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb d4 94 7d 00 [0-48] 81 c3 79 c5 12 00 [0-48] 48 [0-48] 39 18}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fa 41 41 41 41 30 00 5a 30 00 31 34 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJS_2147739769_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJS!bit"
        threat_id = "2147739769"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 00 10 40 00 [0-48] 8b 03 [0-48] bb 4d 5a}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 00 10 40 00 [0-48] 8b 03 [0-48] bb c0 6e 8f 00 [0-48] 81 c3 8d eb 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {81 fa 41 41 41 41 75 30 00 31 f2}  //weight: 1, accuracy: Low
        $x_1_4 = {83 f9 00 0f 30 00 8f 04 08 30 00 31 34 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_VBInject_AJT_2147739791_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJT!bit"
        threat_id = "2147739791"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 00 10 40 00 [0-48] 48 [0-48] 81 38 4d 5a [0-48] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f 7e 14 08 [0-48] 83 e9 fc [0-48] 81 f9 [0-48] 75 [0-48] c3 [0-48] 66 0f ef d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJD_2147739816_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJD!bit"
        threat_id = "2147739816"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fa 41 41 41 41 30 00 5a 30 00 31 34 24}  //weight: 1, accuracy: Low
        $x_1_2 = {05 cc 10 00 00 [0-48] 8b 00 [0-48] 6a 47 [0-48] 83 2c 24 07 [0-48] 68 02 10 00 00 [0-48] 83 2c 24 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJE_2147739855_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJE!bit"
        threat_id = "2147739855"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb f4 cb 6c 00 [0-48] 81 c3 59 8e 23 00 [0-48] 48 [0-48] 39 18}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 41 41 41 41 [0-48] 46 [0-48] 8b 17 [0-48] 56 [0-48] 33 14 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJF_2147739908_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJF!bit"
        threat_id = "2147739908"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 10 20 00 [0-48] 81 04 24 00 00 20 00 [0-48] 5b [0-48] 8b 03}  //weight: 1, accuracy: Low
        $x_1_2 = {bb f4 cb 6c 00 [0-48] 81 c3 59 8e 23 00 [0-48] 48 [0-48] 39 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJG_2147739931_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJG!bit"
        threat_id = "2147739931"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 7e 14 08 [0-48] 83 e9 fc [0-32] 81 f9 [0-32] c3 [0-32] 66 0f ef d1}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 00 10 40 00 [0-48] 8b 00 [0-48] bb 00 [0-16] 5a 4d [0-48] 0f cb [0-48] 48 [0-48] 39 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJH_2147740107_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJH!bit"
        threat_id = "2147740107"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 41 41 41 41 [0-48] 46 [0-48] 8b 17 [0-48] 31 f2 [0-48] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bb f4 cb 6c 00 [0-48] 81 c3 59 8e 23 00 [0-48] 48 [0-48] 39 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_AJH_2147740107_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.AJH!bit"
        threat_id = "2147740107"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 c0 10 00 00 20 00 75 20 00 39 18 [0-32] 00 48}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 41 41 41 41 [0-48] 46 [0-48] ff 37 [0-48] 31 34 24 [0-48] 5a [0-48] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ALA_2147740412_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ALA!bit"
        threat_id = "2147740412"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 04 24 00 10 40 00 [0-48] 5b [0-48] 8b 03 [0-48] bb 00 00 00 00 [0-48] 81 c3 40 42 0f 00 [0-48] 81 c3 0d 18 81 00 [0-48] 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ALB_2147740413_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ALB!bit"
        threat_id = "2147740413"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 04 24 00 10 40 00 [0-48] 5b [0-48] 8b 03 [0-48] bb 00 00 00 00 [0-48] 81 c3 2d a0 24 00 [0-48] 81 c3 20 ba 6b 00 [0-48] 39 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_ALC_2147740492_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.ALC!bit"
        threat_id = "2147740492"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 00 10 40 00 [0-48] 8b 00 [0-48] bb 00 a9 d5 04 [0-48] 81 c3 00 e7 84 48 [0-48] 0f cb}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f ef d1 30 00 c3 30 00 75 b5 30 00 66 0f 7e 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_YA_2147742842_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.YA!MTB"
        threat_id = "2147742842"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 44 24 10 75 ?? f7 c4 ?? ?? ?? ?? 31 c9 f7 c6 ?? ?? ?? ?? 66 81 fa ?? ?? 31 34 0f 66 81 fa ?? ?? 83 e9 ?? 66 81 fa ?? ?? 81 f9 ?? ?? 00 00 75 ?? 66 81 fb ?? ?? 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_VBInject_YAK_2147808921_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/VBInject.YAK!MTB"
        threat_id = "2147808921"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fc 83 c0 20 ff 45 38 ff 4d 38 83 e8 21 83 04 24 00 f8 39 08 d9 fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

