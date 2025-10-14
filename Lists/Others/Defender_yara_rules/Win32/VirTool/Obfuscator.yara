rule VirTool_Win32_Obfuscator_C_2147578151_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.C"
        threat_id = "2147578151"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 52 b9 1a 00 00 00 0f 31 69 c0}  //weight: 1, accuracy: High
        $x_1_2 = {3c 2b 74 14 b7 f0 3c 2f 74 0e b7 fc 3c 39 76 08 b7 41 3c 5a}  //weight: 1, accuracy: High
        $x_1_3 = {80 7e 04 3a 75 03 ad ad 4e 80 7e 05 3a 75 04}  //weight: 1, accuracy: High
        $x_1_4 = {02 ca 8a 0c 39 30 0e 46 ff 4d 10 75}  //weight: 1, accuracy: High
        $x_1_5 = {81 f1 de c0 ad 0b ff 75 ?? ff 75 ?? 50 51 ff 75 ?? 68 ?? ?? ?? ?? ff 75 ?? ff 35 ?? ?? ?? ?? 58 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_2147584956_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator"
        threat_id = "2147584956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d c0 2b 4d c0 89 4d c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_2147584956_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator"
        threat_id = "2147584956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 c0 69 c0 01 01 00 00 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_2147584956_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator"
        threat_id = "2147584956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_2147584956_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator"
        threat_id = "2147584956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 68 3e 8b 00 83 f8 70 74 06 00 64 a1 30 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_2147584956_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator"
        threat_id = "2147584956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {94 8b 52 0c 8a 14 1a 8a 1c}  //weight: 1, accuracy: High
        $x_1_2 = {75 23 8b 51 14 8b 41 10 8b fb 2b fe 0f 80}  //weight: 1, accuracy: High
        $x_1_3 = {ff 74 27 2b fe 8d 95}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_2147584956_5
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator"
        threat_id = "2147584956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 c9 8b c1 74 03 8d 04 09 8b 7d fc 8d 04 41 81}  //weight: 1, accuracy: High
        $x_1_2 = {8d 14 31 85 d2 74 02 33 f6 03 c1 8b 7d 0c 03 c8}  //weight: 1, accuracy: High
        $x_1_3 = {d0 8b c2 81 ef d2 02 96 49 f7 d8 89 7d fc 74 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_2147584956_6
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator"
        threat_id = "2147584956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 4d 5a 00 00 66 39 07 75 17 8b 77 3c 81 fe 00 04 00 00 89 75 f8 7f 09 81 3c 3e 50 45 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 30 00 00 52 6a 00 ff d3}  //weight: 1, accuracy: High
        $x_1_3 = {68 34 01 00 00 68 ?? ?? ?? 00 51 89 5d f4 ff d7}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 46 01 83 f8 3e 88 9e ?? ?? ?? 00 7d 19 ba 3e 00 00 00 2b d0 52 8d 88 ?? ?? ?? 00 6a 01 51 e8 ?? ?? ?? ?? 83 c4 0c}  //weight: 1, accuracy: Low
        $x_1_5 = {00 40 49 3b c6 7c f2 07 00 8a 11 88 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_2147584956_7
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator"
        threat_id = "2147584956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 e5 53 56 83 e4 f8 83 ec}  //weight: 1, accuracy: High
        $x_1_2 = {24 07 74 08 8a 44 24}  //weight: 1, accuracy: High
        $x_1_3 = {0f 93 c3 29 f1 0f 93 c7}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 29 cf 19 d6 8b}  //weight: 1, accuracy: High
        $x_1_5 = {31 c9 83 c1 18 89 44 24}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 31 d0 31 ce 35}  //weight: 1, accuracy: High
        $x_1_7 = {00 0f 92 c2 31 db 85 c9}  //weight: 1, accuracy: High
        $n_100_8 = "Soldiers - Arena" wide //weight: -100
        $n_100_9 = "Gates Of Hell" wide //weight: -100
        $n_100_10 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 42 00 61 00 74 00 74 00 6c 00 65 00 20 00 6f 00 66 00 20 00 45 00 6d 00 70 00 69 00 72 00 65 00 73 00}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_N_2147593546_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.N"
        threat_id = "2147593546"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 e8 06 00 00 00 8b 64 24 08 eb 0c ?? ?? 64 ff ?? 64 89 ?? cc [0-32] 64 8f [0-16] e8 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_S_2147598106_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.S"
        threat_id = "2147598106"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 33 f6 66 81 3e 4d 5a 75 f5 89 75 00 be 00 00 ?? ?? 2b 75 00 89 75 20 c7 45 24 ?? ?? ?? ?? c7 45 28 ?? ?? ?? ?? 33 c0 64 8b 40 30 8b 40 0c 8b 40 1c ff 70 08 8f 45 08}  //weight: 1, accuracy: Low
        $x_1_2 = {66 33 f6 66 81 3e 4d 5a 75 f5 89 75 00 be 00 00 ?? ?? 2b 75 00 89 75 1c c7 45 20 ?? ?? ?? ?? c7 45 24 ?? ?? ?? ?? 33 c0 64 8b 78 20 64 8b 40 30 8b 40 0c 8b 40 1c ff 70 08 8f 45 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_T_2147598276_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.T"
        threat_id = "2147598276"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Dokumente und Einstellungen\\Administrator\\Desktop\\" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" wide //weight: 1
        $x_1_3 = "\\server.exe.ucc" wide //weight: 1
        $x_1_4 = "WScript.Shell" wide //weight: 1
        $x_1_5 = "EnableVicsFirewall" ascii //weight: 1
        $x_1_6 = "ExtractServer" ascii //weight: 1
        $x_1_7 = "\\options.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_R_2147598364_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.R"
        threat_id = "2147598364"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 6a 00 6a 00 68 ff ff fb ff ff 15 ?? ?? ?? ?? 85 c0 7e 08 6a 00 (e8 ?? ?? ?? ?? ??|ff 15 ?? ?? ?? ??) a1 ?? ?? ?? ?? 31 05 ?? ?? ?? ?? 31 05 ?? ?? ?? ?? 33 c9 39 0d ?? ?? ?? ?? 76 18 a1 ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 03 c1 30 10 41 3b 0d ?? ?? ?? ?? 72 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_Q_2147598455_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.Q"
        threat_id = "2147598455"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {60 6a 00 68 2e 64 6c 6c 68 65 6c 33 32 68 6b 65 72 6e [0-7] 8b 45 10 ff 10 83 c4 10 89 c7 68 65 63 74 00 [0-6] 68 65 4f 62 6a 68 69 6e 67 6c 68 46 6f 72 53 [0-6] 68 57 61 69 74 54 50 8b 45 0c ff 10}  //weight: 100, accuracy: Low
        $x_100_2 = {60 6a 00 68 2e 64 6c 6c 68 ?? ?? ?? ?? ?? 68 65 6c 33 32 68 6b 65 72 6e 89 e0 6a 00 6a 00 50 8b 45 10}  //weight: 100, accuracy: Low
        $x_100_3 = {60 6a 00 68 2e 64 6c 6c 68 65 6c 33 32 68 ?? ?? ?? ?? ?? 68 6b 65 72 6e 89 e0 6a 00 6a 00 50 8b 45 10}  //weight: 100, accuracy: Low
        $x_100_4 = {eb 14 8b 74 24 0c 8b 86 b8 00 00 00 c6 00 90 c6 40 02 14 31 c0 c3 64 8f 05 00 00 00 00 58 5b 58 5a}  //weight: 100, accuracy: High
        $x_10_5 = "h.dllhel32hkernT" ascii //weight: 10
        $x_10_6 = "heObjhinglhForShWaitTP" ascii //weight: 10
        $x_10_7 = "heNamheFilhodulhGetMTW" ascii //weight: 10
        $x_10_8 = "hdleEheHanhodulhGetMTW" ascii //weight: 10
        $x_10_9 = "hllochualAhVirtTP" ascii //weight: 10
        $x_10_10 = "hdPtrhdReahIsBaTW" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_V_2147599905_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.V"
        threat_id = "2147599905"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 2c 08 2c 08 8b 45 45 90 8b 45 45 90 8b 45 45 90 8b 45 45 90 90 8b 45 45 e9 c9 f8 fe ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_W_2147600277_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.W"
        threat_id = "2147600277"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 fc 2d ?? ?? ?? ?? 8d 80 ?? ?? ?? ?? 48 66 81 38 50 45 75 f8 8b f8 48 66 81 38 4d 5a 75 f8 8b bf 80 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_Y_2147601091_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.Y"
        threat_id = "2147601091"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = {5d c3 00 00 ff ff ff 20 68 69 64 64 65 6e 20 6e 6f 77 21 00 00 00 00 ff ff ff ff 17 00 00 00 59 6f 75 20 63 61 6e 20 6e 65 76 65 72 20 63 61 74 63 68 20 6d 65 21 00 ff ff ff ff 06 00 00 00 4e 65 76 65 72 21 00 00 ff ff ff ff 13 00 00 00 59 6f 75 20 68 61 76 65 20 6e 6f 20 63 68 61 6e 63 65 21}  //weight: 1, accuracy: High
        $x_1_3 = {ba ec 40 00 10 8b c6 e8 f2 fa ff ff 8b d8 b8 6c}  //weight: 1, accuracy: High
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "SizeofResource" ascii //weight: 1
        $x_1_6 = "ReadProcessMemory" ascii //weight: 1
        $x_1_7 = "FindResourceA" ascii //weight: 1
        $x_1_8 = {8b ec 83 c4 f0 53 56 b8 e8 3f 00 10 e8 7a f6 ff ff be 68 66 00 10 33 c0 55 68 db 40 00 10 64 ff 30 64 89 20 e8 fa f8 ff ff ba ec 40 00 10 8b c6 e8 f2 fa ff ff 8b d8 b8 6c 66 00 10 8b 16 e8 88 f2 ff ff b8 6c 66 00 10 e8 76 f2 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule VirTool_Win32_Obfuscator_AB_2147603112_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AB"
        threat_id = "2147603112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {83 c7 01 bb 02 00 00 00 e8 f8 00 00 00 73 d5 e8 f1 00 00 00 73 54 33 c0 e8 e8 00 00 00 0f 83 a7 00 00 00 e8 dd 00 00 00 13 c0 e8 d6 00 00 00 13 c0 e8 cf 00 00 00 13 c0 e8 c8 00 00 00 13 c0 74 15}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AB_2147603112_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AB"
        threat_id = "2147603112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {83 c7 01 bb 02 00 00 00 e8 1f 01 00 00 73 c9 e8 18 01 00 00 73 60 33 c0 e8 0f 01 00 00 0f 83 c2 00 00 00 e8 04 01 00 00 13 c0 e8 fd 00 00 00 13 c0 e8 f6 00 00 00 13 c0 e8 ef 00 00 00 13 c0 74 21 eb 04}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AF_2147604958_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AF"
        threat_id = "2147604958"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Dokumente und Einstellungen\\2fast4you\\Desktop\\VisualStudio6\\VisualStudio6\\Files\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "C:\\Dokumente und Einstellungen\\2fast4you\\Desktop\\VisualStudio6\\VisualStudio6\\Files\\VB98\\Neuer Ordner (2)\\Project2.vbp" wide //weight: 1
        $x_1_3 = "EncryptFile" ascii //weight: 1
        $x_1_4 = "EncryptByte" ascii //weight: 1
        $x_1_5 = "DecryptByte" ascii //weight: 1
        $x_1_6 = "DecryptFile" ascii //weight: 1
        $x_1_7 = "HelpMe.exe" wide //weight: 1
        $x_1_8 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AG_2147604965_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AG"
        threat_id = "2147604965"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe ff ff ba 44 00 00 00 e8 ?? ?? ff ff 8d 85 ?? ff ff ff ba ?? ?? 00 00 e8 ?? ?? ff ff 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8d ?? ?? fe ff ff 33 c0 e8 ?? ?? ff ff 8b ?? ?? fe ff ff e8 ?? ?? ff ff 50 6a 00 e8 ?? ?? ff ff c7 85 18 ff ff ff 07 00 01 00 8d 85 18 ff ff ff 50 8b 85 ?? ?? ff ff 50 e8 ?? ?? ff ff 8d 45 ?? 50 6a 04 8d 45 ?? 50 8b 45 bc 83 c0 08 50 8b 85 ?? ?? ff ff 50 e8 ?? ?? ff ff 6a 40 68 00 30 00 00 8b 45 ?? 50 8b 45 ?? 8b 40}  //weight: 1, accuracy: Low
        $x_1_2 = {34 50 8b 85 ?? ?? ff ff 50 e8 ?? ?? ff ff 8d 45 ?? 50 8b 45 ?? 50 8b 45 ?? 50 8b 45 ?? 8b 40 34 50 8b 85 ?? ?? ff ff 50 e8 ?? ?? ff ff 8d 45 ?? 50 6a 04 8b 45 ?? 83 c0 34 50 8b 45 bc 83 c0 08 50 8b 85 ?? ?? ff ff 50 e8 ?? ?? ff ff 8b 45 ?? 8b 40 34 8b 55 ?? 03 42 28 89 45 c8 8d 85 18 ff ff ff 50 8b 85 ?? ?? ff ff 50 e8 ?? ?? ff ff 8b 85 ?? ?? ff ff 50 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? 00 10 8b 45 ?? 50 e8 ?? ?? ff ff 59 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 55 68 ?? ?? 00 10 64 ff 30 64 89 20 6a 0a 68 ?? ?? 00 10 a1 ?? ?? 00 10 50 e8 ?? ?? ff ff 8b d8 53 a1 ?? ?? 00 10 50 e8 ?? ?? ff ff 8b f8 53 a1 ?? ?? 00 10 50 e8 ?? ?? ff ff 8b ?? ?? e8 ?? ?? ff ff 8b ?? 85 ?? 74 26 8b d7 4a b8 ?? ?? 00 10 e8 ?? ?? ff ff b8 ?? ?? 00 10 e8 ?? ?? ff ff 8b cf 8b ?? e8 ?? ?? ff ff ?? e8 ?? ?? ff ff 8d 4d ec ba ?? ?? 00 10 a1 ?? ?? 00 10 e8 ?? ?? ff ff 8b 55 ec b8 ?? ?? 00 10 e8 ?? ?? ff ff b8 ?? ?? 00 10 e8 ?? ?? ff ff e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? 00 10 8d 45 ec e8 ?? ?? ff ff c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HD_2147605039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HD"
        threat_id = "2147605039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "by Holy_Father && Ratter/29A" ascii //weight: 2
        $x_2_2 = "as a part of The Hacker Defender Project - http://www.hxdef.org" ascii //weight: 2
        $x_2_3 = "http://hxdef.net.ru, http://hxdef.czweb.org, http://rootkit.host.sk" ascii //weight: 2
        $x_2_4 = "Copyright (c) 2000,forever ExEwORx" ascii //weight: 2
        $x_2_5 = "betatested by ch0pper <THEMASKDEMON@flashmail.com>" ascii //weight: 2
        $x_2_6 = "birthday: 03.10.2004" ascii //weight: 2
        $x_2_7 = "[-q] [-d] [-b:ImageBase] [-o:OutputFile] InputFile " ascii //weight: 2
        $x_2_8 = "-q             be quiet (no console output)" ascii //weight: 2
        $x_2_9 = "-d             for dynamic DLLs only" ascii //weight: 2
        $x_2_10 = "-i             save resource icon and XP manifest" ascii //weight: 2
        $x_2_11 = "-a             save overlay data from the end of original file" ascii //weight: 2
        $x_2_12 = "-b:ImageBase   specify image base in hexadecimal string" ascii //weight: 2
        $x_2_13 = "-o:OutputFile  specify file for output" ascii //weight: 2
        $x_2_14 = "(InputFile will be rewritten if no OutputFile given)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule VirTool_Win32_Obfuscator_AI_2147605328_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AI"
        threat_id = "2147605328"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "TranslateAcceleratorA" ascii //weight: 10
        $x_10_2 = "C:\\WINDOWS\\system32\\calc.exe" ascii //weight: 10
        $x_1_3 = {85 c0 0f 84 ?? ?? 00 00 8b d8 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? 00 00 50 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? 00 00 50 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? 00 00 50 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 85 c0 0f}  //weight: 1, accuracy: Low
        $x_1_4 = {f3 a4 6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 80 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 [0-16] 50 6a 00 68 ?? ?? ?? ?? 6a 02 68 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {f3 a4 8b 0c 24 03 49 3c 8b d9 8b d1 8b 04 24 8b 5b 34 66 8b 49 06 81 c2 f8 00 00 00 51 8b 72 14 03 f0 8b 7a 0c 03 fb 8b 4a 10 f3 a4 83 c2 28 59 66 49 75 e8 8b fb 03 7f 3c 8b bf 80 00 00 00 03 fb 8b 4f 0c 83 f9 00}  //weight: 1, accuracy: High
        $x_1_6 = {8b f8 b9 e5 00 00 00 f3 a4 ff e0 8b 3c 24 03 7f 3c 8b f7 8b 7f 34 8b 76 50 03 f7 57 ff 54 24 08 68 00 80 00 00 6a 00 57 ff 54 24 14 6a 40 68 00 30 00 00 68 00 00 01 00 57 ff 54 24 1c 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AK_2147605340_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AK"
        threat_id = "2147605340"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 3c 2e 75 fb 89 f1 29 f9 8d 04 8d 00 00 00 00 29 c4 89 fe 89 e7 50 57 f3 a4 c7 07 44 4c 4c 00 ff 55 f8}  //weight: 1, accuracy: High
        $x_1_2 = {ff 36 ff 93 ?? ?? 00 00 89 c7 83 c6 04 8b 0e 83 c6 04 8b 06 09 c0 74 09 50 57 e8 ?? ?? ff ff 89 06 83 c6 04 e2 ec eb d2 61}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 7d 08 0f b6 1f 09 db 74 0c f7 e3 d1 e0 35 ?? ?? ?? ?? 47 eb ed 89 45 fc 61 8b 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AL_2147605517_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AL"
        threat_id = "2147605517"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 06 56 52 55 4c 5a 00 [0-32] 8b 04 24 83 e8 4f 68 ?? ?? ?? ?? ff d0 [0-255] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AM_2147605717_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AM"
        threat_id = "2147605717"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 61 9c 9d 50 53 51 59 5b 58 74 02 75 00 e9 00 00 00 00 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AP_2147605766_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AP"
        threat_id = "2147605766"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".rawdat" ascii //weight: 1
        $x_1_2 = "xmg.exe" ascii //weight: 1
        $x_1_3 = {72 65 6c 64 65 6c 00 00 5c 64 72 69 76 65 72 73 5c 6e 74 66 73 2e 73 79 73 00 00 00 74 72 75 73 73 00}  //weight: 1, accuracy: High
        $x_2_4 = {8d 86 38 01 00 00 66 81 00 29 37 8b 96 30 01 00 00 [0-32] 6a 05}  //weight: 2, accuracy: Low
        $x_2_5 = {40 00 ff e0 09 00 35 ?? ?? ?? ?? 8d 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AQ_2147605904_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQ"
        threat_id = "2147605904"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c3 00 00 01 00 81 fb 00 00 ?? ?? 75 05 bb 00 00 ?? ?? e8 ?? ?? ?? ?? 83 f9 00 74 de 8b cb 81 c1 00 00 ?? ?? 66 81 39 4d 5a 75 cf 8b 41 3c 03 c1 8b 40 78 83 f8 00 74 c2 03 c1 8b 50 0c 03 d1 81 3a 4b 45 52 4e 75 b3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AT_2147606367_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AT"
        threat_id = "2147606367"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 58 58 58 58 6b db ?? ff d4 50 8b 40 ?? 05 ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AV_2147606370_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AV"
        threat_id = "2147606370"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ShellTmpMap" ascii //weight: 2
        $x_2_2 = "DeCrypt" ascii //weight: 2
        $x_2_3 = "EnCrypt" ascii //weight: 2
        $x_2_4 = "TestBmp" ascii //weight: 2
        $x_2_5 = "TestDebug" ascii //weight: 2
        $x_2_6 = "IofCompleteRequest" ascii //weight: 2
        $x_2_7 = "MmIsAddressValid" ascii //weight: 2
        $x_2_8 = "IoCreateDevice" ascii //weight: 2
        $x_2_9 = "IoCreateSymbolicLink" ascii //weight: 2
        $x_2_10 = "IoDeleteDevice" ascii //weight: 2
        $x_2_11 = "IoDeleteSymbolicLink" ascii //weight: 2
        $x_2_12 = "RtlInitUnicodeString" ascii //weight: 2
        $x_2_13 = "@INIT" ascii //weight: 2
        $x_4_14 = "can not found %s" ascii //weight: 4
        $x_2_15 = "Func2Func" ascii //weight: 2
        $x_2_16 = "ShellMap" ascii //weight: 2
        $x_1_17 = "warning" ascii //weight: 1
        $x_1_18 = ".reloc" ascii //weight: 1
        $x_2_19 = "dont panic" ascii //weight: 2
        $x_2_20 = "-foI1" ascii //weight: 2
        $x_5_21 = "ring0 module" ascii //weight: 5
        $x_5_22 = "\\\\.\\ring0" ascii //weight: 5
        $x_5_23 = "\\DosDevices\\ring0" wide //weight: 5
        $x_5_24 = "\\Device\\ring0" wide //weight: 5
        $x_5_25 = "ring0.sys" ascii //weight: 5
        $x_5_26 = "XDLL.DLL" ascii //weight: 5
        $x_2_27 = "mydrv" ascii //weight: 2
        $x_2_28 = "xwgfe" ascii //weight: 2
        $x_2_29 = "\\$H\\$X" ascii //weight: 2
        $x_2_30 = "Nnoe3" ascii //weight: 2
        $x_2_31 = "NTOSKRNL.EXE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AX_2147606497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AX"
        threat_id = "2147606497"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = "PiD Team.ProtectionID" ascii //weight: -100
        $x_2_2 = {81 fe ff ff 00 00 7c ed 64 a1 18 00 00 00 8b 40 34 88 45 ff 80 7d ff 64 8b 45 f4 73 ?? 8b ?? 3c}  //weight: 2, accuracy: Low
        $x_2_3 = {f6 eb 8d 0c 3a 30 01 8a 01 02 45 ?? 88 01 8b 5d ?? 8a 5b 08 32 d8 f6 d3 42 88 19 3b 56 04 72 dc 04 00 8a c2 b3}  //weight: 2, accuracy: Low
        $x_1_4 = {eb 1f 8b 06 3d 00 00 00 80 72 05 0f b7 c0 eb 07 8b 4d ?? 8d 44 08 02 50 53 ff 55 ?? 89 06 83 c6 04 83 3e 00 75 dc}  //weight: 1, accuracy: Low
        $x_1_5 = {55 8b ec 87 e5 5d e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AY_2147606498_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AY"
        threat_id = "2147606498"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 02 75 06 81 c2 00 02 00 00 51 8b 4f 10 83 f8 02 75 06 81 e9 00 02 00 00 57 bf c8 00 00 00 8b f1 e8 27 00 00 00 8b c8 5f b8 ?? ?? ?? ?? 03 c5 e8 24 00 00 00 59 49 eb b1 59 83 c7 28 49 eb 8a 8b 85 ?? ?? ?? ?? 89 44 24 1c 61 ff e0 56 57 4f f7 d7 23 f7 8b c6 5f 5e c3 60 83 f0 05 40 90 48 83 f0 05 8b f0 8b fa 60 e8 0b 00 00 00 61 83 c7 08 83 e9 07 e2 f1 61 c3 57 8b 1f 8b 4f 04 68 b9 79 37 9e 5a 42 8b c2 48 c1 e0 05 bf 20 00 00 00 4a 8b eb c1 e5 04 2b cd 8b 6e 08 33 eb 2b cd 8b eb c1 ed 05 33 e8 2b cd 2b 4e 0c 8b e9 c1 e5 04 2b dd 8b 2e 33 e9 2b dd 8b e9 c1 ed 05 33 e8 2b dd 2b 5e 04 2b c2 4f 75 c8 5f 89 1f 89 4f 04 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AZ_2147606499_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AZ"
        threat_id = "2147606499"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a d2 8a 07 90 4f 3c 00 74 f6 47 83 ec 08 68 60 02 00 00 8a d2 6a 40 ff 53 e8 90 89 04 24 8d 05 21 10 40 00 50 8a d2 ff 53 f0 8d 15 09 10 40 00 52 50 ff 53 ec 8a d2 89 44 24 04 33 c0 8a d2 8a 07 90 96 83 c7 fc 8b 07 2b f8 8a d2 8b 2f 90 83 c7 04 8b c7 8b cd 8a d2 c0 4c 08 ff 04 90 80 74 01 ff 98 e2 f1 8a d2 ff 34 24 68 04 01 00 00 ff 53 fc 57 58 03 c5 50 90 ff 74 24 04 ff 53 dc 6a 00 68 80 00 00 00 8a d2 6a 02 6a 00 6a 00 68 00 00 00 40 50 ff 53 f8 40 74 46 8a d2 48 50 56 8a d2 6a 00 8a d2 54 83 2c 24 50 90 55 57 50 ff 53 e4 5e ff 53 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BD_2147607400_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BD"
        threat_id = "2147607400"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 00 33 d2 b8 ?? ?? ?? ?? 33 c9 bb ?? ?? ?? ?? 81 fa ac 26 00 00 75 02 28 03 43 c1 e8 08 41 83 f9 04 75 0a b8 ?? ?? ?? ?? b9 00 00 00 00 81 fb ?? ?? ?? ?? 72 da 42 81 fa 1b 27 00 00 76 c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BE_2147607449_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BE"
        threat_id = "2147607449"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 2e 64 6c ?? [0-15] 6e 74 64 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 74 72 ?? [0-15] 74 4c 64 74 ?? [0-15] 4e 74 53 65}  //weight: 1, accuracy: Low
        $x_1_3 = {51 68 00 04 00 00 68 00 00 00 00 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 74 08 ?? ?? 5f 59 f3 a4 eb f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BF_2147607594_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BF"
        threat_id = "2147607594"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 24 01 b8 ?? ?? ?? ?? 33 c9 bb ?? ?? 40 00 81 ff 06 27 00 00 75 02 28 03 43 c1 e8 08 41 83 f9 04 75 0a b8 ?? ?? ?? ?? b9 00 00 00 00 81 fb ?? ?? 40 00 72 da 47 81 ff 11 27 00 00 76 c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BG_2147607679_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BG"
        threat_id = "2147607679"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 00 00 00 00 b8 ?? ?? ?? ?? 33 c9 c7 44 24 ?? ?? ?? 40 00 81 3c 24 ?? 27 00 00 75 06 8b 54 24 ?? 28 02 ff 44 24 ?? c1 e8 08 41 83 f9 04 75 0a b8 ?? ?? ?? ?? b9 00 00 00 00 81 7c 24 ?? ?? ?? 40 00 72 d0 ff 04 24 81 3c 24 ?? 27 00 00 76 b5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BK_2147608022_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BK"
        threat_id = "2147608022"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 5d 83 3b 00 0f 85 a5 00 00 00 fc 89 1b 8b 4b 0c 33 c0 ff d1 8b 4b 10 e3 2f}  //weight: 1, accuracy: High
        $x_1_2 = {61 9d c3 83 ec 54 8b fc 8b 76 0c 8b d7 ac 84 c0 74 03 aa eb f8 e8 0b 00 00 00 20 6e 6f 74 20 66 6f 75 6e 64 00 5e ac aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BL_2147608041_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BL"
        threat_id = "2147608041"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 8b 05 30 00 00 00 89 45 fc 8b 45 fc 83 c0 0c 8b 00 83 c0 0c 8b 00 83 c0 18 8b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BL_2147608041_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BL"
        threat_id = "2147608041"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be c1 8a 4a 01 33 c6 42 84 c9 75 ?? 5e c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = "h4321T" ascii //weight: 1
        $x_1_3 = {6a 01 68 44 33 22 11 b8 dd cc bb aa ff d0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BL_2147608041_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BL"
        threat_id = "2147608041"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8b 04 24 66 33 c0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b fc 66 81 38 4d 5a 75 13 8b 50 ?? 81 fa 00 10 00 00 77 08 66 81 3c 10 50 45 74 07 2d 00 00 01 00 eb df 50 8b 74 10 ?? 03 f0 83 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BP_2147608488_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BP"
        threat_id = "2147608488"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 c7 04 24 ?? ?? ?? ?? 5a 31 f9 66 8b 3a 66 47 66 89 3a 81 ef ?? ?? ?? ?? 66 83 02 01 4f 41 83 c2 01 e8 07 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BQ_2147608543_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BQ"
        threat_id = "2147608543"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 39 66 83 c7 01 66 89 39 01 d7 50 29 c2 5a 66 8b 11 66 83 c2 01 66 89 11 81 e3 ?? ?? ?? ?? e8 11 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BU_2147608887_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BU"
        threat_id = "2147608887"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 6f 61 64 c7 45 ?? 4c 69 62 72 c7 45 ?? 61 72 79 41 c7 45 ?? 00 00 00 00 c7 45 ?? 56 69 72 74 c7 45 ?? 75 61 6c 50 c7 45 ?? 72 6f 74 65 c7 45 ?? 63 74 00 00 c7 45 ?? 56 69 72 74 c7 45 ?? 75 61 6c 41 c7 45 ?? 6c 6c 6f 63}  //weight: 10, accuracy: Low
        $x_10_2 = {e8 00 00 00 00 58 8b f0 2d ?? ?? ?? ?? 89 ?? ?? ff ff ff 81 ?? 00 f0 ff ff 89 ?? ?? ff ff ff 8b ?? ?? 81 ?? 00 f0 ff ff 66 ?? ?? 4d 5a 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BV_2147608979_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BV"
        threat_id = "2147608979"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 66 8b 02 3d 4d 5a 00 00 74 ?? 33 c0 e9 ?? ?? 00 00 8b 8d ?? ?? ff ff 8b 55 ?? 03 51 3c 89 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 81 38 50 45 00 00 74 ?? 33 c0 e9 ?? ?? 00 00 6a 40 68 00 10 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BX_2147609178_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BX"
        threat_id = "2147609178"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c3 00 00 01 00 81 fb 00 00 00 80 75 05 bb 00 00 f0 bf e8 ?? ?? ?? ?? 83 f8 00 74 e3 66 81 3b 4d 5a 75 dc 8b 43 3c 03 c3 66 81 38 50 45 75 d0 f6 40 17 20 74 ca 8b 40 78 03 c3 8b 50 0c 03 d3 81 3a 4b 45 52 4e 75 b8 81 7a 04 45 4c 33 32 75 af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZ_2147609463_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZ"
        threat_id = "2147609463"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 6a 00 68 2e 64 6c 6c 68}  //weight: 1, accuracy: High
        $x_1_2 = {3d 2e 65 78 65 74 ?? 3d 2e 45 58 45 74 ?? 3d 2e 74 6d 70 74 ?? 3d 2e 54 4d 50}  //weight: 1, accuracy: Low
        $x_1_3 = "huenchFreqhancehformhyPerhQuerT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CD_2147609812_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CD"
        threat_id = "2147609812"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 74 75 62 00 00 50 72 6f 6a 65 63 74 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {79 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 02 00 00 00 5c 00 00 00 08 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 [0-32] 7c 00 7c 00 7c 00 00 00 06 00 00 00 74 00 6d 00 70 00 00 00 10 00 00 00 5c 00 74 00 6d 00 70 00 2e 00 65 00 78 00 65 00 00 00 00 00 08 00 00 00 70 00 61 00 73 00 73 00 00 00 00 00 0c 00 08 00 00 00 00 00 00 00 00 00 56 42 41 36 2e 44 4c 4c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CE_2147610110_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CE"
        threat_id = "2147610110"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "404"
        strings_accuracy = "High"
    strings:
        $x_200_1 = {8b c3 99 03 45 e0 13 55 e4 33 04 24 33 54 24 04 83 c4 08 5a 88 02 43 46 4f 75}  //weight: 200, accuracy: High
        $x_200_2 = {8a 98 00 01 00 00 02 14 18 81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75}  //weight: 200, accuracy: High
        $x_1_3 = "VirtualAllocEx" ascii //weight: 1
        $x_1_4 = "VirtualProtectEx" ascii //weight: 1
        $x_1_5 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_200_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CF_2147610421_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CF"
        threat_id = "2147610421"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 40 00 00 00 [0-16] 8b ?? 3c 01 ?? 8b ?? 50 [0-8] ff (d0|2d|d7)}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f8 00 7d 00 00 [0-16] 0f 83 ?? 00 00 00 [0-24] 80 fc 05 [0-16] 0f 83 ?? 00 00 00 [0-24] 81 f8 7f 00 00 00 [0-16] 0f 87 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CG_2147610423_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CG"
        threat_id = "2147610423"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 e9 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 30 00 00 00 8b 40 68 85 c0 74 02 eb}  //weight: 1, accuracy: High
        $x_1_3 = {31 d2 64 ff 32 64 89 22 cd 03 8b 64 24 08 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CH_2147610451_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CH"
        threat_id = "2147610451"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e9 01 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {e8 01 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {66 35 de c0}  //weight: 10, accuracy: High
        $x_10_4 = {66 3d 93 9a}  //weight: 10, accuracy: High
        $x_10_5 = {24 8d 64 24 04}  //weight: 10, accuracy: High
        $x_1_6 = {03 7c 24 04}  //weight: 1, accuracy: High
        $x_1_7 = {03 74 24 04}  //weight: 1, accuracy: High
        $x_1_8 = {03 6c 24 04}  //weight: 1, accuracy: High
        $x_1_9 = {03 54 24 04}  //weight: 1, accuracy: High
        $x_1_10 = {03 4c 24 04}  //weight: 1, accuracy: High
        $x_1_11 = {03 5c 24 04}  //weight: 1, accuracy: High
        $x_1_12 = {03 44 24 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CK_2147610687_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CK"
        threat_id = "2147610687"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {ff ff 0f ae f8}  //weight: 6, accuracy: High
        $x_5_2 = {81 f9 33 32 04 00}  //weight: 5, accuracy: High
        $x_3_3 = {81 f9 22 01 00 00}  //weight: 3, accuracy: High
        $x_3_4 = "1L$(" ascii //weight: 3
        $x_4_5 = {8a 4c 2c 18}  //weight: 4, accuracy: High
        $x_4_6 = {88 54 2c 18}  //weight: 4, accuracy: High
        $x_4_7 = {0f b6 54 34 14}  //weight: 4, accuracy: High
        $x_4_8 = {0f b6 4c 14 14}  //weight: 4, accuracy: High
        $x_1_9 = {8d 64 24 0f}  //weight: 1, accuracy: High
        $x_1_10 = {8d 64 24 1f}  //weight: 1, accuracy: High
        $x_1_11 = {8d 64 24 2f}  //weight: 1, accuracy: High
        $x_1_12 = {8d 64 24 3f}  //weight: 1, accuracy: High
        $x_1_13 = {8d 64 24 4f}  //weight: 1, accuracy: High
        $x_1_14 = {8d 64 24 5f}  //weight: 1, accuracy: High
        $x_1_15 = {8d 64 24 6f}  //weight: 1, accuracy: High
        $x_1_16 = {8d 64 24 7f}  //weight: 1, accuracy: High
        $x_1_17 = {8d 64 24 8f}  //weight: 1, accuracy: High
        $x_1_18 = {8d 64 24 9f}  //weight: 1, accuracy: High
        $x_1_19 = {8d 64 24 af}  //weight: 1, accuracy: High
        $x_1_20 = {8d 64 24 bf}  //weight: 1, accuracy: High
        $x_1_21 = {8d 64 24 cf}  //weight: 1, accuracy: High
        $x_1_22 = {8d 64 24 df}  //weight: 1, accuracy: High
        $x_1_23 = {8d 64 24 ef}  //weight: 1, accuracy: High
        $x_1_24 = {8d 64 24 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 16 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 15 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 12 of ($x_1_*))) or
            ((4 of ($x_4_*) and 14 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_3_*) and 11 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 15 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 14 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_4_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 16 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 13 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*) and 12 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 16 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 13 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 15 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 11 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 4 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 4 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CO_2147611156_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CO"
        threat_id = "2147611156"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {76 16 8b ff 83 fd 04 72 02 33 ed 8a 4c 2c 1c 30 0c 38 40 45 3b c3 72 ec 53 57 e8}  //weight: 2, accuracy: High
        $x_1_2 = {69 c0 6d 4e c6 41 05 39 30 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {76 1b 83 f9 04 72 02 33 c9 8b 44 24 08 8a 54 0c 10 03 c6 30 10 41 46 3b 74 24 0c 72 e5}  //weight: 2, accuracy: High
        $x_1_4 = {69 f6 6d 4e c6 41 81 c6 39 30 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CQ_2147611465_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CQ"
        threat_id = "2147611465"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 cd 2d c3 64 8f 05 00 00 00 00 83 c4 04 ff 64 24 20 08 00 80 37 ?? 68 [0-80] 85 ?? 74 07 80 ?? 00 ?? ?? eb f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CR_2147611502_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CR"
        threat_id = "2147611502"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb ff ff ff 77 64 8b 83 19 00 00 88 8b 44 48 10 0f b6 40 02 f7 d0 83 e0 01 8b d8 68 f6 fb c3 00 e8 00 00 00 00 83 2c 24 33 8b f4 83 c6 04 ff e6}  //weight: 1, accuracy: High
        $n_2_2 = "mobileEx Professional Service Tool" wide //weight: -2
        $n_2_3 = "LUTCREATORABOUTFORM" wide //weight: -2
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CT_2147611589_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CT"
        threat_id = "2147611589"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 75 04 87 ?? ff ?? ?? eb f4 04 00 eb 0a 80}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 75 04 89 ?? ff 04 00 eb 0a 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_CV_2147611843_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CV"
        threat_id = "2147611843"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "84"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "ControlService" ascii //weight: 10
        $x_10_3 = "AdjustTokenPrivileges" ascii //weight: 10
        $x_10_4 = "NtUnmapViewOfSection" ascii //weight: 10
        $x_10_5 = "ZwTerminateJobObject" ascii //weight: 10
        $x_10_6 = "DMDEPack" wide //weight: 10
        $x_10_7 = "DMDEPACHER" wide //weight: 10
        $x_1_8 = "runiep.exe,nod32kui.exe,nod32krn.exe," wide //weight: 1
        $x_1_9 = "wscntfy.exe,wuauclt.exe," wide //weight: 1
        $x_1_10 = "kav32.exe,kpfwsvc.exe,kpfw32.exe," wide //weight: 1
        $x_1_11 = "rfwsrv.exe,sched.exe,avast.exe,guard.exe" wide //weight: 1
        $x_1_12 = "\\Pack.vbp" wide //weight: 1
        $x_1_13 = "\\killvv.sys" wide //weight: 1
        $x_1_14 = "cls_Driver" ascii //weight: 1
        $x_1_15 = {33 00 36 00 30 00 73 00 61 00 66 00 65 00 62 00 6f 00 78 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_16 = {73 00 61 00 66 00 65 00 62 00 6f 00 78 00 54 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = {33 00 36 00 30 00 54 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = {33 00 36 00 30 00 53 00 61 00 66 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_19 = {52 00 61 00 76 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_20 = {61 00 76 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_21 = {43 00 43 00 65 00 6e 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_22 = {52 00 61 00 76 00 6d 00 6f 00 6e 00 44 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_23 = {52 00 61 00 76 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_24 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" wide //weight: 1
        $x_1_25 = "Wscript.Shell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 14 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CW_2147612070_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CW"
        threat_id = "2147612070"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e6 03 75 11 8b 5d 10 66 01 da 6b d2 ?? c1 ca ?? f7 d2 89 55 10 30 10 40 c1 ca ?? e2 e0 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e6 03 75 0f 8b 5d 10 66 01 da 6b d2 ?? c1 c2 ?? 89 55 10 30 10 40 c1 ca ?? e2 e2 c9}  //weight: 1, accuracy: Low
        $x_1_3 = {83 e6 03 75 12 8b 5d 10 66 01 da 6b d2 ?? 66 f7 (d2|da) c1 (c2|ca) ?? 89 55 10 30 10 40 c1 ca ?? e2 df c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_CX_2147612241_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CX"
        threat_id = "2147612241"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b3 02 41 b0 10 e8 ?? 00 00 00 10 c0 0f 83 f3 ff ff ff 0f 85 ?? 00 00 00 aa e9 ?? ff ff ff e8 ?? 00 00 00 29 d9 0f 85 ?? 00 00 00 e8 ?? 00 00 00 e9 [0-32] 9c [0-16] 9d [0-16] 9c [0-16] 9d [0-16] 9c [0-16] 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CZ_2147612671_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CZ"
        threat_id = "2147612671"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 08 00 00 00 2d 00 10 00 00 c7 00 01 00 00 00 64 2b 05 08 00 00 00 05 ?? ?? ?? ?? ff e0 64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 48 30 50 31 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {80 c3 30 38 19 75 05 41 41 42 eb e9 58 8b 00 eb d9 58 8b 40 18 50 eb 0d 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 00 00 00 00 31 d2 31 c0 56 80 3e 00 74 0a a6 74 f8 ae 75 fd 5e 42 eb f0 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_DA_2147612705_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DA"
        threat_id = "2147612705"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 01 00 00 00 c3 c3 60 8b 74 24 24 8b 7c 24 28 fc b2 80 33 db a4}  //weight: 1, accuracy: High
        $x_1_2 = {03 c2 ff e0 b1 15 00 00 60 e8 00 00 00 00 5e 83 ee 0a 8b 06 03 c2 8b 08 89 4e f3 83 ee 0f 56 52 8b f0 ad ad 03 c2 8b d8 6a 04 bf 00 10 00 00 57 57 6a 00 ff 53 08 5a 59 bd 00 80 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_DF_2147614205_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DF"
        threat_id = "2147614205"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 8b 15 30 00 00 00 8b 52 0c 8b 52 0c 8b 12 8d 7d e7 8b 72 30 b9 0d 00 00 00 66 ad aa 66 0b c0 74 02}  //weight: 1, accuracy: High
        $x_1_2 = {b9 04 00 00 00 0f 31 89 04 24 89 54 24 04 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_DI_2147616003_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DI"
        threat_id = "2147616003"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 57 56 53 e8 0d 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 68 70 65 86 b1 ?? ?? 00 00 00 ff d0 e8 17 00 00 00 52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 00 50 68 ff 1f 7c c9 e8 ?? 00 00 00 ff d0 0b c0 74 07 8c c9 0a ed 75 01 ?? e8 9d ff ff ff 8b 5c 24 fc 66 33 db 8b c3 03 40 3c 0f b7 50 14 8d 54 10 18 8b 42 34 03 c3 05 ?? ?? 00 00 8b cb 41 50 51 68 2f 6f 06 10 e8 ?? 00 00 00 54 54 6a 40 ff 72 30 ff 72 34 01 1c 24 ff d0 58 59 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_DN_2147616769_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DN"
        threat_id = "2147616769"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {58 ff d0 40 e8 00 00 00 00 2d ?? ?? ?? ?? 01 04 24 ff 14 24 2d ?? ?? ?? ?? 83 7d f4 00 75 05}  //weight: 3, accuracy: Low
        $x_3_2 = {58 ff d0 40 e8 00 00 00 00 2d ?? ?? ?? ?? 01 04 24 8b 04 24 ff d0 2d ?? ?? ?? ?? 83 7d f4 00 75 05}  //weight: 3, accuracy: Low
        $x_1_3 = {0f b7 45 f0 85 c0 74 08 6a 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f 00 45 f0}  //weight: 1, accuracy: High
        $x_2_5 = {e8 00 00 00 00 58 25 00 f0 ff ff 05 00 12 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_DP_2147617366_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DP"
        threat_id = "2147617366"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 4c 30 0f e8}  //weight: 2, accuracy: High
        $x_1_2 = {4c 81 f9 33 32 04 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {4c 81 fa 22 01 00 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {4c 4c f3 a6 e8}  //weight: 1, accuracy: High
        $x_1_5 = {72 6f 74 65 [0-4] e8}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 8d 80 4e 6c 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {4c 8d 88 00 60 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_DR_2147617654_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DR"
        threat_id = "2147617654"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 25 00 00 ff ff 66 8b 00 66 35 de c0 66 3d 93 9a 74 07 2d 00 00 01 00 eb e7 25 00 00 ff ff 89 45 fc 8b 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_DS_2147617680_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DS"
        threat_id = "2147617680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d 0c 0b (0f|??) 84 ?? ?? 00 00 06 00 81 (e8|2d|ff)}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fb 7c 00 00 00 (74|??) 06 00 81 (e8|2d|ff)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_DT_2147617745_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DT"
        threat_id = "2147617745"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 6f 74 65 [0-4] e8}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f9 33 32 04 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {81 fa 22 01 00 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 04 f3 a6 e8}  //weight: 1, accuracy: High
        $x_2_5 = {83 c4 04 30 0f e8}  //weight: 2, accuracy: High
        $x_1_6 = {8d 80 22 6c 00 00 e8}  //weight: 1, accuracy: High
        $x_1_7 = {8d 88 00 60 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_DU_2147618146_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DU"
        threat_id = "2147618146"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 6a 00 68 ?? 3a 5c ?? 54 ff d0 83 c4 08 83 f8 01 75 01 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_DX_2147618209_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DX"
        threat_id = "2147618209"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 5e 81 e9 ?? ?? ?? ?? 8b 56 40 53 81 e1 ?? ?? ?? ?? 66 2b d2 66 c1 cf 09 52 57 66 83 ?? ?? a1 ?? ?? ?? ?? 03 14 24 ff d0 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d0 59 ba ?? ?? ?? ?? f7 d2 8b b2 4c 00 00 00 21 ef f7 d2 41 29 ef 8b 01 81 f2 bd a8 46 0d 29 f0 85 c0 75 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_DQ_2147618297_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DQ"
        threat_id = "2147618297"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 25 00 00 ff ff 66 8b 00 66 35 ?? ?? 66 3d ?? ?? 74 07 2d 00 00 01 00 eb ?? 25 00 00 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_DZ_2147618354_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DZ"
        threat_id = "2147618354"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 01 00 00 00 c3 31 ff 89 e5 83 ec ?? 8d (55|5d|4d) [0-26] ff 15 ?? ?? ?? ?? 31 (d2|db|c9) 88 (c2|c3|c1) 89 ec 01 (d7|df|cf) 81 ef ?? 00 00 00 81 ff ?? ?? ?? ?? 7c (a0|2d|e0) [0-10] 6a 40 68 00 30 00 00 68 ?? ?? ?? 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_DW_2147618460_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.DW"
        threat_id = "2147618460"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 de 81 c8 ?? ?? ?? ?? 8b 4e 2c 53 48 66 33 c9 c1 f8 1d 51 90 29 c0 8b 15 ?? ?? ?? ?? 41 ff d2}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d2 59 ba ?? ?? ?? ?? f7 d2 8b 3a f7 d0 4a 41 21 d6 8b 01 81 ea a5 6a cd 83 31 f8 85 c0 75 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_EA_2147618582_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.EA"
        threat_id = "2147618582"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 45 c8 68 00 00 00 f0 6a 01 6a 00 6a 00 50 ff 15}  //weight: 10, accuracy: High
        $x_1_2 = {c7 45 e3 4b 65 72 6e be 54 3f f0 bc f7 d2 ba 37 0d e2 26 33 da 8b d6 c7 45 e7 65 6c 33 32 8d 15 fe 7f 8b 24 c1 c7 06 b9 a0 cd fc c6 8d 3d a6 1d 0b 24 c1 c3 1d c7 45 eb 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 cc 56 69 72 74 c1 ef 00 81 c6 1d e7 82 16 bf ed f4 24 94 c7 45 d0 75 61 6c 50 81 c3 ec c8 02 ac 81 c2 30 0a 7a bc 87 ce c7 45 d4 72 6f 74 65 33 fa 89 fe c7 45 d8 63 74 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_EI_2147619190_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.EI"
        threat_id = "2147619190"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 68 ?? ?? ?? 00 68 00 30 40 00 ff 15 ?? 20 40 00 68 00 30 40 00 33 ?? 33}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 8d 45 e8 50 8d 45 ec 50 ff 15 ?? 20 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_EQ_2147619834_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.EQ"
        threat_id = "2147619834"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 24 d6 01 00 01 11 2b 1d ?? ?? ?? ?? 83 c1 48 83 e9 44}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 28 78 00 00 03 3d ?? ?? 40 00 2b 1d ?? ?? 40 00 03 3d ?? ?? 40 00 81 c0 c9 27 00 00 03 3d ?? ?? 40 00 29 01 03 5c 24 20 77 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ER_2147621044_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ER"
        threat_id = "2147621044"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb 04 00 00 00 83 eb 02 ba 15 12 40 00 f7 d3 f7 db 81 fc 54 45 02 00 30 1a 83 ea 05 90 83 c2 06 81 fa 15 1a 41 00 75 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ER_2147621044_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ER"
        threat_id = "2147621044"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 00 8b 40 08 89 45 ?? 8b 45 ?? 25 00 00 ff ff 81 38 4d 5a ?? ?? 74 ?? 2d 00 00 01 00 eb ?? 89 45 ?? e8 00 00 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_FB_2147621138_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FB"
        threat_id = "2147621138"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 1c 61 c2 08 00 55 1c 8b ec 83 83 28 80 65 ff 80 53 56 57 00 6a 01 33 f6 81 7d 0c d8 70 7c e0 5b 1c 89 75 f8 cc 5d f0 06 e8 81 ec 03 dc 00 1e f4 73 07 6a 02 e9 41 63 08 38 8b 7d a8 b9 36 1f ce 10 b8 0c 04 0a 83 01 ca ff f3 ab 8b 45 10 cc 4d 14 63 89 0c 03 c1 78 0a d8 1d 5e 0c 33 30 c9 3b 16 0f 84 13 a3 31 79 1c 0f b6 38 c1 e6 61 0b f7 40 41 86 37 83 f9 05 59 33 7c df 52 20 df 2c 84 7d 70 1c 0c 0f 86 ef 07 50 eb 50 03 82 5b cc bc f4 30 f8 c3 9e 08 83 e7 1d 9c e0 04 06 c7 81 fa 34 e0 01 3c 8d 34 1a 73 21 b5 22 55 be 07 24 4d 41 18 c1 e1 08 cd e2 86 b0 cb 40 89 1e c7 a9 8b 06 21 da c1 eb fc 0f af 18 d8 39 5d 3e 83 80 67 01 50 bf 0a 82 b0 b0 2b f8 59 0c c1 ef 05 03 b2 d3 c7 6c 45 ff b5 e8 0a 82 3e 97 03 08 8d 04 40 28 c8 0a 82 3d f8 07 0a 84 30 d8 88 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_EB_2147621491_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.EB"
        threat_id = "2147621491"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 45 e0 73 73}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 e2 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 01 68 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 03 80 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {c7 45 e3 4b 65 72 6e}  //weight: 1, accuracy: High
        $x_1_6 = {c7 45 eb 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_7 = {c7 45 cc 56 69 72 74}  //weight: 1, accuracy: High
        $x_1_8 = {c7 45 d4 72 6f 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule VirTool_Win32_Obfuscator_EM_2147621589_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.EM"
        threat_id = "2147621589"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 3a 2f 2f [0-64] 2f [0-22] 2e (65|6a)}  //weight: 10, accuracy: Low
        $x_10_2 = {50 52 0f 31 33 d0 01 55}  //weight: 10, accuracy: High
        $x_10_3 = {c7 04 24 40 00 00 00 e8 ?? ?? 00 00}  //weight: 10, accuracy: Low
        $x_10_4 = {04 24 8b 04 24}  //weight: 10, accuracy: High
        $x_1_5 = {04 24 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ff ff 8d}  //weight: 1, accuracy: Low
        $x_1_6 = {24 fc c7 04 24 ?? ?? ?? ?? e8 ?? ?? 00 00 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ET_2147622034_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ET"
        threat_id = "2147622034"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ad 33 c2 ab 83 (c6 (fd|fe|ff|00)|ee (00|01|02|03)) [0-24] c1 07 02 02 02 02 02 02 02 c2 03 c2 05 c2 0d ca 07 ca 0b ca 0d cb 0d}  //weight: 3, accuracy: Low
        $x_3_2 = {ad 33 c3 ab 83 (c6 (fd|fe|ff|00)|ee (00|01|02|03)) [0-24] c1 07 02 02 02 02 02 02 02 c2 03 c2 05 c2 0d ca 07 ca 0b ca 0d cb 0d}  //weight: 3, accuracy: Low
        $x_2_3 = {83 f8 09 0f 84 ?? 00 00 00 04 00 03 (c6|c7) 03 03 01 01 01 c3 c6 c7}  //weight: 2, accuracy: Low
        $x_1_4 = {8b 45 fc 0f b7 0a 69 c0 3f 00 01 00 03 c1}  //weight: 1, accuracy: High
        $x_1_5 = {94 c8 37 09 01 00 (b8|2d|bf)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_EU_2147622035_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.EU"
        threat_id = "2147622035"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 40 00 ff 15 ?? ?? 40 00 0b 00 8d 45 ?? 50 6a 40 68}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 30 00 10 ff 15 ?? ?? 00 10 0b 00 8d 45 ?? 50 6a 40 68}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 30 14 13 ff 15 ?? ?? 14 13 0b 00 8d 45 ?? 50 6a 40 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_EJ_2147622429_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.EJ"
        threat_id = "2147622429"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 ca ba 04 00 00 00 83 c7 03 83 c7 15 83 fa 04 75 ee ff d2 51}  //weight: 1, accuracy: High
        $x_1_2 = {bb 5b 22 2d 31 01 f9 03 15 3e 93 40 00 81 fb 5b 22 2d 31 75 eb ff 15 20 80 40 00 89 cf}  //weight: 1, accuracy: High
        $x_1_3 = {83 eb 33 89 da b9 02 00 00 00 51 ff 15 1c 80 40 00 8b 3c 24 5f 39 d3 74 03 83 ef 0b ff 15 00 80 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_EO_2147622607_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.EO"
        threat_id = "2147622607"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 d3 5c 5c 2e 5c}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 d7 6d 61 69 6c}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 db 73 6c 6f 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_IS_2147622764_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IS"
        threat_id = "2147622764"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 8d 45 e8 50 8d 45 ec 50 ff 15 ?? 20 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc 00 30 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 8d 45 e4 50 6a 0c 8d 45 f0 50 ff 75 e8 ff 15 ?? 20 40 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 8d 45 e4 50 6a 19 8d 45 f4 50 ff 75 ec ff 15 ?? 20 40 00}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 45 e4 50 6a 40 68 ?? ?? ?? 00 68 00 30 40 00 ff 15 ?? 20 40 00 68 00 30 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_IT_2147623102_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IT"
        threat_id = "2147623102"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@*\\AY:\\zeus\\downloadersource\\My_Crypter_vbcrypter\\vbcrypter\\newStubMy\\myprog.vbp" wide //weight: 1
        $x_1_2 = "@aSplitter;C:\\WINDOWS\\system32;C:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_EP_2147623116_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.EP"
        threat_id = "2147623116"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 0d 30 00 00 00 [0-10] 8b 91 90 00 00 00 81}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0a 39 c1 74 07 01 d9 42 31 c6 eb f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_EY_2147623749_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.EY"
        threat_id = "2147623749"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 cf 0f a4 f7 64 0f a5 f7 47 11 e9 b9 a4 d7 3e 09 3a c6 f2 d1 d1 0f b7 fd 8b cd c7 c1 04 b7 9e e9 0f be c6 8b cd 0f a4 f7 b4 f7 c3 44 f7 de 29 38 f0 0f c1 c8 f2 f7 c3 84 37 1e 69 8a c6 47 47 eb 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_FH_2147624380_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FH"
        threat_id = "2147624380"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 c2 1c 00 00 c0}  //weight: 2, accuracy: High
        $x_2_2 = {66 81 7a fe cd 2e}  //weight: 2, accuracy: High
        $x_1_3 = {68 e4 a9 52 09}  //weight: 1, accuracy: High
        $x_1_4 = {68 3e f6 96 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_FI_2147625237_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FI"
        threat_id = "2147625237"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 2b 45 0c 03 45 d8 83 c0 0c ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {89 44 24 34 33 c0 ff 65}  //weight: 1, accuracy: High
        $x_1_3 = {8b 75 18 8b 5d 14 ff 65 f0}  //weight: 1, accuracy: High
        $x_4_4 = {b8 39 01 00 c0 eb 3f}  //weight: 4, accuracy: High
        $x_4_5 = {0f be 4d ff 33 c8 88 4d ff 8b 55 0c 8a 45 ff 88 02}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_FJ_2147625294_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FJ"
        threat_id = "2147625294"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f4 53 57 56 90 68 11 10 40 00 90 c3 90 0f 31 52 90 58 83 f8 0a 0f 82 24 00 00 00 90 ff 15 ?? ?? ?? ?? 52 64 a1 18 00 00 00 8b 40 30 66 8b 80 ac 00 00 00 81 04 24 56 10 40 00 66 29 04 24 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_FM_2147625503_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FM"
        threat_id = "2147625503"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b df 74 3a c7 45 f8 ?? ?? ?? ?? 81 45 f8}  //weight: 2, accuracy: Low
        $x_1_2 = {3b c7 59 74 02 ff d0 57 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {2b 45 10 33 cf 2b f1 83 7d fc 00 77 c2}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 00 ff ff 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_FN_2147625565_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FN"
        threat_id = "2147625565"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {81 04 39 01 00 00 00 81 3c 39 ff ff ff ff 0f 85 ec ff ff ff 81 c1 04 00 00 00 81 f9 10 00 00 00 0f 85 da ff ff ff}  //weight: 6, accuracy: High
        $x_6_2 = {39 00 00 00 fa 0f 85 (ec|f0) ff ff ff 81 c1 04 00 00 00 81 f9 10 00 00 00 0f 85 (da|de) ff ff ff}  //weight: 6, accuracy: Low
        $x_2_3 = {ff f5 89 e5 81 ec ?? 00 00 00 ff f6 [0-32] e8 00 00 00 00 58 81 e8 ?? ?? 40 00}  //weight: 2, accuracy: Low
        $x_1_4 = {81 7f 0c ff ff ff ff 0f 85}  //weight: 1, accuracy: High
        $x_1_5 = {47 80 34 31}  //weight: 1, accuracy: High
        $x_1_6 = {89 ad fc ff ff ff 80 34 31}  //weight: 1, accuracy: High
        $x_1_7 = {be 00 f0 7e 00}  //weight: 1, accuracy: High
        $x_1_8 = {81 f9 c0 03 00 00 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_FO_2147625627_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FO"
        threat_id = "2147625627"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 6e 0f b7 10 81 fa 4d 5a 00 00 75 63 03 40 3c 8b 08 81 f9 50 45 00 00 75 56 8b 50 74 8d 40 78 8d 04 d0}  //weight: 2, accuracy: High
        $x_2_2 = {59 49 e3 02 eb ?? 53 30 14 24 30 54 24 01 30 54 24 02 30 54 24 03}  //weight: 2, accuracy: Low
        $x_1_3 = {75 16 8b 42 28 01 c6 8b 3d ?? ?? ?? ?? 29 f7 83 ef 05 c6 06 e9 89 7e 01}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 14 02 8a 02 32 05 ?? ?? ?? ?? 88 02 ff 45 fc e2 e6}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 78 04 81 3b 03 00 00 80 74 07 b8 00 00 00 00 eb 0b ff 87 b8 00 00 00 b8 ff ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_FQ_2147625857_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FQ"
        threat_id = "2147625857"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 65 61 70 57 61 6c 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 c0 01 00 00 00 ff c8}  //weight: 1, accuracy: High
        $x_1_3 = {81 ef 01 00 00 00 47}  //weight: 1, accuracy: High
        $x_1_4 = {81 ed 01 00 00 00 45}  //weight: 1, accuracy: High
        $x_1_5 = {81 c2 01 00 00 00 ff ca}  //weight: 1, accuracy: High
        $x_1_6 = {81 f9 44 03 00 00 0f 85 33 00 [0-48] 80 34 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_FR_2147625861_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FR"
        threat_id = "2147625861"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 fb ff ee ff ee [0-10] 74 [0-10] 81 fb ee ff ee ff [0-10] 74 ?? [0-10] c3}  //weight: 10, accuracy: Low
        $x_1_2 = {b9 05 00 00 00 [0-11] f7 f1}  //weight: 1, accuracy: Low
        $x_3_3 = {64 8b 1d 30 00 00 00 [0-10] 8b 9b 90 00 00 00 [0-10] 8b 1b [0-32] 8b 5b 08}  //weight: 3, accuracy: Low
        $x_2_4 = {66 0f 1f 84 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_FS_2147625895_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FS"
        threat_id = "2147625895"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 75 ?? (58|8b 04 24 83) 89 c2 ff e2 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f9 00 75 ?? 58 ff e0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_GA_2147626425_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GA"
        threat_id = "2147626425"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 50 51 66 58 59 b0 ?? b3 ?? 00 ?? 66 b8 ?? ?? b7 ?? 66 01 d8 b9 ?? ?? ?? ?? 89 d0 e2 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {66 31 c0 30 c0 30 db 30 ff b9 ?? ?? ?? ?? e2 fe 31 c0 31 c9 31 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_FW_2147626501_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FW"
        threat_id = "2147626501"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f c5 ca 04}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 2a a0 00 00 0f 85 4b f9 ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {64 8b 05 18 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 8b 0d 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {8a 42 ff eb}  //weight: 1, accuracy: High
        $x_1_6 = {81 f8 2e 00 00 c0 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_FW_2147626501_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FW"
        threat_id = "2147626501"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 1b 56 ad f6}  //weight: 1, accuracy: High
        $x_1_2 = {68 c1 09 69 c7}  //weight: 1, accuracy: High
        $x_1_3 = {66 81 38 4d 5a}  //weight: 1, accuracy: High
        $x_1_4 = {8d 9b 80 00 00 00 8b 1b}  //weight: 1, accuracy: Low
        $x_1_5 = {66 8e e8 66 8c e8}  //weight: 1, accuracy: High
        $x_1_6 = {66 8f 40 16 0f b7 4b 06}  //weight: 1, accuracy: Low
        $x_1_7 = {35 da 8c a9 89}  //weight: 1, accuracy: High
        $x_1_8 = {35 82 fa 50 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_FY_2147626701_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.FY"
        threat_id = "2147626701"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {cd 2a 39 c8 74 fa}  //weight: 1, accuracy: High
        $x_1_2 = {b8 aa fc 0d 7c e8}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 ff d0 01 85 ?? ?? ?? ?? 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_GB_2147626782_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GB"
        threat_id = "2147626782"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba fc fd fe ff}  //weight: 1, accuracy: High
        $x_1_2 = {b8 f8 f9 fa fb}  //weight: 1, accuracy: High
        $x_1_3 = {bb f4 f5 f6 f7}  //weight: 1, accuracy: High
        $x_1_4 = {bf f0 f1 f2 f3}  //weight: 1, accuracy: High
        $x_1_5 = {2d 10 10 10 10 81 eb 10 10 10 10 81 ea 10 10 10 10}  //weight: 1, accuracy: High
        $x_2_6 = {fe c2 30 07 fe c9 75 cd}  //weight: 2, accuracy: High
        $x_2_7 = {ff 0c 24 ff 0c 24 81 2c 24 29 e7 97 00 ff 0c 24 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_GC_2147626892_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GC"
        threat_id = "2147626892"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e9 0c ff ff ff ?? ?? ?? ?? 55 8b ec 53 56 57 8b 75 08 8b 7d 0c 8b 5d 10 33 d2 03 df a4 3b fb 73 4a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_GD_2147626893_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GD"
        threat_id = "2147626893"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 04 f8 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 85 08 f8 ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {3d 88 77 00 00 e9}  //weight: 1, accuracy: High
        $x_1_4 = {3d ba 77 00 00 0f 83}  //weight: 1, accuracy: High
        $x_1_5 = {3d 82 78 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_GD_2147626893_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GD"
        threat_id = "2147626893"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 1b 00 00 00 ?? 8b 4c 24 0c 8b 81 a8 00 00 00 89 81 a0 00 00 00 83 81 b8 00 00 00 07 33 c0 c3 33 c0 ff 04 24 64 ff 30 64 89 20 cc e8 3c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 1d 00 00 00 8b 4c 24 0c 8b 91 b0 00 00 00 4a 75 07 83 81 b8 00 00 00 03 89 91 b0 00 00 00 33 c0 c3 33 c9 64 ff 31 64 89 21 ?? 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_GG_2147627683_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GG"
        threat_id = "2147627683"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 6e c0 0f 6e ca 0f 73 f0 [0-2] 0f ef c1 0f 6e cf 0f 7e ce ad 0f 6e d0 ad 0f 6e d8 0f 73 f2 [0-2] 0f ef d3 0f ef d0 0f 7e d0 ab 0f 73 d2 [0-2] 0f 7e d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_GH_2147627730_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GH"
        threat_id = "2147627730"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 00 00 00 8b ?? 30 8b ?? 54 8b ?? 04 8b ?? 04 8b ?? 04 81 ?? 20 00 20 00 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_GI_2147627897_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GI"
        threat_id = "2147627897"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 b9 e8 03 00 00 f7 f1 a3 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f0 81 3a 50 45 00 00 74 07 33 c0 e9 ?? ?? 00 00 6a 04 68 00 20 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7d ec 08 73 39 83 7d ec 04 75 06 83 7d f4 7f 76 2d 83 7d ec 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_GK_2147627915_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GK"
        threat_id = "2147627915"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 e8 01 ca 01 eb 89 d8 68 7c ea 00 00 ff 15 ?? ?? 41 00 68 8b 30 41 00 8d 14 30 8d 83 89 00 00 00 5a 8d 14 08 8d 04 10 68 06 b6 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_GL_2147628012_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GL"
        threat_id = "2147628012"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 00 bb 04 00 00 00 83 eb 02 ba 74 12 40 00 f7 d3 f7 db 81 fc 54 45 02 00 30 1a 83 ea 03 90 83 c2 04 81 fa 74 2e 40 00 75 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_GM_2147628039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GM"
        threat_id = "2147628039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 f6 83 c0 00 83 e8 00 32 c2 83 eb 00 83 c3 00 aa 83 fa 63 02 d1 8b d2}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 30 6b c9 21 33 ce ff c0 68 ff ff ff ff 01 54 a4 00 5a 0f 85 e6 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_GN_2147628093_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GN"
        threat_id = "2147628093"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 0c 8b 45 fc b9 ?? ?? ?? ?? 0f b6 30 6b c9 21 33 ce}  //weight: 10, accuracy: Low
        $x_10_2 = {6b d2 42 0f b6 01 33 d0 41 [0-6] ff 4c 24 04 0f 85}  //weight: 10, accuracy: Low
        $x_10_3 = {8b 45 fc 8b d7 b9 ?? ?? ?? ?? 0f b6 30 6b c9 21 33 ce}  //weight: 10, accuracy: Low
        $x_1_4 = {3b 4d 14 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {3b 45 14 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_GO_2147628129_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GO"
        threat_id = "2147628129"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 80 90 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff b0 90 00 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {25 ee ee ee ee}  //weight: 2, accuracy: High
        $x_2_4 = {2e 00 00 c0 02 00 81 (e8|f8)}  //weight: 2, accuracy: Low
        $x_3_5 = {0f 01 e0 41 83 f9 02}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_GQ_2147628193_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GQ"
        threat_id = "2147628193"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {79 fc fc 31 c9 89 c8 31 d2 f6 35 ?? ?? ?? ?? 86 e0 30 e4 02 80 ?? ?? ?? ?? 02 81 ?? ?? ?? ?? 00 05}  //weight: 2, accuracy: Low
        $x_2_2 = {64 8b 15 18 00 00 00 8b 52 30 8b 52 54 8b 52 04 8b 52 04 8b 52 08 83 ea 49}  //weight: 2, accuracy: High
        $x_1_3 = {64 a1 30 00 00 00 8b 80 90 00 00 00 8b 00 8b 40 08 2d ff ee ff ee}  //weight: 1, accuracy: High
        $x_1_4 = {83 ef 03 30 12 f7 d2 f7 da 81 fa ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_5 = {30 1a 83 ea ?? [0-1] 83 c2 ?? 81 fa ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_6 = {40 30 02 f7 d2 f7 da 81 fa ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_7 = {f7 d0 f7 d8 30 02 42 81 fa ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_8 = {40 30 02 42 81 fa ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_9 = {40 30 06 46 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_GS_2147628425_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GS"
        threat_id = "2147628425"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {32 c8 30 8a}  //weight: 4, accuracy: High
        $x_4_2 = {81 fa 00 a8 01 00 7d}  //weight: 4, accuracy: High
        $x_4_3 = {b9 07 00 00 00 f3 a5 66 a5 a4}  //weight: 4, accuracy: High
        $x_1_4 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_5 = "SetBkColor" ascii //weight: 1
        $x_1_6 = "SetBkMode" ascii //weight: 1
        $x_1_7 = "GetBkMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_GT_2147628466_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GT"
        threat_id = "2147628466"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 44 24 08 61 74 45 78}  //weight: 1, accuracy: High
        $x_1_2 = {81 44 24 08 70 6f 74 65}  //weight: 1, accuracy: High
        $x_1_3 = {81 44 24 04 73 61 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {81 44 24 04 00 00 6c 50}  //weight: 1, accuracy: High
        $x_1_5 = {81 04 24 54 69 72 74}  //weight: 1, accuracy: High
        $x_1_6 = {81 44 24 08 67 6e 67 57}  //weight: 1, accuracy: High
        $x_1_7 = {81 44 24 08 6c 53 74 72}  //weight: 1, accuracy: High
        $x_1_8 = {81 44 24 08 63 57 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {81 44 24 08 6e 68 6f 72}  //weight: 1, accuracy: High
        $x_1_10 = {81 44 24 04 51 65 6d 61}  //weight: 1, accuracy: High
        $x_1_11 = {81 04 24 4d 70 65 6e}  //weight: 1, accuracy: High
        $x_2_12 = {80 7c 24 04 56 0f 84}  //weight: 2, accuracy: High
        $x_1_13 = {81 44 24 08 76 57 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {81 44 24 04 4b 75 74 65}  //weight: 1, accuracy: High
        $x_1_15 = {81 44 24 08 71 73 00 00}  //weight: 1, accuracy: High
        $x_1_16 = {81 44 24 08 70 6f 63 65}  //weight: 1, accuracy: High
        $x_1_17 = {81 44 24 08 6d 64 65 50}  //weight: 1, accuracy: High
        $x_1_18 = {81 44 24 04 76 69 74 43}  //weight: 1, accuracy: High
        $x_1_19 = {81 04 24 45 65 74 45}  //weight: 1, accuracy: High
        $x_1_20 = {81 04 24 52 65 72 6d}  //weight: 1, accuracy: High
        $x_3_21 = {80 7c 24 05 69 0f 84}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_GU_2147628507_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GU"
        threat_id = "2147628507"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 00 83 f8 58 [0-32] 0f b6 40 ff 83 f8 50 [0-32] 0f b6 40 fe 83 f8 55}  //weight: 2, accuracy: Low
        $x_1_2 = {68 00 40 00 00 68 00 04 00 00 6a 01 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 08 00 00 6a 08 ff 75 ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_GV_2147628522_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GV"
        threat_id = "2147628522"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 ee d1 e2 03 54 24 10 0f b7 02 c1 e0 02 03 44 24 08 8b 00 03 c3 8b 54 24 30 ff e2}  //weight: 3, accuracy: High
        $x_1_2 = {89 a2 35 8b 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = {13 04 18 5d 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 77 50 ff 77 34 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_GW_2147628604_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GW"
        threat_id = "2147628604"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 81 38 4d 5a 74 07 2d 00 00 01 00 eb f2 40 81 38 ff 75 18 8d 75 f7 81 78 04 45 10 ff 75 75 ee 48 80 38 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_GX_2147628621_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GX"
        threat_id = "2147628621"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 60 9c bb 34 27 00 00 50 89 f8 31 ff 5b 9d 61 9c 60 9c bb 34 27 00 00 50 89 f8 31 ff 5b 9d 61 bb 34 27 00 00 60 9c bb 34 27 00 00 50 89 f8 31 ff 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_GY_2147628676_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GY"
        threat_id = "2147628676"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 84 05 f8 fe ff ff}  //weight: 3, accuracy: High
        $x_1_2 = {68 ff ff ff ff 01 (44|4c|54|5c|64|6c|74|7c) (24|64|a4|e4) 00 (8f (c0|c1|c2|c3|c4|c5|c6|c7)|(58|59|5a|5b|5c|5d|5e|5f))}  //weight: 1, accuracy: Low
        $x_1_3 = {68 ff ff ff ff 01 (04|0c|14|1c|24|2c|34|3c) (24|64|a4|e4) (8f (c0|c1|c2|c3|c4|c5|c6|c7)|(58|59|5a|5b|5c|5d|5e|5f))}  //weight: 1, accuracy: Low
        $x_1_4 = {68 ff ff ff ff 01 (84|8c|9c|94|ac|a4|b4|bc) (24|64|a4|e4) 00 00 00 00 (8f (c0|c1|c2|c3|c4|c5|c6|c7)|(58|59|5a|5b|5c|5d|5e|5f))}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_HA_2147628760_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HA"
        threat_id = "2147628760"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e8 10 83 c0 02 8d 80 ?? ?? ?? ?? ff e0}  //weight: 2, accuracy: Low
        $x_1_2 = {64 8b 15 18 00 00 00 41 52 [0-16] 5e 48 c7 46 14}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 46 14 38 37 36 34 01 f0}  //weight: 1, accuracy: High
        $x_2_4 = {0f 70 ca ff 0f 77}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_HB_2147628792_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HB"
        threat_id = "2147628792"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 dc c9 89 44 24 1c 61 9d ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 30 00 00 00 8b 40 18 8b 40 0c 83 f8 02}  //weight: 1, accuracy: High
        $x_1_3 = {2e 64 6c 6c 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HC_2147628803_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HC"
        threat_id = "2147628803"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 cd 2e eb 08 58 2d c4 2e eb 08 eb f4 86 e0 91 0f c9 81 e9 4c d9 01 00 03 ca eb 02 cc e9 ff d1 34 35 83 e0 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HF_2147628831_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HF"
        threat_id = "2147628831"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f2 83 c6 03 8b 09 8b d6 8b 09 21 da 8b 09}  //weight: 1, accuracy: High
        $x_1_2 = {8b 09 81 c1 ?? ?? ?? ?? 01 d3 51 01 f6 68 ?? ?? ?? ?? c7 85 f4 ff ff ff 21 ff ff ff 8b 5d f8 5b 81 e8 ?? ?? ?? ?? 8d 43 5c c1 eb 05 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HG_2147628863_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HG"
        threat_id = "2147628863"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 00 f0 ff ff 66 81 38 4d 5a 74 03 48 eb f1}  //weight: 1, accuracy: High
        $x_1_2 = {31 07 af e2 fb}  //weight: 1, accuracy: High
        $x_2_3 = {ac 3c 41 72 06 3c 5a 77 02 04 20 aa e2 f2 81 7d ?? 6b 65 72 6e 75 c7 81 7d ?? 65 6c 33 32 75 be 81 7d ?? 2e 64 6c 6c 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_HH_2147628880_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HH"
        threat_id = "2147628880"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d ec 8b 3f 83 ee ae 2b d3 c1 e7 08 03 75 f4 8b ce 81 c7 ?? ?? ?? ?? b9 04 00 00 00 01 f6 b9 ?? ?? ?? ?? 01 de 39 89 a4 00 00 00 74 ef 8b ca 57 68 ?? ?? ?? ?? be 51 ff ff ff 2b 75 f0 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HJ_2147628993_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HJ"
        threat_id = "2147628993"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d5 89 ee 81 f3 14 00 00 00 89 ee f7 d5 4d 75 ef 81 f3 13 00 00 00 81 f3 1e 00 00 00 33 1f ?? 89 dd 89 ed 89 2f 83 c7 02 47 47 ?? 81 c2 02 00 00 00 4a ?? 49 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HL_2147629044_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HL"
        threat_id = "2147629044"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 01 e0 03 c0}  //weight: 1, accuracy: High
        $x_1_2 = {ba 65 e7 f8 75 f2 02 00 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HM_2147629072_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HM"
        threat_id = "2147629072"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 28 f8 ff ff 8d 04 d0 8b 30 83 c6 10 83 68 04 10 ff 70 04 56 57 e8 63 ff ff ff 03 78 04 42 81 fa ?? ?? ?? ?? 75 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 07 33 45 10 88 07 47 49 85 c9 75 f2}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 0c 8b 04 b7 31 02 ff 32 ff 75 08 e8 dc ff ff ff 8b 55 10 31 02 8b 02 8b 4d 0c 51 8b 09 89 0a 59 89 01 4e 83 fe 01 77 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_HP_2147629361_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HP"
        threat_id = "2147629361"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 01 e0 03 c0 3d ?? ?? ?? ?? 72 ?? 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {a1 6c 02 fe 7f [0-6] 3c 06 74 ?? ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HP_2147629361_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HP"
        threat_id = "2147629361"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 7f 5d 89 7d 08 4e b9 03 6c 80 00 8d 3c 24 2b ca 01 f8 81 f3 ?? ?? ?? ?? 8b 1c 24 4f db e2 9b be ?? ?? ?? ?? 03 df 0f 01 e0 03 c0 3d 16 c6 00 00 72 08 8b 7d 08 ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HQ_2147629401_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HQ"
        threat_id = "2147629401"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 b9 ?? ?? ?? ?? [0-2] (f3|66) cf 64 8f 05 00 00 00 00 c9 (ff e0|50 c3)}  //weight: 1, accuracy: Low
        $x_1_2 = {50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 b9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? [0-2] f4 64 8f 05 00 00 00 00 83 c4 04 c9 (ff e0|50 c3)}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 0c 00 00 00 8b 14 04 8b 82 ?? 00 00 00 83 e8 01 89 82 ?? 00 00 00 75 0a 81 82 ?? 00 00 00 ?? 00 00 00 05 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 b9 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 0f 0b 64 8f 05 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_HR_2147629402_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HR"
        threat_id = "2147629402"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 61 6a 66 8b 05 ?? ?? ?? ?? ff d0 59 59 85 c0 0f 85 ?? ?? ?? ?? 83 7d 0c 04 0f 83 ?? ?? ?? ?? 0f b7 45 08 85 c0 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 61 6a 66 8b 05 ?? ?? ?? ?? ff d0 59 59 85 c0 0f 85 ?? ?? ?? ?? 57 ff d6 85 c0 0f 84 ?? ?? ?? ?? 83 7d 0c 04}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 61 6a 66 8b 04 ?? ?? ?? ?? ?? ff d0 59 59 85 c0 0f 85 ?? ?? ?? ?? 56 8b (05 ?? ?? ?? ??|04 ?? ?? ?? ?? ??) ff d0 85 c0 0f 84 ?? ?? ?? ?? 83 7d 0c 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_HS_2147629446_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HS"
        threat_id = "2147629446"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 01 e0 03 c0 3d ?? ?? 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HU_2147630037_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HU"
        threat_id = "2147630037"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7a 78 6a 74 ?? 80 7a 47 89 74 ?? 80 7a 49 3b 74 ?? cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HW_2147630243_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HW"
        threat_id = "2147630243"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 04 75 05 31 c9 83 ea 04 47 39 f8 75 e8}  //weight: 1, accuracy: High
        $x_1_2 = {ba 00 00 00 00 01 fa b8 ?? ?? ?? ?? 01 f8 89 c7 89 44 24 04 be ?? ?? ?? ?? 01 c6 80 38 00 75 05 8a 0a 88 08 42 40 39 c6 75 f1 e8 04 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_YA_2147630499_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YA"
        threat_id = "2147630499"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 3d dc 70 40 00 81 f7 ?? ?? ?? ?? 89 3d dc 70 40 00 31 0a 8b 1d 2b 70 40 00 81 cb ?? ?? ?? ?? 89 1d 2b 70 40 00 29 0a 81 2a ?? ?? ?? ?? f7 12 81 02 ?? ?? ?? ?? 81 32 ?? ?? ?? ?? 8b 35 14 72 40 00 31 d6 89 35 14 72 40 00 f7 12 c1 0a ?? 8b 3d 59 72 40 00 31 cf 89 3d 59 72 40 00 83 c2 04 48 0f 85 99 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_HY_2147630652_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.HY"
        threat_id = "2147630652"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 08 00 00 00 ?? ?? cd 2a ?? ?? cd 2a ?? ?? 74 fa ?? ?? ?? ?? cd 2a ?? ?? cd 2a ?? ?? 74 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_IB_2147631184_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IB"
        threat_id = "2147631184"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 00 50 01 00 92 e8 1f 00 00 00 8b 54 24 0c 8b 82 b0 00 00 00 48 75 09 6a f5 59 29 8a b8 00 00 00 89 82 b0 00 00 00 33 c0 c3 33 c9 64 ff 31 64 89 21 29 05 00 10 40 00 83 c4 08 f4 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_IC_2147631371_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IC"
        threat_id = "2147631371"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 00 00 00 27 02 00 83 1e 00 81 ?? (a0|2d|af|00|00|00|90|0a|1a|00|8b|90|01|01|24|0c)}  //weight: 1, accuracy: Low
        $x_1_2 = {64 ff 35 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 89 25 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 00 00 00 27 ?? ?? ?? ?? ?? 33 c0 c3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 8f 05 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ID_2147631415_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ID"
        threat_id = "2147631415"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 83 38 6a 0f 85}  //weight: 2, accuracy: High
        $x_2_2 = {80 38 c2 0f 85}  //weight: 2, accuracy: High
        $x_1_3 = {31 44 24 04 58 05 00 b8}  //weight: 1, accuracy: Low
        $x_1_4 = {81 e9 34 12 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {81 38 8b ff 8b ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_IE_2147631425_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IE"
        threat_id = "2147631425"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 04 c7 04 24 40 00 00 00 68 00 30 00 00 68 ?? ?? ?? ?? 83 ec 04 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 8b 0c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d6 55 68 00 80 00 00 6a 00 56 ff 15 ?? ?? ?? ?? 59 85 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_IF_2147631706_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IF"
        threat_id = "2147631706"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 ee 6a 04 68 10 00 81 34 ?? ?? ?? ?? ?? 83 c1 04 81 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 58 3c 66 8b 44 03 16 66 25 00 20 74 05 e8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_IG_2147631755_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IG"
        threat_id = "2147631755"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 07 d3 ca b9 ?? c7 47 04 ?? ?? ?? ad c7 47 08 33 c2 d3 c2 c7 47 0c ab e2 f8 ff c6 47 10 e3}  //weight: 1, accuracy: Low
        $x_1_2 = {ad 33 c2 d3 c2 ab e2 f8 ff ?? ?? ?? ?? ?? c3 (16 00 d3|15 00 d3 ca)}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 07 ad 33 c2 d3 c7 47 04 c2 ab e2 f8 66 c7 47 08 ff e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_IH_2147631938_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IH"
        threat_id = "2147631938"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 47 66 8b 17 31 f6 81 c8 ?? ?? ?? ?? 83 e8 ?? 81 e8 ?? ?? ?? ?? 0b b5 a8 fd ff ff 46 85 f6 74 1c 31 c0 23 85 c8 fe ff ff 2b 85 e0 fe ff ff 46 31 c6 29 f0 2b 85 a4 fe ff ff 21 45 90 09 c6 81 ea ?? ?? ?? ?? 75 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_II_2147632289_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.II"
        threat_id = "2147632289"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 24 14 02 d2 02 d2 c0 fb 04 0a da 8b 54 24 24 88 1c 16 8a 54 24 14 8a d8 c0 e2 04 c0 fb 02 83 c6 01 0a da}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 39 0f b6 88 ?? ?? ?? ?? 03 ce 03 d1 8a 88 ?? ?? ?? ?? 81 e2 ff 00 00 00 8b f2 0f b6 96 ?? ?? ?? ?? 88 90}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 64 24 00 8b 1d ?? ?? ?? ?? e8 15 ff ff ff 32 44 3e 10 83 c7 01 88 44 3b ff 8b 0d ?? ?? ?? ?? 83 c1 f0 3b f9 72 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_IJ_2147632394_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IJ"
        threat_id = "2147632394"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c9 c9 64 a1 00 00 00 00 8b e0}  //weight: 10, accuracy: High
        $x_1_2 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 68 ?? ?? ?? ?? 33 c0 f7 f0 07 00 50 51 68}  //weight: 1, accuracy: Low
        $x_1_3 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 68 ?? ?? ?? ?? 33 c0 f7 f0 08 00 50 51 52 68}  //weight: 1, accuracy: Low
        $x_1_4 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 68 ?? ?? ?? ?? 33 c0 f7 f0 09 00 50 51 52 53 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_IK_2147632413_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IK"
        threat_id = "2147632413"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 46 08 8b 7e 20 8b 36 80 3f 6b 75 f3 80 7f 18 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 11 84 d2 74 08 0f be d2 83 c2 ?? eb 02 33 d2 88 11 41 80 39 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 40 04 75 c6 40 02 72 c6 40 06 6c c6 40 03 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_IK_2147632413_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IK"
        threat_id = "2147632413"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 54 24 08 89 c7 ff d7 50 ff d7 2b 04 24 85 c0 75 f4 58 e8 19 00 00 00 56 69 72 74}  //weight: 1, accuracy: High
        $x_1_2 = {ff 54 24 0c 83 ec 04 83 04 24 0a 50 ff 54 24 0c 95 89 68 10 50 83 44 24 f0 15 ff 74 24 f0}  //weight: 1, accuracy: High
        $x_1_3 = {5f 66 31 ff 8b 07 48 66 31 c0 81 38 4d 5a 90 00 75 f4 6a 70 68 53 6c 65 65 54 50 ff 57}  //weight: 1, accuracy: High
        $x_1_4 = {8b 40 3c 01 c8 89 c2 8b 98 c0 00 00 00 85 db 60 0f 84 ?? ?? ?? ?? e8 15 00 00 00 54 6c 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_IY_2147632459_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IY"
        threat_id = "2147632459"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 83 39 6a 0f 85}  //weight: 2, accuracy: High
        $x_1_2 = {31 44 24 04 58 05 00 b8}  //weight: 1, accuracy: Low
        $x_1_3 = {81 e9 34 12 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {81 38 8b ff 8b ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_IL_2147632836_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IL"
        threat_id = "2147632836"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 e8 02 fe 7f [0-8] 0b c0 6a 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_IM_2147632873_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IM"
        threat_id = "2147632873"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 83 cd ff e8 05 00 00 00 e9}  //weight: 10, accuracy: High
        $x_1_2 = {ff ff 00 c6 45 ?? 44 c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 65 c6 45 ?? 74 c6 45 ?? 65 c6 45 ?? 46 c6 45 ?? 69 c6 45 ?? 6c c6 45 ?? 65 c6 45 ?? 41 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {fe ff ff c6 45 ?? 44 c6 45 ?? 65 c6 45 ?? 6c c6 45 ?? 65 c6 45 ?? 74 c6 45 ?? 65 c6 45 ?? 46 c6 45 ?? 69 c6 45 ?? 6c c6 45 ?? 65 c6 45 ?? 41 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 08 89 4d ?? 8b 95 ?? ?? ?? ?? 8b 02 89 45 f8 8d 4d ?? 51 ff 55 00 89 45 ?? 8d 95 ?? ?? ?? ?? 52 8b 45 ?? 50 ff 55 f8 89 45 ?? 8d [0-5] 51 8b 55 04 52 ff 55 f8}  //weight: 1, accuracy: Low
        $x_1_5 = {ff ff 47 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 4c c6 85 ?? ?? ff ff 61 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 45}  //weight: 1, accuracy: Low
        $x_1_6 = {ff ff 74 c6 85 ?? ?? ff ff 54 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 6d c6 85 ?? ?? ff ff 70 c6 85 ?? ?? ff ff 50 c6 85 ?? ?? ff ff 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_IN_2147632956_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IN"
        threat_id = "2147632956"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 34 08 8b 34 b3 2b 74 82 10 33 34 82 56 8d 34 08 8b 7d fc 8d 3c b7 5e 89 37 8b 74 82 20 01 34 82 8b 74 82 30 01 74 82 10 40 83 f8 04 72 d1 83 c1 04 3b 4d 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_IO_2147633376_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IO"
        threat_id = "2147633376"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 f5 ff 00 00 01 f0 89 85 40 fd ff ff 89 85 c4 fd ff ff 89 ?? c7 85 d0 fd ff ff ?? 00 00 00 c7 85 d1 fd ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JC_2147633561_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JC"
        threat_id = "2147633561"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b d9 e2 fb b9 ?? ?? ?? ?? 5b e2 fd 59 51 b9 ?? ?? ?? ?? 53 8b d9 51 b9 ?? ?? ?? ?? 8b d9 e2 fc 59 5b e2 ef 59 06 00 51 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JD_2147633738_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JD"
        threat_id = "2147633738"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fb 00 50 80 7c 0f 84 ?? ?? ?? ?? 81 fb 2e 26 00 70 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {96 59 87 fd 74 1c 83 c7 02 e2 dc e9}  //weight: 1, accuracy: High
        $x_1_3 = {66 ad 86 c4 66 33 45 ?? 83 6d ?? ?? ff 45 ?? 66 ab e2 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_IU_2147633759_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IU"
        threat_id = "2147633759"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d0 32 02 42 b3 08 d1 e8 73 ?? 35 20 83 b8 ed fe cb 75 ?? e2}  //weight: 1, accuracy: Low
        $x_1_2 = {ad ad 03 c7 0f ba f0 1f 73 ?? 60 8b d8 e8 ?? ?? ?? ?? 61 eb ?? 01 10 e2}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 30 00 00 51 6a 00 68 4a 0d ce 09 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JE_2147633874_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JE"
        threat_id = "2147633874"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 13 3b c1 74 12 00 fe 7f}  //weight: 1, accuracy: Low
        $x_1_2 = {39 45 fc 74 ?? eb 11 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {66 81 3c 18 50 45 (75|0f 85) [0-6] 18 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_IW_2147635843_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.IW"
        threat_id = "2147635843"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 69 72 74 c7 45 ?? 75 61 6c 50 c7 45 ?? 72 6f 74 65 c7 45 ?? 63 74 45 78 c6 45 ?? 00 c6 45 ?? 6b c6 45 ?? 00 c6 45 ?? 65 c6 45 ?? 00 c6 45 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d1 c9 c3 ba ?? ?? ?? ?? 89 d1 31 d2 41 42 81 fa ?? ?? ?? ?? 75 f6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JG_2147636376_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JG"
        threat_id = "2147636376"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 03 76 3c 81 c6 a0 00 00 00 8b 36 81 fe 00 00 06 00 77 ?? cc}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 03 5b 3c 81 c3 a0 00 00 00 8b 1b 81 fb 00 00 06 00 77 ?? cc}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d0 03 52 3c 81 c2 a0 00 00 00 8b 12 81 fa 00 00 06 00 77 ?? cc}  //weight: 1, accuracy: Low
        $x_1_4 = {8b f8 03 7f 3c 81 c7 a0 00 00 00 8b 3f 81 ff 00 00 06 00 77 ?? cc}  //weight: 1, accuracy: Low
        $x_1_5 = {8b c8 03 49 3c 81 c1 a0 00 00 00 8b 09 81 f9 00 00 06 00 77 ?? cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_JH_2147636396_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JH"
        threat_id = "2147636396"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 54 6a 40 53 68 cc 1b 00 00 57 89 4d fc 89 55 c0 89 4d c4 89 45 cc 89 75 d0 89 7d d8 e8}  //weight: 1, accuracy: High
        $x_1_2 = {30 03 46 89 75 ec 3b 75 2c 72 b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JJ_2147637267_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JJ"
        threat_id = "2147637267"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 2c 24 10 81 04 24}  //weight: 10, accuracy: High
        $x_1_2 = {ff ff 8c 0c 24 03 00 68 ?? ?? ?? ?? ?? ?? ?? [0-22] c3}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 8c 1c 24 03 00 68 ?? ?? ?? ?? ?? ?? ?? [0-22] c3}  //weight: 1, accuracy: Low
        $x_1_4 = {ff ff 8c 24 24 03 00 68 ?? ?? ?? ?? ?? ?? ?? [0-22] c3}  //weight: 1, accuracy: Low
        $x_1_5 = {ff ff 8c 2c 24 03 00 68 ?? ?? ?? ?? ?? ?? ?? [0-22] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_JL_2147637282_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JL"
        threat_id = "2147637282"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 88 28 03 00 00 03 48 08}  //weight: 1, accuracy: High
        $x_1_2 = {c1 ea 02 83 44 24 20 04 68 f8 ff fd 7f eb}  //weight: 1, accuracy: High
        $x_1_3 = {29 4c 24 20 8b 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JL_2147637282_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JL"
        threat_id = "2147637282"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 4f 8a 27 88 66 ?? 88 07 e2 f5 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 03 43 3c 81 78 50 00 80 04 00 76}  //weight: 1, accuracy: High
        $x_1_3 = {50 33 c2 5a ab 83 e9 03 e2 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_JL_2147637282_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JL"
        threat_id = "2147637282"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 03 75 [0-2] b8 ?? ?? ?? ?? [0-2] [0-2] 8b 88 ?? ?? ?? ?? [0-2] [0-2] 03 88 ?? ?? ?? ?? [0-2] [0-2] 0f b6 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JL_2147637282_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JL"
        threat_id = "2147637282"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 4b 13 0b 80 ?? ?? 8b 88 b5 ec f2 ff ?? ?? 03 88 d5 ef f2 ff ?? ?? 0f b6 c9 ?? ?? 83 f9 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JL_2147637282_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JL"
        threat_id = "2147637282"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 74 33 fe c1 e6 02 03 77 1c 03 f3 ad 03 c3 59 5f 2b f8}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 74 33 fe 0f b7 36 c1 e6 02 03 77 1c 03 f3 ad 03 c3 59 5f 2b f8}  //weight: 10, accuracy: Low
        $x_10_3 = {8b 36 0f b7 f6 c1 e6 02 03 77 1c 03 f3 ad 03 c3 59 5f 2b f8}  //weight: 10, accuracy: Low
        $x_10_4 = {0f b7 f6 c1 e6 02 03 77 1c 03 f3 ad 03 c3 59 5f 2b f8}  //weight: 10, accuracy: Low
        $x_1_5 = {66 81 fa 4d 5a 8b c2 74}  //weight: 1, accuracy: Low
        $x_1_6 = {66 81 ea 4d 5a 92 74}  //weight: 1, accuracy: Low
        $x_1_7 = {51 8b c8 f3 a4}  //weight: 1, accuracy: High
        $x_1_8 = {51 8b c8 eb f3 a4}  //weight: 1, accuracy: Low
        $x_1_9 = {01 42 04 2b c8 73}  //weight: 1, accuracy: High
        $x_1_10 = {01 42 04 2b c8 eb 73}  //weight: 1, accuracy: Low
        $x_1_11 = {01 42 04 eb 2b c8 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_JL_2147637282_5
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JL"
        threat_id = "2147637282"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 07 83 c0 03 d3 c8 2b c3 83 ea 01 ab 85 d2 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 03 d3 c8 2b c3 83 ea 01 ab 85 d2 75}  //weight: 1, accuracy: Low
        $x_1_3 = {83 e9 04 75 51 [0-4] [0-4] ad [0-4] [0-4] b9 ?? ?? ?? ?? [0-4] [0-4] 83 c0 ?? [0-4] [0-4] d3 c8 [0-4] [0-4] 2b c2 [0-4] [0-4] ab [0-4] [0-4] 59}  //weight: 1, accuracy: Low
        $x_1_4 = {83 e9 04 eb 75 51 [0-4] [0-4] ad [0-4] [0-4] b9 ?? ?? ?? ?? [0-4] [0-4] 83 c0 ?? [0-4] [0-4] d3 c8 [0-4] [0-4] 2b c2 [0-4] [0-4] ab [0-4] [0-4] 59}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 07 d3 c8 [0-4] [0-4] 2b c3 [0-4] [0-4] 83 ea 01 [0-4] [0-4] ab [0-4] [0-4] 75}  //weight: 1, accuracy: Low
        $x_1_6 = {83 e9 04 75 51 [0-4] [0-4] ad [0-4] [0-4] b9 ?? ?? ?? ?? [0-4] [0-4] 83 c0 ?? [0-4] [0-4] 2b c2 [0-4] [0-4] ab [0-4] [0-4] 59}  //weight: 1, accuracy: Low
        $x_1_7 = {83 e9 04 eb 75 51 [0-4] [0-4] ad [0-4] [0-4] b9 ?? ?? ?? ?? [0-4] [0-4] 83 c0 ?? [0-4] [0-4] 2b c2 [0-4] [0-4] ab [0-4] [0-4] 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_JL_2147637282_6
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JL"
        threat_id = "2147637282"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 00 00 fe 7f 8b 02 8b 8a 20 03 00 00 03 c8 8b 07 c1 e9 02}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 00 00 fe 7f 8b 0a 8b 07 03 8a 20 03 00 00 c1 e9 02}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 00 00 fe 7f 8b 8a 20 03 00 00 8b 07 03 0a c1 e9 02}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 00 00 fe 7f 8b 88 20 03 00 00 03 08 c1 e9 02 8b 07}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 00 fe 7f [0-4] [0-4] 8b 04 24 [0-4] [0-4] 8b 88 20 03 00 00 [0-4] [0-4] 03 08 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 8b 07}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 88 28 03 00 00 [0-4] [0-4] 03 48 08 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 8b 07 [0-4] [0-4] 0f be c9 [0-4] [0-4] 33 c3}  //weight: 1, accuracy: Low
        $x_1_7 = {03 87 20 03 00 00 8b 0e 03 07 83 e0 7f 32 c8 33 cb 80 f9}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 89 30 03 00 00 [0-4] [0-4] 03 c8 [0-4] [0-4] 8b 07 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 33 c3 [0-4] [0-4] 0f be c9}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 81 00 ff 01 00 [0-4] [0-4] 8b 89 20 02 02 00 [0-4] [0-4] 03 c8 [0-4] [0-4] 8b 07 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 33 c3 [0-4] [0-4] 0f be c9}  //weight: 1, accuracy: Low
        $x_1_10 = {b8 00 00 fe 7f 8b 88 20 03 00 00 03 08 8b 07 0f be c9}  //weight: 1, accuracy: Low
        $x_1_11 = {8b 07 c1 e9 02 33 c3 0f be c9 33 c1 34 4d 75}  //weight: 1, accuracy: Low
        $x_1_12 = {8b 81 e3 3f 00 00 [0-4] [0-4] 8b 89 03 43 00 00 [0-4] [0-4] 03 c8 [0-4] [0-4] 8b 07 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 33 c3}  //weight: 1, accuracy: Low
        $x_1_13 = {8b 89 b0 cd 12 00 [0-4] [0-4] 8d 0c 08 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 8b c3 [0-4] [0-4] 0f be c9 [0-4] [0-4] 33 07}  //weight: 1, accuracy: Low
        $x_1_14 = {8b 89 c1 d0 0c 00 [0-4] [0-4] 8d 0c 08 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 8b c3 [0-4] [0-4] 0f be c9 [0-4] [0-4] 33 07}  //weight: 1, accuracy: Low
        $x_1_15 = {8b 89 6f 26 0d 00 [0-4] [0-4] 8d 0c 08 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 8b c3 [0-4] [0-4] 0f be c9 [0-4] [0-4] 33 07}  //weight: 1, accuracy: Low
        $x_1_16 = {8b 89 8a 84 c8 03 [0-4] [0-4] 8d 0c 08 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 8b c3 [0-4] [0-4] 0f be c9 [0-4] [0-4] 33 07}  //weight: 1, accuracy: Low
        $x_1_17 = {8b 89 27 48 32 00 [0-4] [0-4] 8d 0c 08 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 8b c3 [0-4] [0-4] 0f be c9 [0-4] [0-4] 33 07}  //weight: 1, accuracy: Low
        $x_1_18 = {8b 89 cb 14 77 00 [0-4] [0-4] 8d 0c 08 [0-4] [0-4] c1 e9 02 [0-4] [0-4] 8b c3 [0-4] [0-4] 0f be c9 [0-4] [0-4] 33 07}  //weight: 1, accuracy: Low
        $x_1_19 = {8d 0c 08 c1 e9 02 8b c3 0f be c9 33 07 33 c1 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_JK_2147637283_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JK"
        threat_id = "2147637283"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 ff b5 70 ff ff ff ff b5 64 ff ff ff ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {b8 00 04 00 00 31 d2 b9 36 07 03 00 f3 ab 8b 45 0c}  //weight: 1, accuracy: High
        $x_1_3 = {89 79 04 8d 8c 0e 08 02 00 00 c7 45 dc 08 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 3f c1 e1 08 09 f9 c1 e0 08 ff 45 f8 89 4d 0c e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_JK_2147637283_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JK"
        threat_id = "2147637283"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 f2 79 36 18}  //weight: 1, accuracy: High
        $x_1_2 = {68 33 00 32 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 23 f9 35 9d}  //weight: 1, accuracy: High
        $x_1_4 = {68 ee 13 4c b6}  //weight: 1, accuracy: High
        $x_1_5 = {8b 54 01 50}  //weight: 1, accuracy: High
        $x_1_6 = {81 c4 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {66 81 3e 4d 5a}  //weight: 1, accuracy: High
        $x_1_8 = {5f 83 ef 05 55 8b ec 81 c4 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JM_2147637332_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JM"
        threat_id = "2147637332"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 2c 24 c3 06 00 55 bd}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 f9 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JN_2147637419_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JN"
        threat_id = "2147637419"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 3b c1 74 ?? 75 ?? c1 ?? 20 c1 ?? 20 [0-12] e9 [0-2] 00 00 8b ff 55 8b ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JO_2147637488_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JO"
        threat_id = "2147637488"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 c0 74 27 a9 00 00 00 80 74 07 25 ff ff 00 00 eb 09 83 c0 02}  //weight: 1, accuracy: High
        $x_1_2 = {c3 2b 7c 24 28 89 7c 24 1c 61 c2 08 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 56 69 72 74 75 61 6c 46 72 65 65 00 6b 65 72 6e 65 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JP_2147637772_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JP"
        threat_id = "2147637772"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 fe ff ff 89 ?? f0 [0-4] 00 89 ?? d8 8b ?? f0 83 [0-2] 89 ?? e4 81 75 fc 38 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 e0 00 00 40 00 83 65 e8 00 83 a5 54 fe ff ff 00 eb}  //weight: 1, accuracy: High
        $x_1_3 = {6a 18 66 89 45 ?? 58 6a 06 66 89 45 ?? 59 33 c0 8d 7d ?? f3 ab 8b 45 ?? 0f af 45 ?? 6b c0 03}  //weight: 1, accuracy: Low
        $x_2_4 = {24 83 c4 04 29 ?? 8b ?? 08 03 ?? f8 c6 ?? 00 30 ?? 8b ?? fc ?? 89 ?? fc 83 7d fc 01 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_JQ_2147637996_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JQ"
        threat_id = "2147637996"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 05 f8 02 fe 7f 35 55 00 00 c0 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JV_2147638457_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JV"
        threat_id = "2147638457"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 40 05 67 c6 40 02 74 c6 00 47 c6 40 03 52 c6 40 04 65 c6 40 01 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JX_2147638988_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JX"
        threat_id = "2147638988"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 cc 80 25 00 00 c6 45 d0 67 c6 45 d1 39 c6 45 d2 68 c6 45 d3 37 c6 45 d4 74 c6 45 d5 34 c6 45 d6 72 c6 45 d7 39 c6 45 d8 68 c6 45 d9 34 c6 45 da 6a c6 45 db 68 c6 45 dc 34}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 ea fe ff ff 43 c6 85 eb fe ff ff 6c c6 85 ec fe ff ff 61 c6 85 ed fe ff ff 73 c6 85 ee fe ff ff 73 c6 85 ef fe ff ff 4f c6 85 f0 fe ff ff 62 c6 85 f1 fe ff ff 6a c6 85 f2 fe ff ff 65 c6 85 f3 fe ff ff 63 c6 85 f4 fe ff ff 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JY_2147639043_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JY"
        threat_id = "2147639043"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a9 8b 08 00 06 00 c7 85 ?? ?? ff ff 00 02 83 bd 01 ff ff 00 0f 84 ?? ?? 00 00 [0-255] c7 85 ?? ?? ff ff ?? ?? 00 00 00 02 ff b5 06 ff ff 68 07 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_JZ_2147639106_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.JZ"
        threat_id = "2147639106"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c7 02 46 eb 81 fe ?? ?? ?? ?? 74 03 7d f8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c7 02 46 e9 81 fe ?? ?? ?? ?? 0f 84 03 7d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_KA_2147639132_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KA"
        threat_id = "2147639132"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 15 18 00 00 00 [0-32] 8b 52 30 [0-255] cd 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KC_2147639745_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KC"
        threat_id = "2147639745"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 61 c4 74 e7}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 fa 4d 5a}  //weight: 1, accuracy: High
        $x_1_3 = {3d 04 d0 17 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_KC_2147639745_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KC"
        threat_id = "2147639745"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 5c 18 ff 89 1c 28 8b 7c 28 04 8b 74 28 08 8b 4c 28 0c 8b 54 28 10 c1 e9 02 41 ad 03 c2 ab e2 fa}  //weight: 1, accuracy: High
        $x_1_2 = {03 ea 01 2c 24 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KD_2147639834_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KD"
        threat_id = "2147639834"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 d8 1c 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KE_2147639842_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KE"
        threat_id = "2147639842"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 85 c0 0f 84}  //weight: 1, accuracy: High
        $x_1_2 = {8b b0 88 00 00 00 8d 54 02 18 89 55 ec}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 f0 01 00 00 00 1c 00 c7 45 e0 ?? 00 00 00 c7 45 e4 ?? 00 00 00 c7 45 e8 ?? 00 00 00 c7 45 ec ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KF_2147640300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KF"
        threat_id = "2147640300"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 30 00 00 00 05 01 01 01 01 05 f8 f9 eb e9 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {a9 00 00 f0 0f 05 01 01 01 01 05 f8 f9 eb e9 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_3 = {a9 00 00 ff 00 05 01 01 01 01 05 f8 f9 eb e9 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_KG_2147640334_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KG"
        threat_id = "2147640334"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 40 74 14 8d 05 ?? ?? ?? ?? 8b 00 3b 05 ?? ?? ?? ?? 75 02 eb 02 eb e7}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 40 74 11 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 75 02 eb 02 eb ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_KH_2147640344_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KH"
        threat_id = "2147640344"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 51 8b 4d 0c 33 d2 f7 f1 59 4e 8a 06 86 04 3a 88 06 58 49 0b c9 75 e3}  //weight: 1, accuracy: High
        $x_1_2 = {03 5b 3c 8b 4b 54 81 c3 f8 00 00 00 (8b|ff 73) 02 05 5b 0b db 75 02}  //weight: 1, accuracy: Low
        $x_1_3 = {68 c8 12 11 97 50 e8 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_KJ_2147640497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KJ"
        threat_id = "2147640497"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 48 3c 89 4d cc 8b 55 cc 0f b7 42 14 8b 4d cc 8d 54 01 18 89 55 dc 6a 40 68 00 30 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {c6 00 68 8b 0d ?? ?? ?? ?? 89 48 01 c6 40 05 c3}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 40 68 00 30 00 00 8b 45 cc 8b 48 50 51 6a 00 ff 15 ?? ?? ?? ?? 89 45 d4 8b 95 50 ff ff ff 8b 42 3c 8b 4d cc 0f b7 51 06 6b d2 28 8d 84 10 38 01 00 00}  //weight: 2, accuracy: Low
        $x_1_4 = {8d 4c 10 02 8b 15 ?? ?? ?? ?? 03 55 f4 33 0a a1 ?? ?? ?? ?? 03 45 f4 89 08 eb}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 54 01 02 8b 45 c4 03 45 f4 33 10 8b 4d c4 03 4d f4 89 11 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_KN_2147640839_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KN"
        threat_id = "2147640839"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac 34 55 3c c5 74 26 3c 99 74 22 3c 98 74 1e 3c bd 74 1a 3c bc 74 16 3c be 74 12 3c a1 74 0e 3c af 74 0a 3c ae 74 06 3c 5a 74 02 e2 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KO_2147640887_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KO"
        threat_id = "2147640887"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3e 8b 49 30 3e 8b 41 0c}  //weight: 1, accuracy: High
        $x_1_2 = {89 48 01 c6 40 05 c3}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 51 06 6b d2 28 8d 84 10 38 01 00 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_KP_2147640920_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KP"
        threat_id = "2147640920"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 03 00 00 7d 06 00 81 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {f2 36 df 05 7d 0a 00 [0-4] 81 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {81 7d 0c 11 11 11 11 75 07}  //weight: 1, accuracy: High
        $x_1_4 = {a8 e1 02 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_KQ_2147641077_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KQ"
        threat_id = "2147641077"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 07 92 8e 2a 74 ?? 81 f9 da 12 44 ca 74 ?? 81 f9 83 e1 14 ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KV_2147641288_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KV"
        threat_id = "2147641288"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 6a 02 ?? ff 15 ?? ?? ?? ?? 83 c4 10 8b 45 f0 2d ?? ?? ?? ?? 89 45 f0 85 c0 0f 85 ?? ?? ff ff ff 15 ?? ?? ?? ?? 83 f8 7e 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KW_2147641326_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KW"
        threat_id = "2147641326"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 83 38 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {80 38 c2 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {83 fa 0f 0f 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KX_2147641342_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KX"
        threat_id = "2147641342"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 76 78 0b f6 74 32 03 f3 8b 76 0c 03 f3 81 3e 4b 45 52 4e 75 23 83 c6 04}  //weight: 1, accuracy: High
        $x_1_2 = {ad 8b f8 ad 8b c8 83 f8 08 7e 2a 29 4d cc 83 e9 08 d1 e9 33 c0 66 ad 8b d0 c1 ea 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KS_2147641465_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KS"
        threat_id = "2147641465"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 02 59 5a 01 c1 83 c2 01 81 fa 00 ba 04 00 75 ?? 89 ce 8d 55 ?? 52 ff 94 1e 00 46 fb ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 83 c6 04 eb 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_LL_2147641554_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.LL"
        threat_id = "2147641554"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d fc 8b 4d f8 41 31 c0 83 e8 62 f7 d0 83 f8 47 75 03 c2 08 00}  //weight: 1, accuracy: High
        $x_1_2 = {32 d2 01 d8 29 c1 43 8a 53 ff 3a 15 ?? ?? ?? 00 75 ?? 8a 53 01 3a 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_MC_2147641596_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.MC"
        threat_id = "2147641596"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 00 8b 40 08}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 03 8b f0 81 e6 00 f0 00 00 bf 00 30 00 00 66 3b f7 75}  //weight: 1, accuracy: High
        $x_1_3 = {25 ff 0f 00 00 03 01 03 45 08 01 10 8b 41 04 43 83 e8 08 43 ff 45 0c d1 e8 39 45 0c}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4d fc 8b c1 99 83 e2 07 03 c2 8b 55 08 c1 f8 03 03 c2 81 e1 07 00 00 80 ?? ?? 49 83 c9 f8 41 83 45 fc 05 d3 e6 09 30 43 3b 5d 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_MP_2147641629_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.MP"
        threat_id = "2147641629"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 fc 89 00 00 03}  //weight: 1, accuracy: High
        $x_1_2 = {6a 01 68 78 58 64 78 68 88 67 59 76}  //weight: 1, accuracy: High
        $x_1_3 = {b9 bd 3a 00 00 66}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4d 08 89 01 e9 07 00 00 00 81 75 fc}  //weight: 1, accuracy: High
        $x_1_5 = {76 4c bf 4c 6c 4c ba 4c 44 4c b5 4c 77 4c b0 4c 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_MZ_2147641662_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.MZ"
        threat_id = "2147641662"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 b9 99 99 99 99 50 58 2d 00 01 00 00 05 00 01 00 00 e2 f2}  //weight: 1, accuracy: High
        $x_1_2 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 50 8b c3 33 c0 58 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_MZ_2147641662_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.MZ"
        threat_id = "2147641662"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d c8 8b 45 fc 03 40 3c 8b 40 28 03 45 fc 5b c9 8b f4 83 c6 10 68 00 40 00 00 68 00 10 00 00 51 50 52 c3}  //weight: 1, accuracy: High
        $x_1_2 = {c1 c7 07 83 c7 02 03 f8 80 3e 00 75 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_NN_2147641819_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.NN"
        threat_id = "2147641819"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 18 c6 45 ec 47 c6 45 ed 65 c6 45 ee 74 c6 45 ef 4d}  //weight: 1, accuracy: High
        $x_1_2 = {83 ec 10 c6 45 f4 56 c6 45 f5 69 c6 45 f6 03}  //weight: 1, accuracy: High
        $x_1_3 = {83 ec 14 c6 45 ec 03 c6 45 ed 69 c6 45 ee 03 c6 45 ef 74}  //weight: 1, accuracy: High
        $x_1_4 = "CreateHardLinkA" ascii //weight: 1
        $x_1_5 = "beautiful flowers here" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_NR_2147641908_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.NR"
        threat_id = "2147641908"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 b4 0f b7 40 06 39 45 a4 7d 41 8b 45 a4 6b c0 28 8b 4d b4 8d 84 01 f8 00 00 00 89 45 a0 8b 45 a0 8b 4d f4 03 48 14 89 4d ec 8b 45 a0 8b 4d d0 03 48 0c 89 4d c4 8b 45 a0 ff 70 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_NT_2147642100_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.NT"
        threat_id = "2147642100"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7d 0c 11 11 11 11 75 12 c7 45 0c d4 70 81 03 8b 45 0c}  //weight: 1, accuracy: High
        $x_1_2 = {00 f2 36 df 05 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_NU_2147642329_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.NU"
        threat_id = "2147642329"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 39 83 7d 08 0e 75 07 b8 ?? ?? ?? 00 eb 2c 83 7d 08 0f 75 07 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {52 6a 02 e8 ?? ?? ?? ff 83 c4 04 50 e8 ?? ?? ?? ff 83 c4 04 50 6a 02 e8 ?? ?? ?? ff 83 c4 04 50 e8 ?? ?? ?? 00 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_NV_2147642586_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.NV"
        threat_id = "2147642586"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 4c f6 ff ff 2e c6 85 4d f6 ff ff 64 c6 85 4e f6 ff ff 65 c6 85 4f f6 ff ff 72}  //weight: 1, accuracy: High
        $x_1_2 = {ac d2 c8 aa 81 c1 15 cd 5b 07 4a 0b d2 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_NV_2147642586_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.NV"
        threat_id = "2147642586"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 6a 02 8b ?? ?? ff ff ff ?? ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 04 6a 00 6a ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {8a 0c 11 32 8c 85 c8 fb ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_NW_2147643050_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.NW"
        threat_id = "2147643050"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 78 02 52 75 06 80 78 01 45 74}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 14 8d ?? ?? e8 ?? ff ff ff 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_NX_2147643107_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.NX"
        threat_id = "2147643107"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 47 75 35 8b 45 08 0f be 40 03 83 f8 4d 75 29 8b 45 08 0f be 40 09 83 f8 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_NY_2147643117_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.NY"
        threat_id = "2147643117"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 75 0c 68 ff ff 0f 00 ff d0}  //weight: 2, accuracy: Low
        $x_1_2 = {68 6a d9 3f 2e}  //weight: 1, accuracy: High
        $x_1_3 = {68 9d 73 e8 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_OB_2147643497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OB"
        threat_id = "2147643497"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 33 f6 66 ba 4d 5a 66 ad 66 33 d0 74 08 81 ee 02 10 00 00 eb ed 8d 5e fe 8b 76 3a 66 ba 50 45 8d 34 1e 66 ad 66 33 d0 75 e4 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OE_2147644145_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OE"
        threat_id = "2147644145"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 45 70 8b 45 70 8b 4d 68 3b c1 0f 82 ?? ff ff ff 8b 45 d8 8b 4d 70 3b c8 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 40 7f c6 45 41 67 c6 45 42 43 88 5d 43 c7 45 68 00 20 00 00 89 5d 70 8b f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_OF_2147644206_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OF"
        threat_id = "2147644206"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 50 53 8d 45 ac 8d 5d bc 50 53 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00}  //weight: 1, accuracy: High
        $x_1_2 = {30 14 19 41 3b c8 75 f2 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OG_2147644227_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OG"
        threat_id = "2147644227"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 51 06 8b d9 81 c3 f8 00 00 00 c1 e0 1f d1 e0 f7 43 24 00 00 00 20 74 03 83 c8 01 f7 43 24 00 00 00 40 74 03 83 c8 02 f7 43 24 00 00 00 80 74 03 83 c8 04 f7 43 24 00 00 00 10 74 03 83 c8 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OH_2147644274_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OH"
        threat_id = "2147644274"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 58 3c 8b 54 03 50 55 56 57}  //weight: 1, accuracy: High
        $x_1_2 = {8b 00 39 48 18 75 f9 8b 15}  //weight: 1, accuracy: High
        $x_1_3 = {2b 7d 34 83 3c 08 00 8d 14 08 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_OI_2147644312_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OI"
        threat_id = "2147644312"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 43 14 ff 73 50 8d 7c 18 18 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? 85 c0 0f 84 ?? ?? ?? ?? ff 73 54 56 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OJ_2147644340_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OJ"
        threat_id = "2147644340"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 d2 4f 24 7d 38}  //weight: 1, accuracy: High
        $x_1_2 = {69 d2 9a fa 21 12}  //weight: 1, accuracy: High
        $x_1_3 = {81 c1 43 aa 35 43}  //weight: 1, accuracy: High
        $x_1_4 = {81 f2 c3 db 99 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OK_2147644477_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OK"
        threat_id = "2147644477"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 07 8b 4d ?? c1 e9 19 0b c1 89 45 ?? 8b 55 ?? 0f ?? 02 33 45 ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 0c 4a 81 e1 ff 0f 00 00 8b 55 ?? 03 0a 8b 55 08 89 04 0a}  //weight: 1, accuracy: Low
        $x_2_3 = {eb 0f 58 2b 05 ?? ?? ?? 00 03 05 ?? ?? ?? 00 ff e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_OL_2147644536_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OL"
        threat_id = "2147644536"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b dd 03 5c 24 18 81 c3 00 10 00 00 8b 33 68}  //weight: 1, accuracy: High
        $x_1_2 = {53 5b 53 5b 53 5b 53 5b 53 5b 53 5b 81 c4 04 00 00 00 52 33 d2 8b 54 24 04 52 23 d0 ba 10 00 00 00 31 54 24 0c 8b 54 24 0c 03 d4 8f 42 08 0b d1 5a 03 64 24 04 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OM_2147644605_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OM"
        threat_id = "2147644605"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 01 00 00 7d 3c 8b 15 ?? ?? ?? ?? 33 c0 8a 02 8b 0d ?? ?? ?? ?? 33 d2 8a 11 33 c2 8b 0d ?? ?? ?? ?? 88 01 8b 15 ?? ?? ?? ?? 83 c2 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 01 a3 ?? ?? ?? ?? eb b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ON_2147644850_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ON"
        threat_id = "2147644850"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7b 3c 00 10 00 00 77 ?? 03 5b 3c 8b 43 08}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 83 a7 ab 4b 75 02}  //weight: 1, accuracy: High
        $x_1_3 = {3d 7c 58 54 b4 75 02 02 00 f7 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_OO_2147644964_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OO"
        threat_id = "2147644964"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 39 32 4c 02 ?? 8b 40 ?? 88 0c 07 8b 45 08 ff 40 ?? 8b 45 08 ff 80 ?? ?? 00 00 [0-2] 8b 45 08 83 78 ?? 04 72 ?? 89 ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OP_2147645250_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OP"
        threat_id = "2147645250"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 00 c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? c6 05}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 00 0f b6 d1 81 f2}  //weight: 1, accuracy: High
        $x_1_3 = {eb 00 8b 15 ?? ?? ?? ?? 33 55 08 89 55 0c 0f b6 45 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OP_2147645250_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OP"
        threat_id = "2147645250"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 74 0a 8a 06 34 ?? 88 06 46 49 eb f1 59 49 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 ff 5f 00 00 83 f9 00 74 ?? 51 8b 85 ?? ?? ?? 00 8d b5 ?? ?? ?? 00 8b 8d ?? ?? ?? 00 83 f9 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 47 6c 6f 62 61 6c ?? 6c 6c 6f 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_OQ_2147645385_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OQ"
        threat_id = "2147645385"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 5e 8b 24 24 8b ad ?? ?? ?? 00 8d bd ?? ?? ?? 00 8a 06 8b 5e 01 88 07 89 5f 01 c6 06 e9 8d bd ?? ?? ?? 00 2b fe 83 ef 05 89 7e 01 89 b5 ?? ?? ?? 00 8b b5 ?? ?? ?? 00 83 c6 02 56 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OS_2147645409_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OS"
        threat_id = "2147645409"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 00 00 00 76 b8 01 00 00 00 e9 ?? 00 00 00 81 c3 00 10 00 00 8d 44 24 ?? c7 00 6b 63 75 66 c7 40 04 70 73 61 6b c7 40 08 6b 73 72 65 c7 40 0c 79 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7b 3c 00 10 00 00 77 ?? 03 5b 3c 8b 43 08 35 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OT_2147645410_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OT"
        threat_id = "2147645410"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf 00 00 00 00 f7 d7 33 f8 f7 d7 6b db 00 ff 75 0c 53 53 53 68 3f 00 0f 00 ff 75 08 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OU_2147645419_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OU"
        threat_id = "2147645419"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 01 6a 02 6a 03 6a 04 6a 05 6a 06 6a 07 6a 08 ff d0 8d 35 ?? ?? ?? ?? 25 ff 00 00 00 2b f0 ff e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OV_2147645440_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OV"
        threat_id = "2147645440"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 3e 00 00 02 00 81}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ca 79 79 79 79}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 01 [0-8] ff 55 ?? 8b ?? 0c 8b ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 89 ?? ?? 6a 00 8b ?? 08 ?? 6a 00 6a 00 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OY_2147645529_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OY"
        threat_id = "2147645529"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 31 c2 83 ea ff 59 02 03 03 5b 5f 5e 5e 5f 5b 29 d4 89 f2 89 fe 87 f2 51 56 29 ?? 89 ?? f4 89 ?? ?? 55}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 a4 00 00 00 00 8d ?? a4 6a 00 ff 15 ?? ?? ?? 00 35 00 40 0f 00 3d 02 40 0f c0 74 01 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OZ_2147645530_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OZ"
        threat_id = "2147645530"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 64 24 14 00 66 83 bc 24 c0 00 00 00 00 74 50 33 f6 8d bc 24 c0 00 00 00 68 00 02 00 00 53 ff 15 ?? ?? ?? ?? 6a 01 8d 86 ?? ?? ?? ?? 50 57 ff 15 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? ff 44 24 14 8b 74 24 14 03 f6 8d bc 34 c0 00 00 00 66 83 3f 00 75 b9 8d 44 24 78 50 6a 00 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PB_2147645566_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PB"
        threat_id = "2147645566"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 01 3b 15 ?? ?? ?? ?? 72 05 ba 00 00 00 00 3b 4d fc 72 02 eb 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PC_2147645573_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PC"
        threat_id = "2147645573"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 23 f2 8b 4c b0 08 03 f9 23 fa 89 7d 08 8b 7c b8 08 8b 5d 08 89 7c b0 08 03 f9 23 fa 89 4c 98 08 8a 4c b8 08 8b 7d fc 32 0f 8b 5d f8 88 0c 3b 47 3b 7d f4 89 7d fc 8b 7d 08 75 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PD_2147645680_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PD"
        threat_id = "2147645680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 00 54 00 45 00 58 00 54 00 49 00 4e 00 43 00 4c 00 55 00 44 00 45 00 03 00 34 00 33 00 31 00 04 00 34 00 33 00 31 00 56 00 05 00 34 00 33 00 31 00 56 00 56 00 06 00 34 00 33 00 31 00 56 00 56 00 56 00 07 00 34 00 33 00 31 00 56 00 56 00 56 00 56 00 08 00 34 00 33 00 31 00 56 00 56 00 56 00 56 00 56 00 09 00 34 00 33 00 31 00 56 00 56 00 56 00 56 00 56 00 56 00 01 00 36 00 00 00 44 3a 5c 4c 61 73 74 53 61 76 65 5c 52 65 64 50 69 6c 6c 43 72 79 70 74 65 72 0d 65 73 6f 75 72 63 65 2e 68 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PG_2147645743_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PG"
        threat_id = "2147645743"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 81 a0 00 00 00 03 c7 8b 51 34 8b b1 a4 00 00 00 74 ?? 85 f6 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 51 e8 ?? ?? ?? ?? 8b 55 f4 89 15 44 43 40 00 5f 5e 5d 5b 83 c4 24 83 c4 08 ff 25 ?? ?? ?? ?? 33 c0 0f 85 ?? ?? ff ff 83 7d f8 00 74 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PH_2147645967_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PH"
        threat_id = "2147645967"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 50 08 8b 4e ?? 6a ?? 6a ?? 6a ?? 89 01 8b 46 ?? 6a ?? ff 50 08 8b 4e ?? 89 01}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 31 ff 50 04 85 c0 8b 46 4c 75 08 81 00 ?? ?? 00 00 eb ?? 81 00 ?? ?? 00 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PJ_2147646008_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PJ"
        threat_id = "2147646008"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 02 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 f1 02 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 00 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff d0 ff 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 05 c4 11 00 00 ff d0 a1 ?? ?? ?? ?? ?? ?? ?? ?? 05 ?? ?? 00 00 ff d0 [0-32] 68 ?? ?? ?? ?? ff 74 24 ?? e8 ?? 00 00 00 ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PK_2147646017_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PK"
        threat_id = "2147646017"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d f4 c7 45 fc 00 00 00 00 eb 09 8b 55 fc 83 c2 08 89 55 fc 81 7d fc ?? ?? 00 00 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d f4 03 c8 89 4d f4 8b 55 f8 03 55 fc 8b 02 03 45 ec 8b 4d f8 03 4d fc 89 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PK_2147646017_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PK"
        threat_id = "2147646017"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ff 00 20 00 00 0f 82 c6 85 e5 fd ff ff 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 44 95 e4 [0-16] 8b 08}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 74 b5 e4}  //weight: 1, accuracy: High
        $x_1_4 = {39 08 0f 84 ?? ?? 00 00 [0-16] 8b d8 8b 03 [0-16] 8a 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PK_2147646017_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PK"
        threat_id = "2147646017"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 04 8b 10 8b 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 52 3c 8b 44 02 50}  //weight: 1, accuracy: High
        $x_1_3 = {03 c1 8b 0d ?? ?? 40 00 8b 49 08 ff 31 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8a 0c 30 [0-32] 80 e9 ?? d0 c9 88 0c 30 3b c3 0f 85 48 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PL_2147646134_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PL"
        threat_id = "2147646134"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 dc 85 c9 75 2d 0d 00 00 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PM_2147646143_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PM"
        threat_id = "2147646143"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 75 10 8b 45 0c 0f b6 0c 10}  //weight: 1, accuracy: High
        $x_1_2 = {f7 75 10 8b 4d 0c 0f b6 14 11 03}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 0f b6 14 10 03 ca 81 e1 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 55 08 0f b6 0c 0a 03 c1 25 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b 4d 08 0f b6 04 01 03 d0 81 e2 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {0f b6 08 03 d1 81 e2 ff 00 00 00 8b 45 08 0f b6 0c 10 8b 55 14}  //weight: 1, accuracy: High
        $x_1_7 = {8b 45 08 8b 75 08 8a 0c 0e 88 0c 10 0f b6 ?? ?? 2b 15 ?? ?? ?? ?? 89 15}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 55 e8 81 ea 01 08 00 00 89 55 f8 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
        $x_1_9 = {0f b6 14 10 03 ca 88 4d ?? 0f b6 45 ?? 8b 4d 08 8a 14 01 88 55}  //weight: 1, accuracy: Low
        $x_1_10 = {8a 02 88 01 8b 4d 08 03 4d ?? 8a 55 ?? 88 11 8b 45 08}  //weight: 1, accuracy: Low
        $x_1_11 = {8b 55 0c 03 55 ?? 0f b6 02 8b 4d 08 03 4d ?? 0f b6 11 33 d0 8b 45 08}  //weight: 1, accuracy: Low
        $x_1_12 = {78 38 42 4d 08 8a 14 01 88 55 ?? 0f b6 45 ?? 0f b6 4d ?? 8b 55 08 8b 75 08 8a 04 06}  //weight: 1, accuracy: Low
        $x_1_13 = {8b 45 08 8b 75 08 8a 0c 0e 88 0c 10 0f b6 55 ?? 8b 45 08 8a 4d ?? 88 0c 10}  //weight: 1, accuracy: Low
        $x_1_14 = {8b 45 08 0f b6 14 10 03 ca 88 4d ?? 0f b6 45 ?? 8b 4d 08}  //weight: 1, accuracy: Low
        $x_1_15 = {8b 55 08 0f b6 0c 0a 03 c1 88 45 ?? 0f b6 55 ?? 8b 45 08}  //weight: 1, accuracy: Low
        $x_1_16 = {8b 4d 08 0f b6 04 01 03 d0 88 55 ?? 0f b6 4d ?? 8b 55 08}  //weight: 1, accuracy: Low
        $x_1_17 = {0f b6 02 03 c8 81 e1 ff 00 00 00 8b 55 08 0f b6 04 0a 8b 4d 14}  //weight: 1, accuracy: High
        $x_1_18 = {68 00 b0 42 00 e8}  //weight: 1, accuracy: High
        $x_1_19 = {68 00 c0 42 00 e8}  //weight: 1, accuracy: High
        $x_1_20 = {68 00 20 43 00 e8}  //weight: 1, accuracy: High
        $x_1_21 = {68 00 d0 42 00 e8}  //weight: 1, accuracy: High
        $x_1_22 = {68 00 10 43 00 e8}  //weight: 1, accuracy: High
        $x_1_23 = {81 c2 59 3e 00 00}  //weight: 1, accuracy: High
        $x_1_24 = {81 c1 59 3e 00 00}  //weight: 1, accuracy: High
        $x_1_25 = {05 59 3e 00 00}  //weight: 1, accuracy: High
        $x_1_26 = {05 59 35 00 00}  //weight: 1, accuracy: High
        $x_1_27 = {81 c1 59 35 00 00}  //weight: 1, accuracy: High
        $x_1_28 = {81 c2 59 35 00 00}  //weight: 1, accuracy: High
        $x_1_29 = {81 c2 49 3e 00 00}  //weight: 1, accuracy: High
        $x_1_30 = {81 c1 49 3e 00 00}  //weight: 1, accuracy: High
        $x_1_31 = {05 49 3e 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_PN_2147646169_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PN"
        threat_id = "2147646169"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9f ff ff 2b c8 03 4d f8 89 4d f8 8b 45 f8 02 00 b9}  //weight: 1, accuracy: Low
        $x_1_2 = {05 00 5a 00 00 [0-16] 33 c7 66 3b 46 20 5f 5e 5b 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PN_2147646169_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PN"
        threat_id = "2147646169"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8d 6c 24 ?? 81 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 7e 14 8b 37 8b d8 eb 3b f7 75 ?? 33 c0 5f 5b 5e c9 c2 04 00 8b 46 10 eb f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PN_2147646169_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PN"
        threat_id = "2147646169"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Usartysaid" ascii //weight: 1
        $x_1_2 = {2c 6a 0c 63 88 44 24}  //weight: 1, accuracy: High
        $x_2_3 = {be d6 43 d2 7d 23 8f 55 04 93 5d e0 3b d3 95 94}  //weight: 2, accuracy: High
        $x_2_4 = {8d 04 0a 8a d1 80 e2 03 c1 e8 04 f6 ea b2 fe 2a d0 00 14 0f ff 45 ?? 8b 55 ?? eb ?? 8b 45 ?? 83 c1 20 3b c8 72 ?? 8b 45 ?? 33 c9 85 c0 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_PN_2147646169_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PN"
        threat_id = "2147646169"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 80 94 01 00 00 8b 00 03 41 3c 8b (4d 14|4c) 8b 89 (d4|d8) 01 00 00 8b 49 14 6a 04 68 00 30 00 00 ff 70 50 6a 00 ff d1}  //weight: 10, accuracy: Low
        $x_1_2 = {3a c8 75 0f 8d 45 ?? e8 ?? ?? ff ff 8b 4d ?? 3b c1 74 ?? 8b 45 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0a 80 f9 ?? 75 ?? c6 00 00 8b 86 88 01 00 00 03 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_PO_2147646172_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PO"
        threat_id = "2147646172"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 10 00 00 53 ff 95 ?? ?? ff ff 0b c0 75 0b c0 74 0c 81 fb 00 00 00 ?? 0f 82 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 03 2d 4d 5a 00 00 0b c0 75 ?? 81 7b 3c 00 10 00 00 77 ?? 03 5b 3c 8b 43 08}  //weight: 1, accuracy: Low
        $x_2_3 = {ff ff 57 8d 00 c6 85 ?? ?? ff ff 49 8d 00 c6 85 ?? ?? ff ff 4e 8d 00 c6 85 ?? ?? ff ff 53 8d 00 c6 85 ?? ?? ff ff 50 8d 00 c6 85 ?? ?? ff ff 4f 8d 00 c6 85 ?? ?? ff ff 4f 8d 00 c6 85 ?? ?? ff ff 4c 8d 00 c6 85 ?? ?? ff ff 2e 8d 00 c6 85 ?? ?? ff ff 44 8d 00 c6 85 ?? ?? ff ff 52 8d 00 c6 85 ?? ?? ff ff 56 8d 00 c6 85 ?? ?? ff ff 00 8d 85 ?? ?? ff ff 50 e8 ?? ?? 00 00 68 ?? ?? ?? ?? 50 e8 ?? ?? 00 00 8b f0 ff 75 fc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_PP_2147646207_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PP"
        threat_id = "2147646207"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f1 c1 ee 05 03 74 24 0c 8b d9 c1 e3 04 03 5c 24 10 33 f3 8d 1c 0a 33 f3 2b c6 8b f0 c1 ee 05 03 74 24 14 8b d8 c1 e3 04 03 5c 24 18 33 f3 8d 1c 02 33 f3 2b ce}  //weight: 1, accuracy: High
        $x_1_2 = {8d 7e 01 57 56 8d 4e ff 51 8d 56 fe 52 8d 4e fd 51 8d 56 fc 52 8d 4e fb 51 83 c6 fa 56 ff d0 3c 05 74 ?? 8d 54 24 14 52 8b f7 ff d3 68 ?? ?? ?? ?? 50 ff d5 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PQ_2147646267_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PQ"
        threat_id = "2147646267"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d9 fe d9 fb d9 fa d9 cd}  //weight: 1, accuracy: High
        $x_1_2 = {40 00 0f 18 86}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PS_2147646352_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PS"
        threat_id = "2147646352"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 59 03 4d c0 83 c1 09 ff e1 52 52 52 52 52 52 52 52 52 52 8b 4d c4 [0-10] ff (d0|d7) 83 c4 08 64 a1 (18 00 00 00 3e 8a|34 00)}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 59 03 4d (b8|c0) 83 c1 09 ff e1 03 0a 0a 0a 50 50 50 50 50 50 50 50 50 50 52 52 52 52 52 52 52 52 52 52 53 53 53 53 53 53 53 53 53 53 8b 4d (bc|c4) 41 49 74 06 49 8b d1 42 89 0a ff d7 83 c4 08 [0-32] 8d 40 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_PU_2147646391_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PU"
        threat_id = "2147646391"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 ec 8d 6d fc 89 65 00 8d 65}  //weight: 1, accuracy: High
        $x_1_2 = {81 14 24 89 0a 00 00 [0-4] ba fd a5 17 [0-4] 81 14 24 5e 34 9a e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PV_2147646422_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PV"
        threat_id = "2147646422"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 8b ff cc c3 0f 84}  //weight: 1, accuracy: High
        $x_1_2 = {81 38 33 c0 c2 ?? 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {32 4c 90 01 c1 e1 08 32 0c 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PV_2147646422_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PV"
        threat_id = "2147646422"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cc 8d 61 ?? 59}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c4 8d 60 ?? 58}  //weight: 1, accuracy: Low
        $x_1_3 = {81 38 33 c0 c2 08 0f 84}  //weight: 1, accuracy: High
        $x_1_4 = {81 38 8b ff 90 33 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PV_2147646422_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PV"
        threat_id = "2147646422"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 c2 08 0f (84|85)}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 66 83 78 06 02 0f (84|85)}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 90 90 90 90}  //weight: 1, accuracy: High
        $x_1_4 = {39 58 6f 0f (84|85)}  //weight: 1, accuracy: Low
        $x_2_5 = {81 78 05 33 c0 c9 c2 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_PW_2147646510_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PW"
        threat_id = "2147646510"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 83 ba ?? ?? 00 00 00 74 8b 55 fc 5f 5e 59 5d 81 c4 ?? ?? 00 00 ff e2}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 fc 83 7d fc 05 75 ?? 68 ?? ?? ?? ?? 68 00 10 00 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4d 08 89 81 ?? ?? 00 00 8b 55 08 c7 82 ?? ?? 00 00 57 00 00 00 eb 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_PX_2147646526_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PX"
        threat_id = "2147646526"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 6b 59 6f 06 50 e8}  //weight: 2, accuracy: High
        $x_1_2 = {8d 70 54 6a 04 50 8d 80 ?? ?? ?? ?? 51 91 07 00 59 8b 85 ?? f4 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {56 57 64 8b 35 18 00 00 00 8d 76 30 6a 04 50 8d 80 ?? ?? ?? ?? 51 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_PX_2147646526_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PX"
        threat_id = "2147646526"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 8d 52 7b 59 8d 40 7b 53 8d 40 85 5b 8d 52 85 51 8d 52 7b 59 8d 40 7b}  //weight: 1, accuracy: High
        $x_1_2 = {e8 f3 10 00 00 c6 85 90 fd ff ff 57 8d ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? c6 85 91 fd ff ff 49}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 3e 96 bc ff b5 28 f4 ff ff e8 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_PX_2147646526_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PX"
        threat_id = "2147646526"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 85 91 fd ff ff 44 [0-32] c6 85 92 fd ff ff 56 [0-32] c6 85 93 fd ff ff 41 [0-32] c6 85 94 fd ff ff 50}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 85 91 fd ff ff 49 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 85 92 fd ff ff 4e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 85 93 fd ff ff 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 85 94 fd ff ff 50}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 85 50 fd ff ff 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 85 51 fd ff ff 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 85 52 fd ff ff 76 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 85 53 fd ff ff 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_PY_2147646607_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PY"
        threat_id = "2147646607"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 c7 44 24 04 8b 0d ?? ?? ?? ?? 89 48 04 c6 40 08 68 8b 0d ?? ?? ?? ?? 89 48 09 b1 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {03 42 3c 89 45 ?? 8b 4d ?? 8b 51 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QA_2147646709_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QA"
        threat_id = "2147646709"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 3b 55 10 73 1e 8b 45 0c 03 45 ?? 0f b6 08 8b 55 08 03 55 ?? 0f b6 02 33 c1 8b 4d 08 03 4d ?? 88 01 eb d1 8b e5 5d c2 0c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 01 8b 15 ?? ?? ?? ?? 52 ff 95 ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QC_2147646736_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QC"
        threat_id = "2147646736"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 0a 80 f1 ?? 80 (c1|e9) ?? 88 08 40 42 8a 0a 84 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 14 8d 4d ?? 51 ff d0 (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d f4 8b 11 33 d6 03 d7 3b c2 0f 82 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_QD_2147646899_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QD"
        threat_id = "2147646899"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 60 48 46 51 4d c7 45 64 46 4f 10 11 c7 45 68 0d 47 4f 4f}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 18 60 51 46 42 c7 45 1c 57 46 73 51 c7 45 20 4c 40 46 50 66 c7 45 24 50 62}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 b8 74 51 4a 57 c7 45 bc 46 73 51 4c c7 45 c0 40 46 50 50 c7 45 c4 6e 46 4e 4c 66 c7 45 c8 51 5a}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 cc 6f 4c 42 47 c7 45 d0 71 46 50 4c c7 45 d4 56 51 40 46}  //weight: 1, accuracy: High
        $x_1_5 = {0d 00 ff ff ff 40 8a 44 85 90 30 04 1e 43 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_QF_2147646975_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QF"
        threat_id = "2147646975"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {27 fd fe fc 2e fd fb fc 3d fd e7 fc 4c fd e4 fc fe fc e0 fc 1a 30 19 31 09 41 08 46 38 56 27 57 f9 fc 22 fd fe fc}  //weight: 1, accuracy: High
        $x_1_2 = {2b fd fe fc 59 fd fb fc 4e fd fa fc fe fc f9 fc 1a a0 19 a1 09 b1 08 b6 38 c6 27 c7 38 d6 27 d7}  //weight: 1, accuracy: High
        $x_1_3 = {28 fd fe fc 4a fd fb fc 3d fd e7 fc 4f fd e4 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QG_2147647072_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QG"
        threat_id = "2147647072"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 54 3e ff 09 e9}  //weight: 1, accuracy: High
        $x_1_2 = {3d f0 35 05 00 e9}  //weight: 1, accuracy: High
        $x_1_3 = {68 20 10 dc ba e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QG_2147647072_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QG"
        threat_id = "2147647072"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 8d 59 41 13 e9}  //weight: 1, accuracy: High
        $x_1_2 = {68 51 e2 26 6d e9}  //weight: 1, accuracy: High
        $x_1_3 = {8b 42 18 e9}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 0c 48}  //weight: 1, accuracy: High
        $x_1_5 = {8b 04 88 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QG_2147647072_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QG"
        threat_id = "2147647072"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 57 e7 67 5e 12 12 aa a3 17 13 0e e8 39 17 f7 57 1c 1c d2}  //weight: 1, accuracy: High
        $x_1_2 = {25 5e e8 86 39 53 0c 1e e7 15 f5 72 31 53 22 2b 15 13 4a 78}  //weight: 1, accuracy: High
        $x_1_3 = {e4 96 78 33 15 3a 27 15 1a b2 fe 07 15 0e 06 3d 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QI_2147647250_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QI"
        threat_id = "2147647250"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 42 53 25 f5 1f 17 17 74 15 7b 97 17 17 c6 23 45 4c fa 45 ec 47 23 52}  //weight: 1, accuracy: High
        $x_1_2 = {ec 53 53 f1 4c 16 25 de fb 25 1e 43 39 4c 16 c6 0f}  //weight: 1, accuracy: High
        $x_1_3 = {c6 3f 19 de fb 19 1e 43 39 37 18 20 41 3f 19 fe 4a ec d6 32}  //weight: 1, accuracy: High
        $x_1_4 = {64 c6 5b eb 7b 1f 17 17 2b 7b 1b 17 17 b0 3d 1b 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QJ_2147647259_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QJ"
        threat_id = "2147647259"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a df 80 1a 1f 80 63 3b 46 4d db e4 57 3a 2d 17 46 2d cb e4 37 4e}  //weight: 1, accuracy: High
        $x_1_2 = {2e 3f ed 54 54 f2 4d 17 26 df 00 26 1f 48 3a 4d 17 c7 10 54}  //weight: 1, accuracy: High
        $x_1_3 = {1f b7 38 24 37 c7 40 1a df 00 1a 1f 48 3a 38 19 21 42 40 1a ff 53 ed d7 33}  //weight: 1, accuracy: High
        $x_1_4 = {e4 63 9c 6d fb fa 80 20 18 18 e4 3b 1e 1f 80 1c 18 18 3e 4d eb 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QK_2147647313_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QK"
        threat_id = "2147647313"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 c3 8b 65 e8}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 30 00 00 68 58 04 00 00 6a 00 ff 55 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QL_2147647381_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QL"
        threat_id = "2147647381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e9 10 01 08 ff 4d 38 e8}  //weight: 1, accuracy: High
        $x_1_2 = {83 c1 04 8d 44 04 04 83 f9 10 72 ee a1 2c 51 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 08 81 f9 6e 54 00 00 76 19}  //weight: 1, accuracy: High
        $x_1_4 = {40 83 f8 0c 72 e8 8d 45 c4 50 a1 2c 80 40 00}  //weight: 1, accuracy: High
        $x_1_5 = {6a 0a 8b f0 59 f3 a5 8b 4d 50 01 59 0c ff 45 4c 83 c1 28 89 4d 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_QM_2147647401_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QM"
        threat_id = "2147647401"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 2a c2 fe c8 c0 c0 03 fe c8 2a c2 c0 c0 02 32 c2 d0 c8 02 c2 2c ?? fe c0 c0 c8 04 04 ?? c0 c0 02 fe c0 2c ?? 32 c2 d0 c8 2c ?? 32 c2 aa c1 c2 08 e2 cd 8f 44 24 1c 61 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QN_2147647408_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QN"
        threat_id = "2147647408"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 5b 32 db 81 e3 ?? f0 ff ff 89 5d fc 81 c3 00 0c 00 00 83 eb 04 8b 4d 08 89 0b 8b 45 fc 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 64 8b 40 30 56 8b 40 0c 8b 70 1c ad 8b 40 08 5e c3 8b 4c 24 04}  //weight: 1, accuracy: High
        $x_1_3 = {66 49 81 c1 b5 a5 00 00 66 49 74 07 2d 00 10 00 00 eb ?? 25 ?? f0 ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 e8 10 87 04 24 50 68 00 40 00 00 6a 00 ff 74 24 f8 51 ff 64 24 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_QN_2147647408_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QN"
        threat_id = "2147647408"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec f6 40 0c 40 74 06 83 78 08 00 74 1a 50 ff 75 08 e8 e3 26 00 00 59 59 b9 ff ff 00 00 66 3b c1 75 05 83 0e ff}  //weight: 1, accuracy: High
        $x_1_2 = {eb 0c 8d 45 e0 50 53 e8 3e 00 00 00 59 59 ff 4d e4 78 07 8b 45 e0 88 18 eb 0c 8d 45 e0 50 53}  //weight: 1, accuracy: High
        $x_1_3 = {55 8b ec 83 ec 14 8b 45 0c 89 45 f4 c7 45 f8 00 00 00 00 33 c9 89 4d fc c7 45 f0 00 00 00 00 c7 45 ec 8b 02 00 00 68 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {ff ff eb 02 eb 9a c2 0f 00}  //weight: 1, accuracy: High
        $x_1_5 = "09-0a-s09a-sd9a9-sd-as-d-" ascii //weight: 1
        $x_1_6 = "09-0a-s4355" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_QP_2147647480_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QP"
        threat_id = "2147647480"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c4 38 c7 45 f4 00 00 00 00 8b 4d 08 0f af 4d 10 03 4d 14 6b c9 0a 3b 4d f4 0f 8e ?? ?? ?? ?? 8b 55 0c 89 95 7c fd ff ff 8d 85 60 fe ff ff 50 8b 0d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 89 85 88 fd ff ff 6a 17 6a 01 8b 95 7c fd ff ff 52 ff 95 88 fd ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {89 85 84 fd ff ff 8b 45 f8 50 ff 95 84 fd ff ff 89 85 5c fe ff ff 8b 8d 5c fe ff ff 89 4d f0 8b 55 f0 8b 42 02 83 e8 36 89 45 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QR_2147647561_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QR"
        threat_id = "2147647561"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 fd 46 3b bb}  //weight: 1, accuracy: High
        $x_1_2 = {68 4e fe 58 33}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 08 81 e9 4d 5a 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {66 8f 40 16 90 0f b7 4b 06}  //weight: 1, accuracy: High
        $x_1_5 = {f7 45 f8 04 00 00 00 0f 84 ?? ?? ?? ?? 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_QT_2147647602_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QT"
        threat_id = "2147647602"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 84 2f 01 00 00 39 5d 5c 0f 84 12 01 00 00 8b cf 8d 45 50 33 d2 c6 45 50 43 c6 45 51 4f c6 45 52 4d c6 45 53 50}  //weight: 1, accuracy: High
        $x_1_2 = {8b 12 6a 04 ff b0 8c 00 00 00 8b 80 88 00 00 00 03 02 83 c1 1c 50 ff 11 c6 45 04 ab c6 45 05 7a c6 45 06 49 c6 45 07 4d c6 45 08 78 c6 45 09 49}  //weight: 1, accuracy: High
        $x_1_3 = {c6 01 58 c6 41 01 4f c6 41 02 7a c6 41 03 4f c6 41 04 4d c6 41 05 4f c6 41 06 45 c6 41 07 4f c6 41 08 7e c6 41 09 4f c6 41 0a ec c6 00 78 c6 40 01 4f c6 40 02 7a c6 40 03 4f}  //weight: 1, accuracy: High
        $x_1_4 = {66 89 45 e0 6a 6c 58 66 89 45 e2 66 89 45 e4 33 c0 8d 4d dc 66 89 45 e6 88 45 da 8b 43 40 51 89 7d f8 c6 45 c4 4c c6 45 c5 64 c6 45 c6 72 c6 45 c7 46 c6 45 c8 69 c6 45 c9 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_QU_2147647611_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QU"
        threat_id = "2147647611"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 0c 51 e8 55 8b ec 83 ec 10 c7 45 f8 [0-96] 8b 45 f8 03 45 fc 8b 08 03 4d 08 8b 55 f8 03 55 fc 89 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 51 8b 55 fc 8b 45 f8 8d 4c 10 04 51 e8 55 8b ec 51 8b 45 08 8b 08 2b 4d 0c 8b 55 08 89 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_D_2147647738_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.gen!D"
        threat_id = "2147647738"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e0 fc 33 c1 83 c0 ?? 83 c0 ?? 83 c0 [0-4] a3 ?? ?? ?? 00 c1 c8 18 89 02 83 c2 04 c7 02 02 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "QueueUserAPC" ascii //weight: 1
        $x_1_3 = {8a 26 32 e0 88 26 46 c7 05 ?? ?? ?? 00 00 00 00 00 e2 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QW_2147647901_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QW"
        threat_id = "2147647901"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {27 fd fc fc 21 fd fb fc 49 fd e6 fc 24 fd e5 fc 58}  //weight: 10, accuracy: High
        $x_10_2 = {3d fd e3 fc fc fc e0 fc 18 40 19 41 09 51 36}  //weight: 10, accuracy: High
        $x_1_3 = "IiudeuyJHjd" wide //weight: 1
        $x_1_4 = "KJkljLJDkhuUHD" wide //weight: 1
        $x_1_5 = "IUDEIDJKjhdh" wide //weight: 1
        $x_1_6 = "NDJKdjkhKJND" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_QY_2147647955_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QY"
        threat_id = "2147647955"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4e 6c eb 08 34 6b 04 5b 88 01 41 42 8a 02 3c ce 75 f2 c6 01 00 8b 46 6c c3}  //weight: 10, accuracy: High
        $x_1_2 = {c7 01 9c 72 7a 82 c7 41 04 61 63 7f 79 c7 41 08 7e 7c 61 73 c7 41 0c 73 8c 71 60 c7 41 10 60 61 7c ce}  //weight: 1, accuracy: High
        $x_1_3 = {c7 02 9c 72 7a 83 c7 42 04 7f 79 7e 7c c7 42 08 61 73 73 8c c7 42 0c 71 60 60 61 66 c7 42 10 7c ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_QX_2147647959_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QX"
        threat_id = "2147647959"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 04 89 45 ?? 81 7d 00 ?? ?? 00 00 (0f 83|73) 10 00 8b 45 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 04 89 4d ?? 81 7d 00 ?? ?? 00 00 (0f 83|73) 10 00 8b 4d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c2 04 89 55 ?? 81 7d 00 ?? ?? 00 00 (0f 83|73) 10 00 8b 55 00}  //weight: 1, accuracy: Low
        $x_5_4 = {33 c0 66 8b 02 03 45 ?? 8b 4d ?? 03 4d ?? 66 89 01 06 00 8b 55 01 03 55 02}  //weight: 5, accuracy: Low
        $x_5_5 = {33 d2 66 8b 51 02 2b 55 ?? 8b 45 ?? 03 45 ?? 66 89 50 02 06 00 8b 4d 01 03 4d 02}  //weight: 5, accuracy: Low
        $x_5_6 = {33 c9 66 8b 48 02 2b 4d ?? 8b 55 ?? 03 55 ?? 66 89 4a 02 06 00 8b 45 01 03 45 02}  //weight: 5, accuracy: Low
        $x_5_7 = {33 c0 66 8b 42 02 2b 45 ?? 8b 4d ?? 03 4d ?? 66 89 41 02 06 00 8b 55 01 03 55 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_QZ_2147647963_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QZ"
        threat_id = "2147647963"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 85 40 ff ff ff eb 0a c7 85 40 ff ff ff 03 00 00 00 8b 8d 40 ff ff ff c1 e1 06 8b 55 e8 8d 84 4a 60 03 00 00 89 45 a8 c7 45 80 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 24 8b e2 68 00 80 00 00 2d 07 03 00 00 6a 00 2b c1 ff 75 20 05 41 01 00 00 ff 75 ?? 8b 45 10 8b ?? ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {42 65 65 70 00 00 b8 01 48 65 61 70 41 6c 6c 6f 63 00 59 01 47 65 74 50 72 6f 63 65 73 73 48 65 61 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_RA_2147648024_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RA"
        threat_id = "2147648024"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 be 20 00 00 00 f7 f6 3a 00 8b ?? ?? ?? ff ff 83 ?? 01 89 ?? ?? ?? ff ff 81 bd ?? ?? ?? ?? ?? ?? 00 00 73 ?? 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_RG_2147648167_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RG"
        threat_id = "2147648167"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 d0 bc 0a 00 00 8d 45 e8 50 8d 45 d0 50 68 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 8d 4d ec 51 8d 4d d4 51 68 ?? ?? 40 00 56 c7 45 d4 ?? ?? 00 00 ff 50 30}  //weight: 1, accuracy: Low
        $x_10_3 = "\\JOKER-VAIO\\" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_RH_2147648204_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RH"
        threat_id = "2147648204"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 3a 5c 4a 48 46 48 47 46 48 47 46 5c 47 48 4a 47 4a 48 47 48 5c 64 67 66 6a 67 68 67 2e 65 78 65 20 2f 6b 73 64 67 66 68 67 68 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 00 48 00 47 00 46 00 4a 00 48 00 47 00 48 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_RH_2147648204_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RH"
        threat_id = "2147648204"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 00 48 00 47 00 46 00 4a 00 48 00 47 00 48 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 14 33 c6 03 c7 89 44 24 20 89 4c 24}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4c 24 1c 33 c6 03 c7 3b c8 0f 84 ?? 00 00 00 ff 74 24 1c}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 90 03 01 01 3a 38 31 02 41 83 f9 09 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_RI_2147648230_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RI"
        threat_id = "2147648230"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 77 14 8b c6 83 fe ?? 72 ?? b8 ?? ?? 00 00 [0-4] 72 ?? 8b 57 04 eb ?? 8d 57 04 b9 ?? ?? ?? 00 e8 ?? ?? ?? ff 85 c0 75 ?? 83 fe ?? 72 ?? 83 fe ?? 0f 95 c0 [0-3] 7e ?? 6a 00 68 ?? ?? ?? 00 8b cf e8}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 8b f4 8b 65 ?? 81 c4 ?? ?? ?? 00 [0-8] 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_2_3 = {8b e8 83 c4 04 33 f6 8d 4d 01 8b 07 8a 14 30 03 c6 88 51 ff 8a 40 01 88 01 83 c6 04 83 c1 02 3b 77 04 76}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_RJ_2147648264_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RJ"
        threat_id = "2147648264"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 0f 00 c1 e3 0d 0f 00 c0 2b c8}  //weight: 1, accuracy: High
        $x_1_2 = {59 8b dd ac 32 c3 aa e2 d0 5d}  //weight: 1, accuracy: High
        $x_1_3 = {f3 a4 5e 56 33 c9 66 8b 4e 06 81 c6 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {e2 df 59 8b dd ac 32 c3 aa}  //weight: 1, accuracy: High
        $x_1_5 = {83 c6 28 e2 e5 5e 8b 46 28 03 45 fc ff e0}  //weight: 1, accuracy: High
        $x_1_6 = {e2 d5 59 8b 5d fc ac 32 c3 aa}  //weight: 1, accuracy: High
        $x_1_7 = {83 c6 28 e2 e5 5e ff 75 fc e8 ?? ?? 00 00 8b 46 28 03 45 fc ff d0}  //weight: 1, accuracy: Low
        $x_1_8 = {ac 32 c3 aa f7 c1 01 00 00 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_RK_2147648271_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RK"
        threat_id = "2147648271"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {64 8b 36 e9}  //weight: 2, accuracy: High
        $x_1_2 = {3d 56 4a 84 53 e9}  //weight: 1, accuracy: High
        $x_1_3 = {3d 8f a8 a8 24 e9}  //weight: 1, accuracy: High
        $x_1_4 = {68 66 ae 5b 2d e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_RM_2147648378_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RM"
        threat_id = "2147648378"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 32 c3 aa f7 c1 01 00 00 00 74 09 60 6a 01 e8 ?? ?? ?? ?? 61 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 46 28 03 45 fc ff d0 68 00 80 00 00 6a 00 ff 75 fc e8 ?? ?? ?? ?? 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_RN_2147648388_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RN"
        threat_id = "2147648388"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 fb 0f 0f 0f 0f 0f 84}  //weight: 1, accuracy: High
        $x_1_2 = {81 fb 08 09 0a 0b 0f 84}  //weight: 1, accuracy: High
        $x_1_3 = {4f 50 45 4e 47 6c 33 32 2e 44 4c 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_RN_2147648388_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RN"
        threat_id = "2147648388"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 00 57 00 45 00 6a 00 6c 00 6b 00 6a 00 70 00 6f 00 69 00 70 00 6f 00 69 00 64 00 66 00 6a 00 68 00 73 00 6b 00 6a 00 64 00 68 00 66 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "T:\\test.exe sys" wide //weight: 1
        $x_1_3 = {8b 5c 24 10 33 de 8d 84 18 2d 60 00 00 83 f8 08}  //weight: 1, accuracy: High
        $x_1_4 = {bb fe ef ff ff 89 5d fc c7 45 fc f9 ef ff ff}  //weight: 1, accuracy: High
        $x_1_5 = {33 c6 03 c7 89 44 24 20 8b 44 24 14 33 c6 03 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_RO_2147648462_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RO"
        threat_id = "2147648462"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c6 33 ce 33 de 8d 84 18 ?? ?? 00 00 33 d2 03 cf f7 f1 6a 7f c1 e2 03 89 55 f8 8b 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f4 33 c6 2b d8 2b df 33 de 81 fb fe cf ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {8d 45 ec c7 45 ec ?? ?? ?? 00 89 45 d4 33 f6 b9 00 31 00 00 8b 55 ec 8b c6 83 e0 03 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 38 2b d1 0b d7 89 10 33 d2 8b 7d ec 8b c2 83 e0 03 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_RP_2147648518_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RP"
        threat_id = "2147648518"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f8 c7 44 24 28 bb 4e 10 da 8d 85 ?? ?? 40 00 ff d0 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_RQ_2147648626_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RQ"
        threat_id = "2147648626"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 42 24 03 45 d4 8b 4d ?? 66 8b 14 48 66 89 95 24 ff ff ff [0-129] 8b 51 1c 03 55 d4 8b 85 24 ff ff ff 25 ff ff 00 00 8b 04 82 03 45 d4 eb 07 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {89 85 38 ff ff ff 8b 85 38 ff ff ff 89 85 34 ff ff ff c7 45 fc 00 00 00 00 8b 8d 34 ff ff ff e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8d 8d 3c ff ff ff 51 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 95 30 ff ff ff 89 95 2c ff ff ff c6 45 fc 01 8b 8d 2c ff ff ff e8 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_RR_2147648628_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RR"
        threat_id = "2147648628"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 50 2e 89 48 39 8d 90 a7 02 00 00 8d 88 b6 02 00 00 89 50 44 89 48 4f c6 40 60 bf 8b 15 ?? ?? ?? ?? 89 50 61 c6 40 65 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_RS_2147648638_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.RS"
        threat_id = "2147648638"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 95 64 fe ff ff 83 bd 48 fe ff ff 10 76 0c c7 85 48 fe ff ff 40 00 00 00 eb 0a c7 85 48 fe ff ff 04 00 00 00 61 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SC_2147648919_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SC"
        threat_id = "2147648919"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 40 8b c4 8b 4c 24 48 51 6a 00 68 00 00 10 00 50 ff 15 ?? ?? ?? ?? ba ?? ?? ?? ?? 25 ff 00 00 00 03 54 24 44 8d 48 10 83 e0 48 03 d1 89 14 04 8b 04 24 8d 4c 24 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SD_2147648924_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SD"
        threat_id = "2147648924"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 ca 05 89 55 e4 ba 0d 0f 00 00 ff 4d 24 81 ea 4a 0f 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c1 eb 07 c1 e3 08 89 5d e4 bb e2 08 00 00 c1 cb 1d 81 c3 98 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c0 c8 19 c0 c0 0e 2c 08 c0 c0 15 c0 c8 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SE_2147648937_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SE"
        threat_id = "2147648937"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 45 08 0f 85 ?? ?? 00 00 8b 52 04 8b 45 08 03 40 3c 8b 40 28 03 45 08 89 42 [0-32] e8 8d 64 24 [0-32] ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SF_2147648966_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SF"
        threat_id = "2147648966"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b c3 0f 84 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {0a c0 74 2e 8a 06 46 8a 27 47 38 c4 74 f2 2c 41 3c 1a}  //weight: 2, accuracy: High
        $x_2_3 = {8b 0c 86 39 19 0f 95 c1 51 50 8d 4d ?? e8 ?? ?? 00 00 ff 45 ?? 83 ?? ?? 63 7e bc}  //weight: 2, accuracy: Low
        $x_1_4 = {00 54 43 6e 65 72 76 65 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SH_2147648977_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SH"
        threat_id = "2147648977"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb c2 8b 45 08 03 45 f8 8a 08 2a 4d f4 8b 55 08 03 55 f8 88 0a 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {8a 00 32 04 11 8b 4d 08 03 4d f8 88 01 e9}  //weight: 1, accuracy: High
        $x_1_3 = {33 d2 f7 f1 39 55 f0 73 23 8b 45 f0 03 45 fc 33 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SI_2147648984_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SI"
        threat_id = "2147648984"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 52 6c 85 37 e9}  //weight: 1, accuracy: High
        $x_1_2 = {68 a0 64 18 09 e9}  //weight: 1, accuracy: High
        $x_1_3 = {3d 49 15 8b 24 e9}  //weight: 1, accuracy: High
        $x_1_4 = {3d 90 f7 a7 53 e9}  //weight: 1, accuracy: High
        $x_1_5 = {68 c6 bd 23 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_SJ_2147648988_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SJ"
        threat_id = "2147648988"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 8b 40 28 03 45 08 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {81 7d f8 40 1a cd 00 75 04}  //weight: 1, accuracy: High
        $x_1_3 = {ff 72 10 8b 42 14 03 45 f0 50 8b 42 0c 03 45 08 50 e8}  //weight: 1, accuracy: High
        $x_1_4 = {64 73 6b 68 02 00 00 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_SK_2147648999_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SK"
        threat_id = "2147648999"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec ff 15 ?? ?? ?? ?? 8b 4d 08 89 01 8b 55 08 8b 02 69 c0 a4 03 00 00 8b 4d 0c 8b 11 8d 44 02 9c a3 ?? ?? ?? ?? 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 09 8b 55 ?? 83 c2 04 89 55 ?? 81 7d ?? ?? ?? 00 00 0f 83 ?? ?? ?? ?? 8b 45 ?? 25 ff 00 00 00 83 f8 01 75 ?? 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d ?? 00 74 ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d ?? 00 74 ?? 6a 00 6a 00 8b 4d ?? 51 8b 55 ?? 52 ff 15 ?? ?? ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SL_2147649013_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SL"
        threat_id = "2147649013"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c7 8d 8c 08 22 10 00 00 33 cf}  //weight: 1, accuracy: High
        $x_1_2 = {5e f7 f6 81 fa 83 00 00 00 0f}  //weight: 1, accuracy: High
        $x_1_3 = {be c1 d0 ff ff 81 fe dc cf ff ff 0f}  //weight: 1, accuracy: High
        $x_1_4 = {81 fe c2 cf ff ff 0f}  //weight: 1, accuracy: High
        $x_1_5 = {b8 40 09 98 08}  //weight: 1, accuracy: High
        $x_1_6 = {be 92 ac f7 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_SM_2147649052_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SM"
        threat_id = "2147649052"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 28 03 c7 89 45 08 8b 45 08 ff d0 6a 00}  //weight: 1, accuracy: High
        $x_1_2 = {32 ca ff 45 0c ff 45 08 83 7d 08 10 75 15 33 db 89 5d 08 eb 10 ff 45 0c 83 7d 0c 04 75 07 89 5d 0c eb 02 33 db 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SO_2147649345_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SO"
        threat_id = "2147649345"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ea 51 81 fa fc 01 00 00 76 22 8b 45 e4 25 ff ff 00 00 b9 06 00 00 00 2b c8 8b c1 99 8b 4d e8 23 c8 8b 45 ec 23 c2 89 0d 14 30 41 00 c7 45 cc 20 0d 01 00 eb}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d cc 83 e9 01 89 4d cc 83 7d cc 00 0f ?? ?? 00 00 00 8b 4d e8 83 c1 19 8b 75 ec 83 d6 00 8b 45 e4 25 ff 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SQ_2147649396_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SQ"
        threat_id = "2147649396"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 8c 11 5c 4a 00 00 83 c4 2c 3b c1}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0e 3b cf 0f 86 08 00 00 00 49 89 0e e9}  //weight: 1, accuracy: High
        $x_1_3 = {05 67 06 76 00 3b c1 0f 85}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 b6 fa fe 11 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SS_2147649504_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SS"
        threat_id = "2147649504"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 fa 00 00 00 c6 00 00 40 49 75 ?? be 64 00 00 00 68 c8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 28 8b 01 89 02 8b 41 04 89 42 04 66 8b 49 08 66 89 4a 08 8d ?? ?? ?? 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {b0 4c 53 88 ?? ?? ?? 88 ?? ?? ?? ?? ?? ?? 55 b3 65 8d ?? ?? ?? 56 57 c6 ?? ?? ?? 6f c6 ?? ?? ?? 61}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 73 64 75 6d 70 31 35 30 61 75 72 6f 2e 74 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_ST_2147649507_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ST"
        threat_id = "2147649507"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 8a c8 d3 c0 59 51 8a c8 d3 c0 59}  //weight: 1, accuracy: High
        $x_1_2 = {74 09 60 6a 01 e8 ?? ?? ?? ?? 61 e2 b4}  //weight: 1, accuracy: Low
        $x_1_3 = {05 01 01 01 00 05 01 01 01 01 81 f9 35 7c 01 00 72 03}  //weight: 1, accuracy: High
        $x_1_4 = {eb 00 c7 45 ?? 17 de c0 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_SU_2147649552_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SU"
        threat_id = "2147649552"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 06 75 ?? 53 ff 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ef be ad de}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 18 8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 ff e1}  //weight: 1, accuracy: High
        $x_1_3 = {8b 72 19 6a 04 68 00 30 00 00 81 c6 00 02 00 00 56 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_SV_2147649603_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SV"
        threat_id = "2147649603"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 e8 eb 02 00 00 c1 e8 02 eb 02 00 00 c1 e8 04 05 81 11 10 00 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {e2 db e9 4b f6 ff ff 59 5e a1 a2 10 10 00 30 06 eb e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SW_2147649793_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SW"
        threat_id = "2147649793"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 40 00 33 ?? 83 ?? 04 8b ?? fc 89 [0-5] 83 ?? 04 81 [0-5] 89 d0 fb a4 81 [0-5] ac 89 a2 73 83 ?? 04 [0-2] 78 05 00 00 75 ?? 6a 00 e8 ?? ?? 00 00 5d c2 ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {10 40 00 5e b9 78 05 00 00 83 ?? 04 8b ?? fc 89 ?? ?? 83 ?? 04 81 ?? ?? 89 d0 fb a4 81 ?? ?? ac 89 a2 73 83 ?? 04 83 ?? 00 75 ?? 6a 00 e8 ?? ?? 00 00 5d c2 ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {10 40 00 bb 78 05 00 00 85 db 74 ?? 83 ?? 04 83 ?? 04 8b ?? fc 89 ?? ?? fe ff ff 83 ?? 04 81 ?? ?? ?? ?? ?? 89 d0 fb a4 81 ?? ?? ?? ?? ?? ac 89 a2 73 eb ?? e8 ?? ?? 00 00 5d c2 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_SX_2147649801_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SX"
        threat_id = "2147649801"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d6 83 c0 19 64 ff 30 58 ff 70 34 58 83 c7 05 83 e8 06 03 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SZ_2147649896_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SZ"
        threat_id = "2147649896"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 f8 50 6a 40 ff 77 50 ff 75 fc ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 30 00 00 68 00 00 10 00 6a 00 ff 15 ?? ?? ?? ?? 8b f0 8d 45 fc 50 ff 75 14 8d 45 f8 ff 75 08 c6 06 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_SY_2147649897_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.SY"
        threat_id = "2147649897"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 33 5a 31 c2 52 8f 06 83 eb fc 8d 76 04 83 c1 ff 83 f9 00 75 e4 61 68 ?? ?? ?? ?? c3 16 00 c7 04 24 ?? ?? ?? ?? 5b 68 00 5e eb 00 8d 80}  //weight: 2, accuracy: Low
        $x_1_2 = {8d 64 24 fc c7 04 24 ?? ?? ?? ?? 59 83 ec 04 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_2_3 = {60 6b c0 00 83 ec 04 c7 04 24 ?? ?? ?? ?? 5b 01 d8 31 c9 81 c1 ?? ?? ?? ?? 35 ?? ?? ?? ?? d3 c0 05 ?? ?? ?? ?? 49 21 c9 75 ef 83 eb 01 83 fb 00 75 dd b9 ?? ?? ?? ?? 68}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 13 31 c2 52 8f 06 43 43 43 43 83 ee fc 49 09 c9 74}  //weight: 2, accuracy: High
        $x_2_5 = {31 c2 8d 64 24 fc 89 14 24 8f 06 83 c3 04 46 83 c6 01 83 c6 01 46 83 c1 ff 85 c9 74}  //weight: 2, accuracy: High
        $x_1_6 = {83 e9 01 83 f9 00 75 ?? 83 c3 ff 21 db 74 13 00 01 d8 b9 ?? ?? ?? ?? 35 ?? ?? ?? ?? d3 c0 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_TA_2147649911_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TA"
        threat_id = "2147649911"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 03 00 00 00 ad 03 c3 ab e2 fa 8b 74}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 24 20 3b c8 75 0a 8b fa ae 75 fd 4f}  //weight: 1, accuracy: High
        $x_1_3 = {33 d2 4a 42 ad 03 c3 6a 00 50 e8}  //weight: 1, accuracy: High
        $x_1_4 = {6b 65 72 6e 75 d9 81}  //weight: 1, accuracy: High
        $x_1_5 = {eb 7f b2 08 2a d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_TD_2147650246_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TD"
        threat_id = "2147650246"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 45 e0 83 7d e0 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d f4 8b 91 a4 00 00 00 89 55 fc 8b 45 f4 8b 4d 08 03 88 a0 00 00 00 89 4d e8 8b 55 e8 89 55 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_TF_2147650444_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TF"
        threat_id = "2147650444"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 14 83 e0 fd 33 c1 05 bd 04 00 00 a3 ?? ?? ?? 00 c1 c8 10 eb 0c 8b c8 c1 e0 02 d1 c0 83 e0 fa eb e0 c1 c8 08 89 02 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 8b 44 24 10 83 c0 64 c7 00 c3 00 00 00 b8 00 00 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_TG_2147650550_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TG"
        threat_id = "2147650550"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc 31 c9 49 89 ca 31 c0 31 db 3e ac 32 c1 88 e9 88 d5 88 f2 b6 08 66 d1 eb 66 d1 d8}  //weight: 1, accuracy: High
        $x_1_2 = {f7 d2 f7 d1 89 d0 c1 c0 10 66 89 c8 5a 39 c2 74 0b}  //weight: 1, accuracy: High
        $x_1_3 = {8b 13 85 d2 74 30 8b 4a fc 4e 7c 2a 39 ce 7d 26 85 ff 7e 22 29 f1 39 cf 7e 02 89 cf 29 f9 01 f2 8d 04 17 e8 ?? ?? ?? ?? 8b 13 89 d8 8b 52 fc 29 fa e8}  //weight: 1, accuracy: Low
        $x_1_4 = {bf cc cc cc 0c 8a 1e 46 80 fb 20 74 f8 b5 00 80 fb 2d 74 62 80 fb 2b 74 5f 80 fb 24 74 5f 80 fb 78 74 5a 80 fb 58 74 55 80 fb 30 75 13 8a 1e 46 80 fb 78 74 48 80 fb 58 74 43 84 db 74 20 eb 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_TI_2147650693_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TI"
        threat_id = "2147650693"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fb ff ff 07 00 01 00 8b 58 3c 03 d8 ff 55 fc 80 a5 ?? fe ff ff 00 6a 3f 89 45 fc 59 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {00 54 43 6e 65 72 76 65 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_TJ_2147650717_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TJ"
        threat_id = "2147650717"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c7 04 c7 07 ?? ?? ?? ?? 83 c7 04 c7 07 ?? ?? ?? ?? 83 c7 04 c7 07 ?? ?? ?? ?? 83 c7 04 c7 07 ?? ?? ?? ?? 83 c7 04 c7 07 ?? ?? ?? ?? 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 20 53 56 57 e8 ?? ee ff ff 33 db 39 1d f8 a2 41 00 89 45 f8 89 5d fc 89 5d f4 89 5d f0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 74 24 08 85 f6 0f 84 81 01 00 00 ff 76 04 e8 ?? dd ff ff ff 76 08 e8 ?? dd ff ff ff 76 0c e8 ?? dd ff ff ff 76 10 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {64 33 64 38 00 75 73 65 72 33 32 00 6e 74 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_TK_2147650783_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TK"
        threat_id = "2147650783"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 89 45 f8 8b 4d 08 03 4d fc 8a 55 f8 88 11}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 08 89 45 fc 8b 7e 20 8b 36 80 3f 6b 74 ?? 80 3f 4b 74}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 51 04 83 ea 08 d1 ea 89 55 f4 8b 45 08 83 c0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_TL_2147650872_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TL"
        threat_id = "2147650872"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 30 04 00 00 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 10 25 ff 00 00 00 85 c0 74 ?? 8b 4d 0c 8b 11 03 55 f8 8b 45 0c 89 10 eb ?? 8b 4d 0c 8b 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_TN_2147650927_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TN"
        threat_id = "2147650927"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 eb 00 5a 51 a1 ?? ?? ?? ?? eb 14 83 e0 fd 33 c1 05 bd 04 00 00 a3 ?? ?? ?? ?? c1 c8 10 eb 0c 8b c8 c1 e0 02 d1 c0 83 e0 fa eb e0 c1 c8 08 89 02 83 c2 04 c7 02 02 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_TP_2147651003_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TP"
        threat_id = "2147651003"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Plat\\illBo\\mbomB\\ombomosP\\latillosPlB\\ombomBombonBa.vbp" wide //weight: 1
        $x_1_2 = {01 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 2c 00 20 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 00 00 00 00 40 00 1e}  //weight: 1, accuracy: High
        $x_1_3 = "BommVB5!" ascii //weight: 1
        $x_1_4 = {52 b9 58 00 00 00 89 45 e4 ff d6 50 e8 56 07 00 00 8d 45 e8 b9 5b 00 00 00 50 ff d6 50 e8 45 07 00 00 8d 4d e8 51 b9 50 00 00 00 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_TQ_2147651030_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TQ"
        threat_id = "2147651030"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 4d ec 76 12 8a 14 18 80 f2 ?? 80 c2 ?? 88 14 18 40 3b 45 ec 72 ee 8b d3 8d 45 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 94 15 bc fe ff ff c1 e0 06 03 45 bc 41 c1 e0 06 03 c7 c1 e0 06 03 c2 3b 75 10 73 25 8b 7d 0c 8b d0 c1 ea 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_TT_2147651230_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TT"
        threat_id = "2147651230"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 0f b7 49 16 81 f2 ?? ?? ?? ?? 81 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 50 24 81 7d f8 88 13 00 00 76 cc}  //weight: 1, accuracy: High
        $x_1_3 = {ff 70 50 6a 00 ff d1 83 65 f8 00 89 45 fc 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_4 = {eb 0a 80 f1 ?? 80 (c1|e9) ?? 88 08 40 42 8a 0a 80 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_TV_2147651245_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TV"
        threat_id = "2147651245"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a5 66 a5 a4 eb ?? (8b|ff|8f) [0-8] 83 c0 01 [0-16] 0f 73 ?? 6a 06 6a 00 6a 00 6a 00 68 c0 12 (40|00) (10|00) ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 f8 57 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_TX_2147651274_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TX"
        threat_id = "2147651274"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 64 8b 40 30 56 8b 40 0c 8b 70 1c ad 8b 40 08 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 81 34 24 ?? ?? ?? ?? ff 75 e0 e8 ?? ?? ?? ?? 83 c4 08 50 e8 00 00 00 00 80 2c 24 0e 8b 04 24 8b 40 01 83 c0 05 01 04 24 58}  //weight: 1, accuracy: Low
        $x_1_3 = {e8 00 00 00 00 5b 32 db 81 e3 00 f0 ff ff 89 5d fc 81 c3 00 0c 00 00 83 eb 04 8b 4d 08 89 0b 8b 45 fc 5b}  //weight: 1, accuracy: High
        $x_1_4 = {0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_TZ_2147651613_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TZ"
        threat_id = "2147651613"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 88 0b f6 ff ff 03 88 2b f9 ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 0b f6 fd 7f 8b 80 ed 0c 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_UA_2147651620_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UA"
        threat_id = "2147651620"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b cc 8b 44 24 04 68 ?? 7b 07 00 ?? 68 00 00 02 00 51 ff 15 ?? ?? ?? ?? 8b c8 ba ?? ?? ?? ?? c1 e9 1c 03 14 24 c1 e0 04 03 c2 8d 4c 0c ?? 89 01 51 68 00 00 02 00 51 ff 15 ?? ?? ?? ?? 83 c4 ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_UB_2147651629_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UB"
        threat_id = "2147651629"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 03 68 ?? ?? 40 00 48 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e8 03 68 ?? ?? 40 00 68 ?? ?? 40 00 48 ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {83 e8 03 68 ?? ?? 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 48 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {83 e8 03 68 ?? ?? 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 48 ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {53 56 57 bb 01 00 00 00 8b 7c 24 14 50 53 51}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 00 00 00 00 00 00 50 00 4f 00 50 00 4f 00 41 00 4b 00}  //weight: 1, accuracy: High
        $x_3_7 = {c7 85 c4 fe ff ff 9c 07 00 00 c7 85 dc fe ff ff c5 2f 02 00 c7 85 e0 fe ff ff a1 a3 0a 00 c7 85 d4 fe ff ff 74 ce 02 00 6a 04 8d 85 d4 fe ff ff 50 8d 8d c4 fe ff ff 51 e8 2b f2 ff ff 8b 95 c4 fe ff ff 8b 85 c4 fe ff ff 83 e8 01 89 85 c4 fe ff ff 85 d2 0f 84 ae 00 00 00 8b b5 e0 fe ff ff 81 c6 92 b6 a9 00 6a 76 e8 db f3 ff ff 0f b7 c8 2b f1 6a 50 e8 cf f3 ff ff 0f b7 d0 03 95 dc fe ff ff 03 d6 89 95 dc fe ff ff 8b 85 dc fe ff ff 05 53 af 00 00 8b 8d e0 fe ff ff 2b c8 89 8d e0 fe ff ff c7 85 cc fe ff ff 04 27 00 00 8b 95 cc fe ff ff 8b 85 cc fe ff ff 83 e8 01 89 85 cc fe ff ff 85 d2 74 3d 6a 43 e8 7b f3 ff ff}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_TY_2147651637_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.TY"
        threat_id = "2147651637"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 88 00 02 00 00 81 39 41 63 74 78 74}  //weight: 2, accuracy: High
        $x_1_2 = "@d9A!u" ascii //weight: 1
        $x_1_3 = {83 c1 18 83 c1 18 64 8b 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_UC_2147651742_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UC"
        threat_id = "2147651742"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 66 c7 00 e8 00 ff 36 e8 ?? ?? ?? ?? 6a 02 66 c7 00 22 00 ff 36 e8 ?? ?? ?? ?? 6a 03 66 89 18 ff 36 e8 ?? ?? ?? ?? 6a 04 66 89 18 ff 36 e8 ?? ?? ?? ?? 6a 05 66 89 18 ff 36 e8 ?? ?? ?? ?? 6a 06 66 c7 00 68 00 ff 36 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {68 88 00 00 00 66 c7 00 01 00 ff 36 e8 ?? ?? ?? ?? 68 89 00 00 00 66 c7 00 c7 00 ff 36 e8 ?? ?? ?? ?? 68 8c 00 00 00 66 c7 00 eb 00 ff 36 e8 ?? ?? ?? ?? 68 8d 00 00 00 66 c7 00 7c 00 ff 36 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_UF_2147651864_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UF"
        threat_id = "2147651864"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 8a c8 d3 c0 59 51 8a c8 d3 c0 59 05 01 01 01 00 05 01 01 01 01 81 f9 ?? ?? ?? ?? 72 03 89 45 ?? e2 ?? 59 8b 5d ?? ac 32 c3 aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_UG_2147651878_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UG"
        threat_id = "2147651878"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f2 6c 80 c2 4d 88 11}  //weight: 1, accuracy: High
        $x_1_2 = {50 68 c2 24 53 00 05 b6 da ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d ec 33 ce 33 c6 8d 84 01 4a 25 00 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_UG_2147651878_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UG"
        threat_id = "2147651878"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 56 04 85 c0 75 57 60 8b 7d ec 57 03 7d e8 b0 68 aa 8b 45 fc ab b0 c3 aa 8b 4d e4 5e 8b 7d e0 f3 a4 61 8b 45 d4 50 8b 07 50 ff 56 08}  //weight: 1, accuracy: High
        $x_1_2 = {60 8b 4d fc 8b 75 f8 8b 7d f4 ad 89 c2 51 c1 e9 02 ad 31 d0 ab e2 fa 59 83 e1 03 83 f9 00 74 06 ac 32 c2 aa e2 fa 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_UH_2147652037_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UH"
        threat_id = "2147652037"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c6 66 8b 08 41 31 db bb 02 00 00 00 4b 83 fb 06 75 06}  //weight: 1, accuracy: High
        $x_1_2 = {29 d9 29 f3 89 5c 24 fc 40 8a 48 ff 3a 0d ?? ?? ?? ?? 75 d3 8a 48 01 3a 0d ?? ?? ?? ?? 75 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_UJ_2147652055_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UJ"
        threat_id = "2147652055"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 7f b8 40 00 00 00 e8 16 00 8d 0d ?? ?? ?? ?? 89 4d f8 83 6d f8 78 8b 15 ?? ?? ?? ?? 8b 12 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_UK_2147652078_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UK"
        threat_id = "2147652078"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec be 83 8c 01 00 68 80 0c 0e 00 56 4e 56 68 d0 1f 40 00 c3}  //weight: 1, accuracy: High
        $x_1_2 = {65 3a 5c 73 72 63 5c 66 63 72 79 70 74 5c 52 65 6c 65 61 73 65 5c 53 5c 73 5f 68 69 67 68 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_3 = {ba 17 c3 05 00 81 c7 6e 03 00 00 2b ca 81 c2 04 7e 02 00 42 2d 77 71 08 00 c2 6c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_UK_2147652078_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UK"
        threat_id = "2147652078"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 89 45 e8 83 c0 36 89 45 f0 83 c0 0c 89 44 24 04 b9 00 ?? 00 00 51 c1 e9 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 77 0c 81 c6 b0 02 00 00 8b 4f 04 81 e9 b0 02 00 00 83 e9 42 8b fe c1 e9 04}  //weight: 1, accuracy: High
        $x_1_3 = {8a 46 0a 8a 67 0e 32 c2 32 e2 88 66 0a 88 47 0e 83 c7 10 83 c6 10}  //weight: 1, accuracy: High
        $x_1_4 = {b8 a7 50 36 79 90 ba a9 c8 d7 80 8b 4d 10 47 39 07 74 03 49 75 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_UL_2147652091_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UL"
        threat_id = "2147652091"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 4d ff 8a 4d ff 0f b6 c9 88 84 0d 38 ff ff ff 40 83 f8 40 72 dc}  //weight: 2, accuracy: High
        $x_2_2 = {58 50 58 41 c7 45 ?? 58 43 58 4b c6 45 ?? 00 03 ?? eb}  //weight: 2, accuracy: Low
        $x_2_3 = {4c 64 72 46 c7 45 ?? 69 6e 64 45 c7 45 ?? 6e 74 72 79 c7 45 ?? 46 6f 72 41 c7 45 ?? 64 64 72 65 66 c7 45 ?? 73 73 ff 50 04}  //weight: 2, accuracy: Low
        $x_1_4 = {67 c6 44 24 ?? 64 c6 44 24 ?? 69 c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24}  //weight: 1, accuracy: Low
        $x_1_5 = {75 c6 44 24 ?? 73 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24}  //weight: 1, accuracy: Low
        $x_1_6 = {73 c6 44 24 ?? 68 c6 44 24 ?? 6c c6 44 24 ?? 77 c6 44 24 ?? 61 c6 44 24 ?? 70 c6 44 24 ?? 69 c6 44 24}  //weight: 1, accuracy: Low
        $x_1_7 = "XPXAXCXK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_UO_2147652243_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UO"
        threat_id = "2147652243"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c3 de c0 de c0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0e 89 0f 83 eb 04 83 c7 04 83 c6 04 85 db 75 ef}  //weight: 1, accuracy: High
        $x_1_3 = {31 c3 66 01 c3 c1 c3 07 e2 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_US_2147652348_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.US"
        threat_id = "2147652348"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 74 18 78 58}  //weight: 1, accuracy: High
        $x_1_2 = {74 8f fc 03 f3 52}  //weight: 1, accuracy: High
        $x_1_3 = {ff 74 8f fc 5e}  //weight: 1, accuracy: High
        $x_1_4 = {58 0f b7 7c 4a fe 03 1c b8}  //weight: 1, accuracy: High
        $x_1_5 = {33 55 fc 33 ca 68 00 00 00 00 8f 43 0c}  //weight: 1, accuracy: High
        $x_1_6 = {74 13 49 75 ?? 58 c1 e0 ?? c1 e0 ?? d1 e0 5e}  //weight: 1, accuracy: Low
        $x_1_7 = {0c 20 c1 c2 ?? c1 c2 ?? c1 ca ?? c1 c2 ?? 32 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_UT_2147652365_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UT"
        threat_id = "2147652365"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 82 58 01 00 00 4b 8b 45 08 c6 80 59 01 00 00 65 8b 4d 08 c6 81 5a 01 00 00 72 8b 55 08 c6 82 5b 01 00 00 6e 8b 45 08 c6 80 5c 01 00 00 65 8b 4d 08 c6 81 5d 01 00 00 6c 8b 55 08 c6 82 5e 01 00 00 33 8b 45 08 c6 80 5f 01 00 00 32 8b 4d 08 c6 81 60 01 00 00 2e 8b 55 08 c6 82 61 01 00 00 64 8b 45 08 c6 80 62 01 00 00 6c 8b 4d 08 c6 81 63 01 00 00 6c}  //weight: 1, accuracy: High
        $x_1_2 = {c6 80 bc 00 00 00 5e 8b 4d 08 c6 81 bd 00 00 00 3a 8b 55 08 c6 82 be 00 00 00 72 8b 45 08 c6 80 bf 00 00 00 3a}  //weight: 1, accuracy: High
        $x_1_3 = {c6 42 7c 47 8b 45 08 c6 40 7d 65 8b 4d 08 c6 41 7e 74 8b 55 08 c6 42 7f 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_UV_2147652505_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UV"
        threat_id = "2147652505"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {64 8b 40 30 56 8b 40 0c 8b 70 1c ad 8b 40 08}  //weight: 10, accuracy: High
        $x_10_2 = "hel32hkern" ascii //weight: 10
        $x_1_3 = {68 21 dc a9 5d ff 75 e0}  //weight: 1, accuracy: High
        $x_1_4 = {68 62 67 8d a4 ff 75 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_UW_2147652519_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UW"
        threat_id = "2147652519"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d1 ea f7 d0 40 29 04 55 ?? ?? 00 00 b8 00 00 00 00 f8 74 ?? 68 ?? ?? ?? ?? 58 03 c0 8d 04 01 f8 ff 20}  //weight: 5, accuracy: Low
        $x_1_2 = {8b 04 24 57 bf ?? ?? 40 00 87 3c 24 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {f8 f2 fc eb 00 0f 83 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_UX_2147652568_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UX"
        threat_id = "2147652568"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 10 05 e9 00 00 00 05 b8 0b 00 00 c7 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 1e 32 d8 88 1e eb}  //weight: 1, accuracy: High
        $x_1_3 = {59 d1 c0 d1 e0 d1 c0 86 e0 80 e4 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_UY_2147652680_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UY"
        threat_id = "2147652680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 10 6a 00 68 57 04 00 00 89 (8d ?? ??|?? ??) ff d3 81 (7d ??|bd ?? ??) 31 31 31 31 (0f 84|74)}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 02 00 02 00 6a 00 50 52 89 4d f4 ff d6 81 bd ?? ?? ff ff 01 00 34 00 e9 (74|0f 84)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_UZ_2147652712_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.UZ"
        threat_id = "2147652712"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 51 8b 4d 0c 33 d2 f7 f1 59 4e 8a 06 86 04 3a 88 06 58 49 0b c9 75 e3}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 08 81 e9 4d 5a 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff 75 08 8f 46 18 ff 75 10 8f 46 1c ff 75 14 8f 46 20 eb 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_VA_2147652737_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VA"
        threat_id = "2147652737"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 00 83 e8 2d ff e0 cc cc cc cc cc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 95 f0 fd ff ff 8a 0c 4a 88 8c 28 e0 fc ff ff}  //weight: 1, accuracy: High
        $x_1_3 = "help.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_VA_2147652737_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VA"
        threat_id = "2147652737"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {dc 00 00 40 8b 0d ?? ?? 01 01 89 01 a1 ?? 3b 01 01 2b 05 ?? 44 01 01 85 c0 74 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {01 01 0f 86 1e 02 00 00 83 65 ec 00 83 7d e8 ff 75 1d e8}  //weight: 1, accuracy: High
        $x_1_3 = {3b 01 01 0f b6 49 10 89 04 8d ?? ?? 01 01 a1 ?? 3b 01 01 40 a3 ?? 3b 01 01 eb a0}  //weight: 1, accuracy: Low
        $x_1_4 = {3b 01 01 88 01 a1 ?? 3b 01 01 25 f0 01 00 00 a3 ?? 3b 01 01 e9 ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VB_2147652741_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VB"
        threat_id = "2147652741"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 8a 14 08 30 91 ?? ?? ?? ?? 41 83 f9 0c 7e cb 53}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 e6 2b f2 d1 ee 03 f2 c1 ee 04 8d 04 f5 00 00 00 00 2b c6 03 c0 03 c0 ba ?? ?? ?? ?? 2b d0 8a 04 0a 30 81}  //weight: 1, accuracy: Low
        $x_1_3 = {41 83 f9 12 7e cb b8 03 00 00 00 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VC_2147652778_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VC"
        threat_id = "2147652778"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 9c 80 0c 24 01 9d 0f 82 46 9c 80 0c 24 01 9d 0f 82 8b 83 ?? ?? ?? 00 9c 80 0c 24 01 9d 0f 82 03 83 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VC_2147652778_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VC"
        threat_id = "2147652778"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 44 78 fe 04 80 88 45 f7 [0-32] eb 8d 45 f0 0f b6 55 f7 32 d3 b9 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 02 3d 92 00 00 c0 7f 2c 74 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VC_2147652778_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VC"
        threat_id = "2147652778"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d0 4a 75 83 50 58 60 8b}  //weight: 1, accuracy: High
        $x_1_2 = {fe c0 f6 d8 04 9d fe c0 d0 c8 fc 90 aa 49 0f}  //weight: 1, accuracy: High
        $x_1_3 = {ac 8b d2 fc 09 c0 d0 c8 f6 d8 34 e1 fc d0 c0 fe c0 d0 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VC_2147652778_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VC"
        threat_id = "2147652778"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 f7 57 06 f2 e9}  //weight: 1, accuracy: High
        $x_1_2 = {68 ce 8a 23 69 e9}  //weight: 1, accuracy: High
        $x_1_3 = {68 8f b0 e9 11 e9}  //weight: 1, accuracy: High
        $x_1_4 = {68 60 d8 0d da e9}  //weight: 1, accuracy: High
        $x_1_5 = {68 d6 25 22 cb e9}  //weight: 1, accuracy: High
        $x_1_6 = {81 f9 b1 6b 89 31 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_VC_2147652778_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VC"
        threat_id = "2147652778"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 00 ff ff ff 40 8a 90 ?? ?? ?? ?? 30 14 1e a1 ?? ?? ?? ?? 46 3b f0 72 8b a1 ?? ?? ?? ?? 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 80}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 2a 33 d2 8a d3 03 d6 03 c2 25 ff 00 00 00 8b f0 8a 86 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 41 81 f9 00 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VC_2147652778_5
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VC"
        threat_id = "2147652778"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 00 00 00 00 b9 04 00 00 00 53 e2 fd 68 ?? ?? ?? ?? 53 53 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? bb 00 00 00 00 53 53 53 53 68 ?? ?? ?? ?? 53 53 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {56 6a 01 e8 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 02 75 f0 eb 19 46 50 83 c0 78 48 b8 ?? ?? ?? ?? c7 00 00 00 00 00 58 e2 d3 e9 f7 d6 ff ff 59 5e a1 ?? ?? ?? ?? 8a 1e 32 d8 88 1e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QO_2147652787_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QO"
        threat_id = "2147652787"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b7 2d 40 00 0f 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (30|31|32|33|36|37) 91 01 c0 (00|01|02|03|06|07) 21 03 80 (00|01|02|03|06|07)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VD_2147652894_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VD"
        threat_id = "2147652894"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 0f 68 19 2b 90 95 ff 75 e0 e8 ?? ?? ff ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {68 26 80 ac c8 ff 75 e0 e8 ?? ?? ff ff 59 59 8b 4d d8 89 41 0c 68 5f 70 35 3a ff 75 e0 e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VF_2147653223_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VF"
        threat_id = "2147653223"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff e5 c3 2a 2e 2a 00 55 8b ec 81}  //weight: 1, accuracy: High
        $x_1_2 = {f3 a4 5e 56 33 c9 66 8b 4e 06 81 c6 f8 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 46 28 03 45 ec ff d0 68 00 80 00 00 6a 00 ff 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VH_2147653232_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VH"
        threat_id = "2147653232"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 ba ?? ab 40 00 90 81 ea ?? ab 40 00 90 01 d0 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {50 58 8b 02 2d ?? ?? ?? ?? 89 02 83 c2 04 e2 f2 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VG_2147653246_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VG"
        threat_id = "2147653246"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 01 01 01 01 51 90 8a c8 90 d3 c0 90 59 90 eb 10}  //weight: 1, accuracy: Low
        $x_1_2 = {e2 bb 59 8b 1d ?? ?? 00 0d ac 90 32 c3 90 aa f7 c1 01 00 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VI_2147653362_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VI"
        threat_id = "2147653362"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 50 6a ff 8d 8c 24 ?? ?? ?? ?? 51 6a ff 8d 8c 24 ?? ?? ?? ?? 51 50 8b 44 24 ?? 2b c6 33 c3 6a 07 50 8d 84 24 ?? ?? ?? ?? 50 8b 44 24 ?? 8b 40 ?? ff 30 ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 00 85 c9 0f 85 09 00 00 00 04 50 34 c0 e9 16 00 00 00 8b 4d c4 80 e9 30 80 f1 30 2a c1 8b 4d c0 80 e9 30 80 f1 30 d2 c8}  //weight: 1, accuracy: High
        $x_1_3 = {03 c3 8d 14 08 02 cb 8a c1 80 e1 03 24 1f f6 e9 b1 fe 2a c8 00 0a 43 e9 ?? ?? ?? ?? 8b 45 f0 83 e9 80 89 4d 08 3b c8 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VJ_2147653477_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VJ"
        threat_id = "2147653477"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 15 38 10 40 00 8b d0 8d 4d d0 ff 15 2c 11 40 00 50 68 ?? ?? ?? ?? ff 15 38 10 40 00 8b d0 8d 4d cc ff 15 2c 11 40 00 50 68 ?? ?? ?? ?? ff 15 38 10 40 00 8b d0 8d 4d c8 ff 15 2c 11 40 00 50 68 ?? ?? ?? ?? ff 15 38 10 40 00 8b d0 8d 4d c4 ff 15 2c 11 40 00 50 68 ?? ?? ?? ?? ff 15 38 10 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VO_2147653801_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VO"
        threat_id = "2147653801"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 00 8d 85 ?? ?? ff ff 50 51 e8 ?? ?? 00 00 ff d0 8b 85 ?? ?? ff ff 3d ?? ?? 00 00 75 02 c9 c3}  //weight: 1, accuracy: Low
        $x_2_2 = {8b 45 f4 eb 02 eb 10 48 c1 e8 0f c1 e0 0f 0f b7 08}  //weight: 2, accuracy: High
        $x_1_3 = {c6 85 5c fd ff ff 5a}  //weight: 1, accuracy: High
        $x_1_4 = {8b 85 dc fd ff ff 83 e0 f0 3d ?? 92 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_VP_2147653825_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VP"
        threat_id = "2147653825"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 c2 f8 4e 75 fa 5e 8a ca d2 c8 c3}  //weight: 1, accuracy: High
        $x_1_2 = {80 c2 f8 4e 75 fa 5e 8a ca d2 c0 c3}  //weight: 1, accuracy: High
        $x_1_3 = {73 fa 0f b6 c0 8b 44 c1 04 e9 52 ff ff ff d0 e9 3a ca 73 fa 0f b6 c9 8b 04 c8 eb 81 d0 e9 3a ca 73 fa 0f b6 c9 8b 04 c8 eb ae 32 c0 5f c9 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VP_2147653825_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VP"
        threat_id = "2147653825"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 55 fd 8a 0f ff d0 88 07 fe 45 ff 8a 45 ff 3a 06 72 c4 0f b7 46 0a}  //weight: 1, accuracy: High
        $x_1_2 = {8a 56 08 8a 4e 02 ff d0 88 46 02 33 c0 66 89 46 0e 0f b7 46 06}  //weight: 1, accuracy: High
        $x_1_3 = {8a 56 04 8a 4e 01 ff d0 88 46 01 33 c0 66 89 46 0c ff 4d f8 47 0f 85 25 ff ff ff 5b b0 01 eb 30}  //weight: 1, accuracy: High
        $x_1_4 = {8b f0 85 f6 74 21 56 ff 15 ?? ?? ?? ?? 83 f8 01 75 0e 6a 00 ff 15 ?? ?? ?? ?? 50 e8 de fe ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {88 5d f8 c7 45 a8 30 00 00 00 c7 45 ac 03 00 00 00 c7 45 b0 ?? ?? ?? ?? 89 5d b4 89 5d b8 89 45 bc ff d7}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 5f 15 89 4c 24 18 8d 44 24 08 50 8b 43 fc 03 44 24 18 6a 40 ff 33 50 ff 15 ?? ?? ?? ?? 83 f8 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VR_2147654034_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VR"
        threat_id = "2147654034"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 00 00 00 80 3b c8 0f 82 ?? ?? ?? ?? 8d 4d d4 3b c8 0f 82 ?? ?? ?? ?? 8d 45 f0 3d 00 00 ff 7f 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 10 03 d7 89 14 8e 41 83 c0 04 83 f9 ?? 7c f0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 46 58 8d 4f 68 51 8b 4e 38 2b c8 51 50 ff 56 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VS_2147654053_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VS"
        threat_id = "2147654053"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 79 73 74 69 63 20 43 6f 6d 70 72 65 73 73 6f 72 00 05 00 (e8|e9)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VV_2147654070_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VV"
        threat_id = "2147654070"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ogoxu\\eralyga.pdb" ascii //weight: 1
        $x_1_2 = "Xubiqyz\\Ylame.pdb" ascii //weight: 1
        $x_1_3 = "Nizel\\ohuwah.pdb" ascii //weight: 1
        $x_1_4 = "Nikob\\Kexa.pdb" ascii //weight: 1
        $x_1_5 = {89 4d e0 81 7d e0 64 8b 02 00 7d 3b}  //weight: 1, accuracy: High
        $x_1_6 = {89 4d e4 81 7d e4 46 89 02 00 7d 27}  //weight: 1, accuracy: High
        $x_1_7 = {89 55 e0 81 7d e0 40 8d 02 00 7d 3a}  //weight: 1, accuracy: High
        $x_1_8 = {89 45 e8 81 7d e8 fa 8f 02 00 7d 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_VW_2147654079_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VW"
        threat_id = "2147654079"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 83 04 03 cb 85 c0 89 0c 86 75 03 89 75 f8 40 83 f8 19 72 ea}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 38 8b 4e 34 8b 7e 4c 83 c3 68 53 2b c8 51 50 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VX_2147654089_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VX"
        threat_id = "2147654089"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 bb e8 03 00 00 [0-32] e8 64 a1 18 00 00 00 8b d2 8b d2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c0 c0 c0 02 8b d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_VY_2147654127_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VY"
        threat_id = "2147654127"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {bb e8 03 00 00 03 06 06 06 87 ff 87 ff 87 ff 8b d2 8b d2 8b d2 8a c0 8a c0 8a c0}  //weight: 10, accuracy: Low
        $x_1_2 = {c0 c0 02 8b d2 8b d2 8b d2}  //weight: 1, accuracy: High
        $x_1_3 = {c0 c0 02 8b c0 8b c0 8b c0}  //weight: 1, accuracy: High
        $x_1_4 = {c0 c0 02 8a d2 8a d2 8a d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_VZ_2147654154_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.VZ"
        threat_id = "2147654154"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 40 08 e8 04 00 00 00 ?? ?? ?? ?? 59 ff 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WA_2147654190_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WA"
        threat_id = "2147654190"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 0f b7 49 16 35 ?? ?? ?? ?? 05}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 70 50 6a 00 ff d1 89 45 fc 8b 45 f8}  //weight: 1, accuracy: High
        $x_1_3 = {88 01 41 42 8a 02 3c 06 00 eb 08 34 ?? 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 fc 8b 41 3c 03 c1 89 45}  //weight: 1, accuracy: High
        $x_2_5 = {c7 45 d4 58 50 58 41 c7 45 d8 58 43 58 4b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_WB_2147654208_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WB"
        threat_id = "2147654208"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 8d d8 fb ff ff 8a 04 08 32 84 95 e0 fb ff ff 8b 4d 18 8b 11 8b 8d d8 fb ff ff 88 04 0a}  //weight: 1, accuracy: High
        $x_1_2 = {8b 95 a8 fe ff ff 52 8b 85 38 fe ff ff 50 ff 95 98 fb ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {0f 85 1c 02 00 00 8b 55 b4 3b 55 e4 0f 85 a6 00 00 00 8b 45 c4 2b 45 e4 83 c0 01 e9 07 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WE_2147654326_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WE"
        threat_id = "2147654326"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 8c 00 00 00 56 8b 34 d5 ?? ?? ?? ?? 33 f2 8b ca 83 e1 1f c1 c6 04 81 f6 ?? ?? ?? ?? 03 f2 d3 c6 81 f6 ?? ?? ?? ?? d3 c6 81 c6 ?? ?? ?? ?? c1 c6 0e 2b f2 c1 c6 09 89 34 90 4a 79 c9 68 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 08 33 d2 40 84 c9 74 75 81 f2 ?? ?? ?? ?? 0f b6 c9 c1 c2 0f 33 d1 8a 08 40 84 c9 75 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WF_2147654352_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WF"
        threat_id = "2147654352"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 02 3b ?? 75 0b 3d 70 17 00 00 0f 8c ?? 00 00 00 3d 1e 4e 00 00 7f 0e 41 81 f9 10 27 00 00 72 de e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 00 02 00 68 00 60 01 00 68 00 00 04 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 fb 03 7e 04 33 db eb 01 43 [0-3] c5 1e 00 00 7c ?? 8b [0-3] b8 ?? ?? ?? 00 8b f7 b9 c6 1e 00 00 2b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WG_2147654440_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WG"
        threat_id = "2147654440"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 14 03 45 f4 0f b6 08 89 4d f0 8b 55 f4 03 55 d0 89 55 f4 c7 45 c8 01 00 00 00 8b 45 f4 33 d2 f7 75 fc b9 01 00 00 00 2b c8 89 4d c8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 ec 03 45 f8 0f b6 08 03 4d f0 88 4d c7 8b 55 ec 03 55 f8 8a 45 c7 88 02 8b 4d f8 83 c1 02 89 4d f8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WI_2147654529_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WI"
        threat_id = "2147654529"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc c6 40 01 65 8b 4d fc 51 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 08 03 55 f4 8b 02 03 45 f4 8b 4d 08 03 4d f4 89 01 c7 45 fc 7c 00 00 00 8b 55 f4 81 c2 53 57 09 00 89 55 f8 c7 45 fc 7c 00 00 00 8b 45 08 03 45 f4 8b 08 33 4d f8 8b 55 08 03 55 f4 89 0a eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WI_2147654529_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WI"
        threat_id = "2147654529"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8e 88 00 00 00 89 f0 05 8e 00 00 00 8b 18 53 66 8b 5c 24 02 83 c0 04 66 8b 10 66 89 1c 24 66 89 54 24 02 5e ad 81 78 10 60 00 00 40}  //weight: 1, accuracy: High
        $x_1_2 = {e8 1f 00 00 00 8b 44 24 08 50 8b 44 24 08 50 8b 44 24 08 50 31 c0 68 fe ca ad de e9 ?? 00 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WJ_2147654591_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WJ"
        threat_id = "2147654591"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 17 32 d0 46 81 fe 00 35 0c 00 88 17 7c a1 ?? ?? ?? ?? 8d 3c 30 56 8b 35 ?? ?? ?? ?? ff d6 ff d6 ff d6 ff d6 ff d6 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b c1 f7 f5 8b 44 24 14 0f be 14 02 33 c0 8a 81 [0-16] 03 d0 81 e2 ff 00 00 00 89 15 ?? ?? ?? ?? ff ?? 8b 0d ?? ?? ?? ?? 8a 99 ?? ?? ?? ?? ff ?? 8b ?? ?? ?? ?? ?? (a1 ?? ?? ?? ??|8b ?? ?? ?? ?? ??) 8a ?? ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? (40 3d 00 01|41 81 f9 00 01) 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WK_2147654599_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WK"
        threat_id = "2147654599"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 41 31 c0 83 e8 62 f7 d0 (39 c8|83) 75 [0-11] 32 d2 01 d8 29 c1 43 8a 53 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WL_2147654661_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WL"
        threat_id = "2147654661"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d fc 1b 4d ee f7 d1 31 c0 05 5e 09 00 00 40 39 c8 75 32 d2 01 d8 29 c1 43 8a 53 ff 20 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WM_2147654719_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WM"
        threat_id = "2147654719"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 02 6a 00 68 60 d0 09 01 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 83 ec 08 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 48 3b 8d 04 08 83 c0 28 8b 00 60 b4 20 2a c4 0f 8f ?? ?? ?? ?? 61 c3}  //weight: 5, accuracy: Low
        $x_1_2 = {64 66 8b ff 8d ?? ?? ?? 00 00 33 c0 ff b0 ?? ?? ?? ?? c2 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WN_2147654808_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WN"
        threat_id = "2147654808"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 01 01 01 00 05 01 01 01 01 89 45 ?? 8b 5d ?? ac 90 32 c3 90 aa f7 c1 01 00 00 00 74 0b 85 c0 60 6a 01 e8 ?? ?? ?? ?? 61 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 00 24 00 00 8b 35 ?? ?? ?? ?? 81 c6 ca 01 00 00 8b fe 51 b9 d2 de 0e 00 8b 45 ?? d1 c0 89 45 ?? e2 f6 59 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WO_2147654836_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WO"
        threat_id = "2147654836"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 75 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? 33 31 34 32}  //weight: 1, accuracy: Low
        $x_1_2 = {33 31 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 52 75 6e}  //weight: 1, accuracy: Low
        $x_10_3 = {29 18 68 fc e3 fe f8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_WP_2147654958_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WP"
        threat_id = "2147654958"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 d2 03 35 ?? ?? ?? ?? 29 ce 47 8a 57 ff 32 c9 3a 15 ?? ?? ?? ?? 75 c8 8a 57 01 32 1d ?? ?? ?? ?? 3a 15 ?? ?? ?? ?? 75 b7 c6 05 ?? ?? ?? 00 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WQ_2147655017_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WQ"
        threat_id = "2147655017"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b 18 81 c3 41 63 74 78 e8 a2 01 00 00 8b 55 cc 52 8b 45 98 8b 75 0c 2b 30 81 c6 41 63 74 78 e8 9b fc ff ff}  //weight: 5, accuracy: High
        $x_1_2 = {89 4d cc 81 45 cc 50 1c 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 e9 6b 01 00 00 89 4d ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WR_2147655061_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WR"
        threat_id = "2147655061"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {bb e8 03 00 00 03 06 06 06 87 ff 87 ff 87 ff 8b d2 8b d2 8b d2 8a c0 8a c0 8a c0}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 54 24 fc 51 b9 ?? ?? 98 00 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-70] 49 0f 85 ?? ff ff ff 01 0c 24 59}  //weight: 10, accuracy: Low
        $x_1_3 = {c0 c0 02 8b d2 8b d2 8b d2}  //weight: 1, accuracy: High
        $x_1_4 = {c0 c0 02 8b c0 8b c0 8b c0}  //weight: 1, accuracy: High
        $x_1_5 = {c0 c0 02 8a d2 8a d2 8a d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_WS_2147655171_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WS"
        threat_id = "2147655171"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mciqtz32.dll" wide //weight: 1
        $x_1_2 = {6a 02 6a 00 68 60 d0 09 01 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 83 ec 0c e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 48 3b 8d 04 08 8b 40 28 60 b4 40 2a c4 0f 8f ?? ?? ?? ?? 61 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 09 01 c2 00 00 10 00 90 90 90 90 90 90 90 90 90 90 90 90 90 ff 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WT_2147655184_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WT"
        threat_id = "2147655184"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 63 68 41 6c 6c 6f 68 48 65 61 70 54 53 ff 55 08 89 06 6a 00 68 46 72 65 65 68 48 65 61 70 54 53 ff 55 08 89 46 04}  //weight: 1, accuracy: High
        $x_1_2 = {66 33 f6 66 ba 4d 5a 66 ad 66 33 d0 74 08 81 ee 02 10 00 00 eb ed}  //weight: 1, accuracy: High
        $x_2_3 = {ff 71 3b 58 c1 e8 08 83 c0 1c ?? ?? ?? ?? ?? ?? [0-2] 66 81 3c 08 00 90 72 06 5b e8 ?? ?? ?? ?? 33 e4}  //weight: 2, accuracy: Low
        $x_1_4 = {8d 5e fe 84 ff 75 f1 8b 76 3a 66 ba 50 45 8d 34 1e 66 ad 66 33 d0 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_WU_2147655213_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WU"
        threat_id = "2147655213"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 18 8b 86 2c 11 00 00 0b 86 38 11 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {39 9e 10 11 00 00 75 11 ff b6 08 11 00 00 57 ff 75 18 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 48 24 03 0d ?? ?? ?? ?? 89 4d c0 c7 45 cc 00 00 00 00 56 8b 7d cc c1 e7 02 03 7d d8 8b 3f 03 3d ?? ?? ?? ?? 8b 4d c4 f3 a6 74 07 5e 83 45 cc 01 eb e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WU_2147655213_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WU"
        threat_id = "2147655213"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 8b 45 08 25 00 ff ff ff 05 00 01 00 00 2d 00 01 00 00 66 81 38 4d 5a 75 f4 8b 48 3c 81 f9 00 10 00 00 77 e9 03 c8 81 39 50 45 00 00 75 df 89 45 fc 61 8b 45 fc 5f 5e 5b c9 c2 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 20 03 0d ?? ?? ?? ?? 89 4d cc 8b 48 24 03 0d ?? ?? ?? ?? 89 4d b0 c7 45 c0 00 00 00 00 56 8b 7d c0 c1 e7 02 03 7d cc 8b 3f 03 3d ?? ?? ?? ?? 8b 4d b8 f3 a6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WV_2147655218_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WV"
        threat_id = "2147655218"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 0f b7 49 16 35 ?? ?? ?? ?? 2d}  //weight: 1, accuracy: Low
        $x_1_2 = {51 ff 50 14 89 45 f8 8b 45}  //weight: 1, accuracy: High
        $x_1_3 = {ff 70 50 6a 00 ff d1 89 45 fc 8b 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_WW_2147655406_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WW"
        threat_id = "2147655406"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 0c 3a 02 0f 85 51 00 00 00 8b 45 f8 8b 55 0c 0f be 12 33 c1 2b c6 3b d0 0f}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f0 33 c3 be ?? da 9a 78 2b c6 89 45 f8 8b 45 f0 83 65 b0 00}  //weight: 1, accuracy: Low
        $x_1_3 = {89 45 ec 8b 45 dc 8b 75 08 33 c3 bf ?? da 9a 78 2b c7 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {68 d3 ef f2 0d ff 75 08 8d 45 f4 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_WY_2147655713_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WY"
        threat_id = "2147655713"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 fc 51 b9 ?? ?? ?? ?? 90}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff 4b 0f 85 ?? ?? ff ff 05 00 49 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 01 0c 24 05 00 49 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XA_2147655759_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XA"
        threat_id = "2147655759"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 30 88 45 d8 68 40 42 0f 00 6a 00 ff 15 ?? ?? ?? ?? 89 45 fc 0f be 4d d8 83 f1 34 83 f1 71 88 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 d0 8b 45 fc 03 45 d4 0f be 08 33 ca 8b 55 fc 03 55 d4 88 0a eb d1 17 00 8b 4d d4 83 c1 01 89 4d d4 81 7d d4 ?? ?? ?? ?? 7d 1d e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XB_2147655850_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XB"
        threat_id = "2147655850"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f8 83 c4 08 6a 00 68 31 3a 5c 43 89 65 dc 8b 55 dc e8 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 e8 6a 00 68 2e 44 4c 4c 68 45 4c 33 32 68 4b 45 52 4e 54 8b c8 ff d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XD_2147656006_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XD"
        threat_id = "2147656006"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c6 33 ce 2b c1 03 c7 33 c6 89 45 fc 8b 45 fc 33 c6 2b c7 0f}  //weight: 1, accuracy: High
        $x_1_2 = {8b 92 98 01 00 00 89 75 fc 8b 75 fc 8b 12 8b 76 0c 8a 14 16 80 ea ?? 80 f2 ?? 80 fa ?? 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {f7 d6 23 37 89 32 be ?? ?? 00 00 66 89 75 fc 66 8b 7d fc be ?? ?? 00 00 66 33 fe be ?? ?? 00 00 e9}  //weight: 1, accuracy: Low
        $x_1_4 = {89 06 8b 75 f8 3b f0 5e 75 08 c6 41 0a ?? c6 42 08 ?? c6 42 0a ?? c6 41 02}  //weight: 1, accuracy: Low
        $x_1_5 = "=RO<-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_XE_2147656037_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XE"
        threat_id = "2147656037"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 81 7c 24 10 dc 07 74}  //weight: 10, accuracy: High
        $x_1_2 = {81 fb 60 ae 0a 00 89 [0-5] 0f 82 ?? fe ff ff 8b 1d (5c|7c) bb 40 00 ff d3 6a 00 ff 15 ?? 80 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {60 ae 0a 00 0f 82 ?? ?? ff ff 8b 1d 7c bb 40 00 ff d3 6a 00 ff 15 ?? 80 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_XI_2147656250_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XI"
        threat_id = "2147656250"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 03 c1 8b 4d (f4|f8) 0f b7 c0 f7 d0 23 01 8b 4d (f4|f8) 89 01 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 76 0c 8a 14 16 80 ea ?? 80 f2 ?? 80 fa ?? 0f 84 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 0c 8b 09 8a 04 08 04 ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? 34 ?? 3c ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f 84}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 49 0c 8a 04 01 2c ?? 34 ?? 3c ?? 0f 84}  //weight: 1, accuracy: Low
        $x_1_5 = {66 03 c1 f7 d1 8b 4d f8 0f b7 c0 81 15 ?? ?? ?? ?? ?? ?? ?? ?? f7 d0 81 05 ?? ?? ?? ?? ?? ?? ?? ?? 23 01 89 0d ?? ?? ?? ?? 8b 4d f8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 01}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 49 0c 8b 12 8a 0c 11 80 c1 ?? 80 f1 ?? 80 f9 ?? 0f 84}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 45 10 8b 4d 0c 33 c7 03 c6 89 01 e9}  //weight: 1, accuracy: High
        $x_1_8 = {8b 40 0c 8a 04 30 04 ?? 34 ?? 3c ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 76 0c 8a 14 16 88 55 ?? 8a 55 ?? 80 c2 ?? 80 f2 ?? 80 fa}  //weight: 1, accuracy: Low
        $x_1_10 = {f7 d0 23 f0 8a 46 01 04 ?? 34 ?? 3c ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_11 = {66 03 c1 8b 4d 08 66 39 01 0f 85 08 00 66 33 c1 b9}  //weight: 1, accuracy: Low
        $x_1_12 = {66 0f be 0c 01 ba ?? ?? ?? ?? 66 2b ca ba ?? ?? ?? ?? 66 33 ca ba ?? ?? ?? ?? 66 3b ca 0f 85}  //weight: 1, accuracy: Low
        $x_1_13 = {8a 55 ff 80 c2 ?? 80 f2 ?? 80 fa ?? 0f 84}  //weight: 1, accuracy: Low
        $x_1_14 = {8b 76 0c 0f be 34 06 2b f2 33 f1 81 fe ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_15 = {8b 09 8b 5b 0c 8a 0c 0b 88 4d ff c6 45 ?? ?? c7 45 ?? ?? ?? ?? ?? 8b 4d ?? 33 ce 2b cf}  //weight: 1, accuracy: Low
        $x_1_16 = {8b 49 0c 8a 04 01 88 45 fd 8b 45 e4 8b 4d 08 33 c6 03 c7 3b c8}  //weight: 1, accuracy: High
        $x_1_17 = {05 cc 01 00 00 50 8d 45 94 50 e8 ?? ?? ?? ?? e9 b7 00 00 00 8d 85 60 ff ff ff 89 85 54 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_18 = {0f b6 4d ff 81 e9 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 88 4d ff 8a 4d ff 8a 55 ?? 3a ca 0f 84}  //weight: 1, accuracy: Low
        $x_1_19 = {8b 52 0c 8a 0c 0a 88 4d fc 8b 4d ?? 8b 55 ?? 33 c8 03 ce 3b d1 0f 84}  //weight: 1, accuracy: Low
        $x_1_20 = {8b 92 98 01 00 00 33 c6 2b c7 89 02 83 3d ?? ?? ?? ?? 00 0f 8f}  //weight: 1, accuracy: Low
        $x_1_21 = {8b 89 98 01 00 00 33 c6 2b c7 3b 01 0f 85 ?? ?? ?? ?? 8b 44 24 ?? 8b 4c 24 ?? 33 c6}  //weight: 1, accuracy: Low
        $x_1_22 = {8b 4d 10 89 45 f4 8b 01 8b 51 04 33 c6 09 00 ff 75 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_23 = {8a 94 16 73 e9 ff ff 88 94 08 f2 c2 ff ff 8b 45 dc}  //weight: 1, accuracy: High
        $x_1_24 = {8a 94 1a ef b6 ff ff 88 94 01 a5 22 00 00 8b 45 e4}  //weight: 1, accuracy: High
        $x_1_25 = {8a 84 07 5d f0 ff ff 88 84 0a d6 3c 00 00 8b 45 e8}  //weight: 1, accuracy: High
        $x_1_26 = {8a 84 06 97 43 96 02 88 04 0a 8b 45 f8}  //weight: 1, accuracy: High
        $x_1_27 = {8a 94 1a 24 ef ff ff 88 94 08 02 ac ff ff 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_28 = {8b 81 94 01 00 00 8b 08 8b 41 3c 8b 5c 08 28 be}  //weight: 1, accuracy: High
        $x_1_29 = {8b 44 c1 78 89 85 ?? ff ff ff 8b b5 ?? ff ff ff 8b 85 ?? ff ff ff 8b 95 ?? ff ff ff 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_XJ_2147656300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XJ"
        threat_id = "2147656300"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5e 56 31 1e ad 01 c3 85 c0 75 f7}  //weight: 2, accuracy: High
        $x_1_2 = {31 5a 14 83 c2 04 03 5a 10 e2 f5}  //weight: 1, accuracy: High
        $x_1_3 = {66 b9 86 02 02 00 (31|29) c9}  //weight: 1, accuracy: Low
        $x_1_4 = {66 81 e9 0b fe e8 ff ff ff ff 02 00 (31|29) c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_XL_2147656377_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XL"
        threat_id = "2147656377"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 8d 44 3d ?? 0f b6 18 33 d9 03 da 47 88 18 83 ff ?? 72 ed 33 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e7 06 03 c7 eb 0a 80 f1 ?? 80 c1 ?? 88 08 40 42 8a 0a 80 f9 ?? 75 ef c6 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XM_2147656457_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XM"
        threat_id = "2147656457"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 8b b5 6c ff ff ff 8b 11 8b 4a 0c 8b 55 d8 8a 14 32 8b 75 ec 32 14 39 8b 7d e8 88 14 01 b8 01 00 00 00 03 c3 70 6e 89 45 a8 e9}  //weight: 1, accuracy: High
        $x_1_2 = {33 ff 33 f6 b8 ff 00 00 00 3b f0 0f 8f bf 00 00 00 8b 1d ?? ?? ?? ?? 81 fe 00 01 00 00 72 02 ff d3 81 fe 00 01 00 00 72 02 ff d3 8b 55 d8 8b 4d bc 66 0f b6 04 32 66 0f b6 14 31 66 03 c7}  //weight: 1, accuracy: Low
        $x_1_3 = "<'|'>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XN_2147656529_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XN"
        threat_id = "2147656529"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 84 c0 74 09 0c 21 32 d0 c1 c2 0b eb f2}  //weight: 1, accuracy: High
        $x_1_2 = {fd ab 2d 04 04 04 04 e2 f8 fc}  //weight: 1, accuracy: High
        $x_1_3 = {68 64 6c 6c 00 68 64 6c 6c 2e 68 73 62 69 65 8b c4 50}  //weight: 1, accuracy: High
        $x_1_4 = {b0 68 aa 8b 45 08 2b 45 ?? 03 45 ?? ab b0 c3 aa}  //weight: 1, accuracy: Low
        $x_1_5 = {0f 31 50 0f 31 5a 2b c2 3d 00 02 00 00 73 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_XO_2147656575_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XO"
        threat_id = "2147656575"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c8 10 00 00 83 7c 24 1c 01 74}  //weight: 1, accuracy: High
        $x_1_2 = {81 fa 6c 6c 33 32 74 ?? 81 fa 6c 6f 72 65 74}  //weight: 1, accuracy: Low
        $x_1_3 = {89 e5 e8 00 00 00 00 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XP_2147656589_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XP"
        threat_id = "2147656589"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2d 75 34 1f d9}  //weight: 5, accuracy: High
        $x_5_2 = {33 c9 32 4c 90 03}  //weight: 5, accuracy: High
        $x_1_3 = {8b 80 a4 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 90 80 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b 90 88 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {64 ff 35 30 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_XQ_2147656590_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XQ"
        threat_id = "2147656590"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 49 3c 9c 80 0c 24 01 [0-8] 9d}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 28 9c 80 0c 24 01 [0-8] 9d}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4e 10 9c 80 0c 24 01 [0-8] 9d}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 49 38 9c 80 0c 24 01 [0-8] 9d}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c1 28 87 d2 [0-4] f2 f3 36 [0-2] e9}  //weight: 1, accuracy: Low
        $x_1_6 = {03 49 3c 90 90 90 9c 80 0c 24 01}  //weight: 1, accuracy: High
        $x_1_7 = {83 c1 28 90 90 90 9c 80 0c 24 01}  //weight: 1, accuracy: High
        $x_1_8 = {03 49 3c 87 d2 [0-2] f2 f3 36 e9}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 49 38 87 d2 [0-4] f2 f3 36 [0-2] e9}  //weight: 1, accuracy: Low
        $x_1_10 = {03 55 24 87 d2 [0-4] f2 f3 36 [0-1] e9}  //weight: 1, accuracy: Low
        $x_1_11 = {8b 4e 10 87 d2 [0-4] f2 f3 36 [0-1] e9}  //weight: 1, accuracy: Low
        $x_1_12 = {83 c1 28 90 90 90 9c 80 24 24 fe}  //weight: 1, accuracy: High
        $x_1_13 = {03 49 3c 87 d2 [0-4] f2 f3 36 [0-2] e9}  //weight: 1, accuracy: Low
        $x_1_14 = {03 49 3c 90 90 90 9c 80 24 24 fe}  //weight: 1, accuracy: High
        $x_1_15 = {03 49 3c 90 90 90 87 d2 90 f2 f3 36 26 36 e9}  //weight: 1, accuracy: High
        $x_1_16 = {8b 49 38 90 90 90 87 d2 90 f2 f3 36 26 36 e9}  //weight: 1, accuracy: High
        $x_1_17 = {03 49 3c 90 90 90 90 9c 80 24 24 fe}  //weight: 1, accuracy: High
        $x_1_18 = {8b 49 38 90 90 90 90 9c 80 24 24 fe}  //weight: 1, accuracy: High
        $x_1_19 = {8b 4e 10 90 90 90 90 9c 80 24 24 fe}  //weight: 1, accuracy: High
        $x_1_20 = {8b 4e 10 9c 80 24 24 fe 9d}  //weight: 1, accuracy: High
        $x_1_21 = {8b 49 38 9c 80 24 24 fe 9d}  //weight: 1, accuracy: High
        $x_1_22 = {03 49 3c 9c 80 24 24 fe 9d}  //weight: 1, accuracy: High
        $x_1_23 = {83 c1 28 9c 80 24 24 fe 9d}  //weight: 1, accuracy: High
        $x_1_24 = {81 ff 52 a4 bf 08 ?? 9c 80 24 24 fe 9d}  //weight: 1, accuracy: Low
        $x_1_25 = {8b 4e 10 90 9c 80 24 24 fe 9d}  //weight: 1, accuracy: High
        $x_1_26 = {83 c1 28 90 9c 80 24 24 fe}  //weight: 1, accuracy: High
        $x_1_27 = {03 49 3c 90 9c 80 24 24 fe}  //weight: 1, accuracy: High
        $x_1_28 = {8b 5e 0c 87 d2 90 e9}  //weight: 1, accuracy: High
        $x_1_29 = {8b 5e 0c 90 9c 80 24 24 fe 9d}  //weight: 1, accuracy: High
        $x_1_30 = {b9 4c 69 62 72 87 d2 90 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_XR_2147656611_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XR"
        threat_id = "2147656611"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4f 0c 8b 55 b8 8a 14 11 32 15 ?? ?? ?? ?? 88 14 01 8b 0d ?? ?? ?? ?? b8 01 00 00 00 03 c8 89 0d ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 ff 00 00 00 66 3b c8 0f 8f 1c 01 00 00 0f bf f1 (e9 ?? ?? ?? ?? ??|81 fe 00 01) 72 02 ff d7 a1 ?? ?? ?? ?? 33 db 8a 1c 30 81 fb 00 01 00 00 72 02 ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = {50 c6 45 d4 58 e8 ?? ?? ?? ?? 8d 4d d4 51 c6 45 d4 59 e8 ?? ?? ?? ?? 8d 55 d4 52 c6 45 d4 59 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XS_2147656647_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XS"
        threat_id = "2147656647"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 8a 47 01 47 84 c0 75 f8 a0 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 04 30 a2 ?? ?? ?? ?? 34 45 89 0f a2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 14 8b 78 10 a0 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00 04 30 68 ?? ?? ?? ?? 03 cf a2 ?? ?? ?? ?? 6a 00 03 f1 34 44 6a 00 89 35 ?? ?? ?? ?? a2}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 17 32 d0 46 81 fe ?? ?? ?? ?? 88 17 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_XT_2147656660_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XT"
        threat_id = "2147656660"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d3 8b f8 81 c7 4e 05 00 00 eb 02 ff d3 ff d3 3b f8}  //weight: 1, accuracy: High
        $x_1_2 = {89 c3 6a 02 6a 5f 6a 00 ff d6 50 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XT_2147656660_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XT"
        threat_id = "2147656660"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d1 c0 50 8f 85 ?? ?? ff ff e2 ef 3b c3 59 8b 85 ?? ?? ff ff 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 50 8f 85 ?? ?? ff ff 5b ac 32 c3 aa f7 c1 01 00 00 00 74 0b 06 00 8b 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 60 6a 01 e8 ?? ?? ?? ?? 61 e2 ae 8b 85 ?? ?? ff ff 05 ca 01 00 00 50 e8 ?? ?? ?? ?? c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XT_2147656660_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XT"
        threat_id = "2147656660"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 89 45 fc 33 (db|f6) c6 45 ?? 56 c6 45 ?? 25 (43|46) 8b 45 fc 03 (c3|c6) 8b d0 4a 8a 12 3a 55 01 75 f0 8a 10 3a 55 02 75 e9 40 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db c6 45 ?? 56 c6 45 ?? 25 33 c0 89 45 fc e8 00 00 00 00 58 89 45 fc 43 (8b 45 fc 03 c3 8b d0 4a 8a 12 3a 55 00 75 f0|8b 55 fc 8b c2 03 c3 8b c8 49 8a 09 3a 4d 00 75 ee)}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d6 ff d6 3b 45 ?? 72 f7 66 83 ff 3b 72 10 66 83 ef 3b eb 0a 8d 85 ?? ?? ?? ?? 50 ff 55 ?? 66 3b bd ?? ?? ?? ?? 75 ed e8 00 00 00 00 58 89 45 ?? c6 45 ?? 54 c6 45 ?? 5e}  //weight: 1, accuracy: Low
        $x_1_4 = {ff d7 ff d7 3b 45 ?? 72 f7 66 83 7d ?? 3b 72 11 66 83 6d ?? 3b eb 0a 8d 85 ?? ?? ff ff 50 ff 55 ?? 66 8b 45 ?? 66 3b 85 ?? ?? ff ff 75 e9 e8 00 00 00 00 58 89 45 ?? c6 45 ?? 54 c6 45 ?? 5e}  //weight: 1, accuracy: Low
        $x_1_5 = {ff d7 ff d7 3b f0 77 f8 66 83 fb 3b 72 10 66 83 eb 3b eb 0a 8d 85 ?? ?? ff ff 50 ff 55 ?? 66 3b 9d ?? ?? ff ff 75 ed e8 00 00 00 00 58 89 45 ?? c6 45 ?? 54 c6 45 ?? 5e}  //weight: 1, accuracy: Low
        $x_1_6 = {ff d7 8b d8 81 c3 c8 03 00 00 eb 02 ff d7 ff d7 3b d8 77 f8 33 d2 c6 45 ?? 5e c6 45 ?? 54 e8 00 00 00 00 58 89 45 f8}  //weight: 1, accuracy: Low
        $x_1_7 = {88 14 19 ff 45 f0 48 75 d7 50 51 53 8b 45 f4 8b 4d f0 b3 ?? 30 18 40 fe cb 84 db 75 02 b3 ?? e2 f3 5b 59 58 ff 75 08 ff 55 f4}  //weight: 1, accuracy: Low
        $x_1_8 = {68 05 01 00 00 8d 85 ?? fe ff ff 50 6a 00 ff d7 50 ff 55 [0-32] c6 45 ?? 6d c6 45 ?? (70|78) c6 45 ?? (70|78) 8a 85 ?? fe ff ff 3a 45 cc 75 17}  //weight: 1, accuracy: Low
        $x_1_9 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 89 45 ?? c6 45 [0-6] 50 c6 45 ?? 47 33 c0 (89 45 ??|89 c6) 8b 5d 00 8b 43 3c 03 c3 8b 50 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_YC_2147656680_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YC"
        threat_id = "2147656680"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 54 0c 04 c1 e1 04 03 c8 89 0a 83 c4 14 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XU_2147656703_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XU"
        threat_id = "2147656703"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c6 01 00 00 00 56 81 c6 01 00 00 00 81 c6 01 00 00 00 e9 ?? ?? 00 00 81 c7 01 00 00 00 81 c0 01 00 00 00 81 c3 01 00 00 00 03 d8 81 c0 01 00 00 00 81 c3 01 00 00 00 03 c3 81 c3 01 00 00 00 81 c0 01 00 00 00 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {d1 e0 50 81 c3 ?? ?? 00 00 05 ?? ?? 00 00 05 ?? ?? 00 00 81 c3 ?? ?? 00 00 81 c1 ?? ?? 00 00 e9 ?? ?? ff ff 81 e9 01 00 00 00 03 c1 81 c0 01 00 00 00 03 c3 81 c0 01 00 00 00 5f 81 c1 01 00 00 00 81 e9 01 00 00 00 83 c1 0c 81 eb 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_XV_2147656798_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XV"
        threat_id = "2147656798"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 ab aa 8b 3d ?? ?? ?? ?? 8d 45 ec 50 ff d7 8b 75 f8 81 e6 ff ff 00 00 83 fe 31 7e 05 83 ee 32 eb 03 83 c6 0a 8d 4d ec 51 ff d7 8b 55 f8 81 e2 ff ff 00 00 3b d6 75 ed 68 00 2e 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YE_2147656824_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YE"
        threat_id = "2147656824"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 01 ff 45 fc 8b 55 fc 88 08 8b 4d 18 40 3b 51 50 72 e9 8b 4b 3c 03 cb 8b 81 a0 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 6a 5a 59 f7 f1 8b 45 f8 28 14 38 40 89 45 f8 3b 45 f4 72 ea}  //weight: 1, accuracy: High
        $x_1_3 = {8d 0c 10 8d 34 02 8a d9 8b c2 c1 e8 04 24 03 80 e3 1f f6 eb 80 e1 03 f6 e9 b1 fe 2a c8 00 0c 3e ff 45 ec eb c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YE_2147656824_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YE"
        threat_id = "2147656824"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 05 14 81 40 00 eb 26 00 00 a0 93 94 40 00 c7 05 ce 8b 40 00 9a 08 00 00 3c 25 0f 84 11 00 00 00 0f b7 05 8a 8b 40 00 b8 ff 00 00 00 e9 b9 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 05 00 81 40 00 77 38 00 00 a0 93 94 40 00 3c 25 0f 84 14 00 00 00 b8 ff 00 00 00 c7 05 04 81 40 00 9a 24 00 00 e9 dc 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {a0 93 94 40 00 c7 05 08 81 40 00 97 79 00 00 3c 25 0f 84 0f 00 00 00 b8 a5 0e 00 00 b8 ff 00 00 00 e9 8e 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_YF_2147656903_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YF"
        threat_id = "2147656903"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 50 78 85 c0 0f 85 94 00 00 00 8b 45 cc 8b 40 18 89 45 f4 8b 45 f4 8b 55 f8 89 42 40 3d 00 00 40 00 74 09 c7 42 2e 01 00 00 00 eb 07 c7 42 2e 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YG_2147656946_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YG"
        threat_id = "2147656946"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c1 be 03 00 00 00 f7 f6 85 d2 74 0e 8a 04 19 32 05 f0 c0 43 00 34 77 88 04 19 f6 c1 01 74 0f 8a 14 19 32 15 f0 c0 43 00 80 f2 74 88 14 19 41 81 f9 00 d0 07 00 7c b2}  //weight: 1, accuracy: High
        $x_1_2 = {b9 89 d0 00 00 be 30 80 40 00 8b fb f3 a5 66 a5 a4 33 c9 8d 9b 00 00 00 00 f6 c1 03 74 0f 8a 14 19 32 15 c0 c5 43 00 80 f2 76 88 14 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_YI_2147657025_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YI"
        threat_id = "2147657025"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "adsldpc.dll" ascii //weight: 1
        $x_1_2 = {29 ce 47 8a 57 ff 32 c9 3a 15 ?? ?? ?? ?? 75 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 57 01 32 1d ?? ?? ?? ?? 3a 15 ?? ?? ?? ?? 75 b2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YJ_2147657130_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YJ"
        threat_id = "2147657130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?CreateDlgMessage@@YGHPAXPADK|U" ascii //weight: 1
        $x_1_2 = "su82asd7ydiusahksjdhaiusy8d7as6ydiuahsk" ascii //weight: 1
        $x_1_3 = "https:////dufisduhfkjshkdhf.com.au//sdufyiu#9879734" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YJ_2147657130_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YJ"
        threat_id = "2147657130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b7 01 eb 02 b7 00 89 c6 b3 00 80 f9 47 74 3f b3 01 80 f9 45 74 38 b3 02 80 f9 46 74 12 b3 03 80 f9 4e 74 0b 80 f9 4d 0f 85 ?? ?? ?? ?? b3 04 b8 12 00 00 00 8b 55 dc 39 c2 76 25 ba 02 00 00 00 80 f9 4d 75 1b}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 10 85 d2 74 38 8b 4a f8 49 74 32 53 89 c3 8b 42 fc e8 ?? ?? ?? ?? 89 c2 8b 03 89 13 50 8b 48 fc e8 ?? ?? ?? ?? 58 8b 48 f8 49 7c 0e f0 ff 48 f8 75 08 8d 40 f8 e8 ?? ?? ?? ?? 8b 13 5b 89 d0 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 54 32 ff 33 d3 88 54 30 ff 4b 85 db 75 e0 46 4f 75 d7 be ?? ?? ?? ?? b8 ?? ?? ?? ?? bb ?? ?? ?? ?? 30 18 4b 85 db 75 f9 40 4e 75 f0 8d 05 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff d0 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YL_2147657153_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YL"
        threat_id = "2147657153"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 50 58 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 50 58 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 72 73 72}  //weight: 1, accuracy: Low
        $x_1_2 = {55 50 58 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 72 73 72 ?? ?? ?? ?? 63 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {55 50 58 21 ?? ?? ?? ?? 0d 09}  //weight: 1, accuracy: Low
        $x_1_4 = {55 50 58 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 62 62 73 72 ?? ?? ?? ?? 63 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {55 50 58 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 62 62 62 62 ?? ?? ?? ?? 63 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_YN_2147657256_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YN"
        threat_id = "2147657256"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 30 00 00 68 9c 04 00 00 6a 00 ff (15|55)}  //weight: 2, accuracy: Low
        $x_1_2 = {12 11 00 00 89 02 00 81 03 01 01 01 c1 c2 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {05 12 11 00 00 89 85}  //weight: 1, accuracy: High
        $x_2_4 = {80 f0 fa 02 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_YO_2147657261_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YO"
        threat_id = "2147657261"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 66 81 38 4d 5a 0f 85 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 37 00 00 00 e8 ?? ?? ?? ?? 8b 45 e8 8b 40 3c 03 45 f4 89 45 e4 ba ?? ?? ?? ?? b8 37 00 00 00 e8 ?? ?? ?? ?? 8b 45 e4 81 38 50 45 00 00 0f 85 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 37 00 00 00 e8 ?? ?? ?? ?? 8d 85}  //weight: 1, accuracy: Low
        $x_1_2 = {43 80 fb 49 0f 85 ?? ?? ?? ?? fe 44 24 04 80 7c 24 04 5b 0f 85 ?? ?? ?? ?? fe 44 24 03 80 7c 24 03 5b 0f 85 ?? ?? ?? ?? fe 44 24 02 80 7c 24 02 5b 0f 85 ?? ?? ?? ?? fe 44 24 01 80 7c 24 01 5b 0f 85 ?? ?? ?? ?? fe 04 24 80 3c 24 5b 0f 85 ?? ?? ?? ?? 8b c5 8b 17}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 44 24 10 8a 54 24 01 88 50 01 c6 00 01 8d 54 24 10 8d 44 24 0c b1 02 e8 ?? ?? ?? ?? 8d 54 24 0c 8d 44 24 14 e8 ?? ?? ?? ?? 8d 44 24 10 8a 54 24 02 88 50 01 c6 00 01 8d 54 24 10 8d 44 24 14 b1 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YP_2147657289_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YP"
        threat_id = "2147657289"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 03 c7 8b f1 99 f7 fe 8b 84 95 f4 fb ff ff 30 03 8b 45 10 05 3c c9 00 00 ff 45 fc 89 45 10 8b 45 fc 3b 45 0c 7c 93 5f}  //weight: 1, accuracy: High
        $x_1_2 = {40 00 43 43 58 31 0f 85 9a 01 00 00 83 3d ?? ?? 40 00 01 0f 85 8d 01 00 00 bf 82 09 00 00 be 48 c7 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YQ_2147657293_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YQ"
        threat_id = "2147657293"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 08 33 db ff d6 f6 c3 03 8b 4d 08 74 ?? 8a 14 0b 32 15 ?? ?? ?? ?? 80 f2 ?? 88 14 0b f6 c3 01 74 ?? 8a 04 0b 32 05 ?? ?? ?? ?? 34 ?? 88 04 0b 33 d2 8b c3 bf 03 00 00 00 f7 f7 85 d2 74 ?? 8a 14 0b 32 15 ?? ?? ?? ?? 80 f2 ?? 88 14 0b 43 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YR_2147657323_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YR"
        threat_id = "2147657323"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 0a 00 00 00 6a 00 6a 00 ff d6 ff d7 4b 75 f5 bb 0a 00 00 00 6a 00 6a 00 ff d6 ff d7 4b 75 f5 8b 44 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {88 14 08 f6 c1 01 74 14 a1 e0 ?? (42|43) 00 8a 14 08 32 15 c0 ?? (42|43) 00 80 f2 74 88 14 08 41 81 f9 00 d0 07 00 7c a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YS_2147657374_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YS"
        threat_id = "2147657374"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 48 08 ad c1 c8 08 31 d0 ab 83 e9 04 75 f4 6a 04}  //weight: 1, accuracy: High
        $x_1_2 = {57 8b 72 0c 8b 45 08 03 30 56 e8 5d 00 00 00 83 c2 28 66 49 75 e1}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d 10 ad c1 c0 0a 33 45 14 ab 83 e9 04 75 f3}  //weight: 1, accuracy: High
        $x_1_4 = {50 8b 42 0c 03 45 08 50 e8 57 00 00 00 83 c2 28 66 49 75 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_YT_2147657393_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YT"
        threat_id = "2147657393"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 c1 01 74 14 a1 e8 (b1|c1) (42|43) 00 8a 14 (01|08) 32 15 c8 (b1|c1) (42|43) 00 80 f2 ?? 88 14 (01|08) 41 81 f9 88 e3 07 00 7c a2 8b 0d e8 (b1|c1) (42|43) 00 8d 44 24 ?? 50 6a 00 6a 00 51 6a 00 6a 00 ff 15 e0 (b0|c0) (42|43) 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YU_2147657394_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YU"
        threat_id = "2147657394"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 fc e8 ?? ?? ?? ?? ff 75 fc e8 ?? ?? ?? ?? 8b 46 28 [0-16] 03 45 fc [0-16] ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 08 03 76 3c (6a|eb) 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 55 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 75 08 03 76 3c 8b 46 34 6a 40 68 00 30 00 00 ff 76 50 50 8b 45 0c ff 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_YX_2147657621_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YX"
        threat_id = "2147657621"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e0 8b c8 8b 45 f4 99 f7 f9 89 55 f4 b9 00 01 00 00 8b c6 99 f7 f9 89 d6 8b 45 f0 8b d6 88 14 07 ff 45 f0 43 ff 4d e8 75}  //weight: 1, accuracy: High
        $x_1_2 = {4c 4f 6c 69 57 79 49 61 4b 72 50 4e 77 30 30 30 30 30 31 4f 59 4b 4e 79 6e 61 4e 6f 4a 69 50 35 79 6f 4f 70 73 71 45 7f 48 56 6d 33 6d 75 6c 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_YZ_2147657698_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.YZ"
        threat_id = "2147657698"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 33 c0 33 db b9 ?? ?? ?? ?? 03 c3 33 45 08 d1 c0 43 e2 f6 89 44 24 1c 61}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 08 03 76 3c 6a 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 55 ?? 03 00 89 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZB_2147657913_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZB"
        threat_id = "2147657913"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f be 5d 00 33 5c 24 28 53 8b 6c 24 3c 58 88 45 00 c7 05}  //weight: 5, accuracy: High
        $x_1_2 = {0e 00 00 01 8a 06 c7 05 ?? ?? ?? ?? 0f 00 00 01 8a 1f c7 05 ?? ?? ?? ?? 10 00 00 01 30 d8 c7 05 ?? ?? ?? ?? 11 00 00 01 88 06 c7 05 ?? ?? ?? ?? 12 00 00 01}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 68 58 59 59 59 c7 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZC_2147657961_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZC"
        threat_id = "2147657961"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 8b 04 46 66 89 04 4a eb d5 c7 45 f4 00 00 00 00 eb 09 8b 4d f4 83 c1 01 89 4d f4 8b 55 f4 3b 55 14 73 41 8b 45 f4 8b 4d f8 8b 55 08 8b 04 81 33 02}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7e 3c 68 4a 0d ce 09 e8 cf ff ff ff 85 c0 59 74 0f 6a 04 68 00 30 00 00 ff 74 37 50 6a 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ZD_2147658196_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZD"
        threat_id = "2147658196"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 37 13 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {00 00 4d 00 79 00 20 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\triora3\\" ascii //weight: 1
        $x_1_4 = {79 66 69 75 6a 68 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZE_2147658220_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZE"
        threat_id = "2147658220"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 37 13 00 00 66 89 4d d0}  //weight: 1, accuracy: High
        $x_1_2 = {73 40 00 72 0f 85 03 00 80 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {00 00 4d 00 79 00 20 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\triora3\\" ascii //weight: 1
        $x_1_5 = {64 73 66 6b 6a 64 68 66 75 73 64 79 66 69 75 6a 68 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_ZG_2147658424_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZG"
        threat_id = "2147658424"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 01 00 00 00 bb ?? ?? 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 54 32 ff 33 d3 88 54 30 ff 4b 85 db 75 e0 46}  //weight: 1, accuracy: Low
        $x_1_2 = {be 01 00 00 00 bb 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 15 00 0f b6 54 32 ff 33 d3 88 54 30 ff 43 81 fb ?? ?? 00 00 75 dc 46 81 fe}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 54 32 ff 33 d3 88 54 30 ff 43 81 fb ?? ?? 00 00 75 dc 4e 85 f6 75 05 00 be}  //weight: 1, accuracy: Low
        $x_1_4 = {bb 01 00 00 00 8b 45 fc 8a 44 18 ff e8 ?? ?? ?? ?? 33 c7 50 8d 45 fc e8 ?? ?? ?? ?? 5a 88 54 18 ff 43 4e 75 e0}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 54 32 ff 33 d7 88 54 30 ff 47 81 ff ?? ?? 00 00 75 dc 4e 85 f6 75 d2 1a 00 be ?? ?? ?? ?? bf 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_6 = {30 18 4b 85 db 75 f9 40 4e 75 f0 0f 00 be ?? ?? ?? ?? b8 ?? ?? ?? ?? bb}  //weight: 1, accuracy: Low
        $x_1_7 = {30 18 43 81 fb ?? ?? 00 00 75 f5 40 4e 75 ec 0f 00 be ?? ?? ?? ?? b8 ?? ?? ?? ?? bb 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {db 75 ea 8d 05 18 00 bb ?? ?? ?? ?? b8 ?? ?? ?? ?? 8b cb ba ?? ?? 00 00 e8 ?? ?? ?? ?? 4b 85}  //weight: 1, accuracy: Low
        $x_1_9 = {8b d7 30 10 47 81 ff ?? ?? 00 00 75 f3 40 4e 75 ea 0f 00 be ?? ?? ?? ?? b8 ?? ?? ?? ?? bf 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 40 18 89 45 fc c6 45 ?? 47 c6 45 ?? 50 c6 45 ?? 41 33 c0}  //weight: 1, accuracy: Low
        $x_1_11 = {40 89 45 f4 c6 45 ?? 50 c6 45 ?? 47 c6 45 ?? 41 33 c0}  //weight: 1, accuracy: Low
        $x_1_12 = {56 57 c6 45 ?? 41 c6 45 ?? 50 c6 45 ?? 47 33 c0}  //weight: 1, accuracy: Low
        $x_1_13 = {48 83 f8 00 72 12 00 c6 45 ?? 47 c6 45 ?? 41 c6 45 ?? 50 8b 45 ?? 8b 40}  //weight: 1, accuracy: Low
        $x_1_14 = {33 c0 40 8b 4d ?? 03 c8 8b d9 4b 8a 1b 3a 5d ?? 75 f0 8a 19 3a 5d ?? 75 e9 8b d9 43 8a 1b 3a 5d 0c 00 c6 45 ?? 42 c6 45 ?? 21 c6 45 ?? 33}  //weight: 1, accuracy: Low
        $x_1_15 = {58 89 45 f8 c6 45 ?? 54 c6 45 ?? 5e 33 c0 40 8b 55 f8 03 d0 8b ca 49 8a 09 3a 4d ?? 75 f0 8a 0a 3a 4d ?? 75 e9}  //weight: 1, accuracy: Low
        $x_1_16 = {8d 42 01 8b 4d ?? 03 41 08 8d 04 80 33 c9 8a 0c 17 33 c1 48 88 04 17 42 4b 75 e5}  //weight: 1, accuracy: Low
        $x_1_17 = {8a 0f 3a 4d ?? 75 ?? 8a 4f 03 3a 4d ?? 75 ?? 8a 4f 07 3a 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_18 = {8a 1f 3a 5d ?? 75 ?? 8a 5f 03 3a 5d ?? 75 ?? 8a 4f 07 3a 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_19 = {8a 19 3a 5d ?? 75 3b 8a 59 03 3a 5d ?? 75 33 8a 49 07 3a 4d ?? 75 2b}  //weight: 1, accuracy: Low
        $x_1_20 = {e8 00 00 00 00 58 89 45 ?? c6 45 ?? 5e 42 8b 45 ?? 03 c2 8b c8 49 8a 09 3a 4d ?? 75 f0 8a 08 3a 4d ?? 75 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ZI_2147658512_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZI"
        threat_id = "2147658512"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a0 40 00 81 05 f4 ac 40 00 00 c0 00 00 8d ?? dc}  //weight: 1, accuracy: Low
        $x_1_2 = {60 ae 0a 00 0f 82 ?? ff ff ff ff (15|35) f4 ac 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZJ_2147658540_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZJ"
        threat_id = "2147658540"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 83 c0 13 28 10 c1 c2 07 69 d2 01 00 01 00 40 e2 f2}  //weight: 1, accuracy: High
        $x_1_2 = {81 fe 17 ca 2b 6e 75 40 8b 77 18 68 76 46 8b 8a e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4b 54 f3 a4 0f b7 43 14 31 c9 31 d2 8d 44 18 28 66 3b 4b 06 73}  //weight: 1, accuracy: High
        $x_1_4 = {28 01 d8 ff d0 50 ff 55 e8 cd 03 eb fc 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ZL_2147658650_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZL"
        threat_id = "2147658650"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3d dd 07 74 06 66 3d de 07 75}  //weight: 1, accuracy: High
        $x_1_2 = {04 30 32 c2 34 79 88 83 ?? ?? ?? ?? 33 d2 8b c3 b9 03 00 00 00 f7 f1 85 d2 74}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c8 c1 e9 10 c1 e1 08 c1 e9 10 32 d1}  //weight: 1, accuracy: High
        $x_1_4 = {8b c2 c1 e8 10 c1 e0 08 c1 e8 10 32 d8}  //weight: 1, accuracy: High
        $x_1_5 = {8b c2 c1 e8 10 c1 e0 08 c1 e8 10 32 c8}  //weight: 1, accuracy: High
        $x_1_6 = {8b c2 c1 e8 10 c1 e0 08 [0-18] c1 e8 10 32 d0}  //weight: 1, accuracy: Low
        $x_1_7 = {8b d6 c1 ea 10 c1 e2 08 c1 ea 10 32 d3}  //weight: 1, accuracy: High
        $x_1_8 = {8b d6 c1 ea 10 c1 e2 08 c1 ea 10 32 d1}  //weight: 1, accuracy: High
        $x_1_9 = {b9 89 d7 00 00 be [0-6] f3 a5 66 a5 [0-3] a4}  //weight: 1, accuracy: Low
        $x_1_10 = {b9 89 8f 00 00 be [0-6] f3 a5 66 a5 [0-3] a4}  //weight: 1, accuracy: Low
        $x_1_11 = {b9 89 53 00 00 be [0-6] f3 a5 66 a5 [0-3] a4}  //weight: 1, accuracy: Low
        $x_1_12 = {b9 09 56 00 00 be [0-6] f3 a5 66 a5 [0-3] a4}  //weight: 1, accuracy: Low
        $x_1_13 = {b9 89 10 00 00 be [0-6] f3 a5 66 a5 [0-3] a4}  //weight: 1, accuracy: Low
        $x_1_14 = {b9 89 d4 00 00 be [0-6] f3 a5 66 a5 [0-3] a4}  //weight: 1, accuracy: Low
        $x_1_15 = {6a 08 68 45 01 00 00 68 c9 01 00 00 6a 07 68 f4 01 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ZM_2147658730_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZM"
        threat_id = "2147658730"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 57 01 0f b6 4f 02 8d 84 80 10 ff ff ff 8d 54 42 d0 8d 04 92 8d 44 41 d0 0f b6 c0 c1 e0 02 e8 9e ff ff ff 43 83 c7 03 3b dd 7c d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZN_2147658880_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZN"
        threat_id = "2147658880"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8b 00 8b 40 18 [0-32] 89 45 ?? c6 45 ?? 50 c6 45 ?? 41 c6 45 ?? 47}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 50 01 8b 4d f4 03 51 08 8d 14 92 33 c9 8a 0c 07 33 d1 4a 88 14 07 40 4b 75 e5}  //weight: 1, accuracy: High
        $x_1_3 = {8d 50 01 8b 75 ec 0f af 56 04 8b 75 f4 0f b6 34 06 33 d6 8b 75 f4 88 14 06 43 40 49 75 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ZO_2147658925_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZO"
        threat_id = "2147658925"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 54 fd ff ff bb 0d 66 19 00 33 d2 f7 e3 05 5f f3 6e 3c 89 85 54 fd ff ff ad 33 85 54 fd ff ff ab e2 dc b8 00 24 00 00 bb 04 00 00 00 33 d2 f7 f3}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e3 10 b9 ff ff 00 00 53 e8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 06 89 9d 54 fd ff ff 43 e2 ea 61 83 bd 54 fd ff ff 00 0f 84 aa 00 00 00 b9 00 24 00 00 c1 e9 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZP_2147658959_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZP"
        threat_id = "2147658959"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 1c 89 c7 50 68 22 07 e4 71 50 e8 ?? ?? ?? ?? 89 85 f4 fd ff ff 58 68 b6 74 75 5d 50 e8 ?? ?? ?? ?? 89 85 ec fd ff ff 68 50 46 b4 59 57 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c1 00 10 (00|01) 00 c7 01 90 90 90 90 c7 41 04 90 90 90 90 c7 41 08 90 90 90 90 81 c2 ?? ?? ?? ?? c6 02 e9 51 29 d1 89 4a 01}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d2 01 f0 ff 70 fc ff 70 f8 5a 58 3d 2e 65 78 65 74 05 3d 2e 45 58 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZQ_2147658966_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZQ"
        threat_id = "2147658966"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 89 45 fc d1 e6 89 45 fc ff 16 03 00 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZR_2147659011_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZR"
        threat_id = "2147659011"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 23 85 58 ff ff ff 89 85 5c ff ff ff 8b 85 54 ff ff ff 31 85 5c ff ff ff 8b 85 58 ff ff ff 33 85 5c ff ff ff 89 c6 8b c7 31 c6 8b 85 5c ff ff ff 23 c6 89 85 58 ff ff ff ff 85 54 ff ff ff 81 bd 54 ff ff ff ff ff 00 00 7e b4 ff c7 81 ff ff 0f 00 00 7e 9a e8 ?? ?? 00 00 6a 00 ba ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 85 5c ff ff ff 23 85 58 ff ff ff 89 85 54 ff ff ff 31 b5 54 ff ff ff 8b 85 58 ff ff ff 33 85 54 ff ff ff 89 85 5c ff ff ff 31 bd 5c ff ff ff 8b 85 54 ff ff ff 23 85 5c ff ff ff 89 85 58 ff ff ff ff c6 81 fe ff ff 00 00 7e b4 ff c7 81 ff ff 0f 00 00 7e 9a e8 ?? ?? 00 00 6a 00 ba ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ZT_2147659080_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZT"
        threat_id = "2147659080"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 3d bc 56 41 00 c1 0d 76 54 41 00 03 21 7d c8 6a 36 58 c1 e0 03 8b d8 81 e3 4d 4b 00 00 be 7a 00 00 00 2b}  //weight: 1, accuracy: High
        $x_1_2 = {c1 05 c2 56 41 00 06 d1 eb 31 1d 94 54 41 00 29 1d c5 56 41 00 ba 00 00 00 00 33 d2 6b d2 7d 89 55 b8 68 22 5b 1a 00 5a c1 da 11}  //weight: 1, accuracy: High
        $x_1_3 = {c1 c9 0c 21 4d fc 29 0d 06 52 41 00 8d 9f 9f 00 00 00 c1 db 19 c1 05 24 52 41 00 05 4b 83 fb 38 75 19 68 da 16 1e 00 8f 05 fc 51 41 00 ff 0d f6 54 41 00 6a 23 8f 05 e8 53 41 00 09 5d c4 be 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZU_2147659099_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZU"
        threat_id = "2147659099"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 1d 57 9e 77 0e dc 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 77 72 a0 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (ff|6c)}  //weight: 1, accuracy: Low
        $x_1_2 = {6f 00 77 00 64 00 69 00 75 00 66 00 73 00 69 00 64 00 66 00 6a 00 6c 00 6b 00 73 00 61 00 64 00 6a 00 66 00 33 00 6c 00 61 00 73 00 6b 00 6a 00 6a 00 68 00 67 00 6a 00 6b 00 68 00 67 00 6b 00 6a 00 68 00 67 00 00 00 54 00 68 00 65 00 20 00 49 00 4f 00 53 00 74 00 72 00 61 00 72 00 74 00 75 00 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ZW_2147659295_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZW"
        threat_id = "2147659295"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 5c 74 65 73 74 31 32 33 5c ?? ?? (30|2d|39) (30|2d|39) 5c 52 65 6c 65 61 73 65 5c ?? ?? (30|2d|39) (30|2d|39) 2e 70 64 62 0a 00 (64|65) 3a 5c 44 6f 77 6e 6c 6f 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZX_2147659313_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZX"
        threat_id = "2147659313"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 f7 0f b6 04 2a 0f b6 d1 03 d6 03 c2 25 ff 00 00 00 a3 ?? ?? ?? ?? 88 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {03 cb 81 e1 ff 00 00 00 8a 91 ?? ?? ?? ?? 30 14 30 83 c6 01 81 fe 60 ae 0a 00 0f 82 13 ff ff ff 8b 9d f0 fe ff ff 81 c3 00 c0 00 00 ff d3}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 44 24 0b 6e c6 44 24 0e 33 c6 44 24 0f 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZY_2147659346_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZY"
        threat_id = "2147659346"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fa 22 67 3f 7a 74 ?? 81 fa 67 22 7a 3f 0f 84 ?? ?? ?? ?? 81 fa 30 75 2d 68}  //weight: 1, accuracy: Low
        $x_1_2 = {0f a2 31 d8 3d 46 65 6e 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AAB_2147659895_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAB"
        threat_id = "2147659895"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 01 31 c0 8b 14 c7 41 04 24 83 c4 10 c7 41 08 40 ff e2 90}  //weight: 1, accuracy: High
        $x_1_2 = {4a 81 fa 6b 6c 33 32 74 ?? 53 81 fa 6b 6f 72 65 5b 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AAC_2147660025_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAC"
        threat_id = "2147660025"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 01 7e 13 8b c6 8d 51 ff 8b 78 fc 03 38 83 c0 04 4a 89 78 ?? 75 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 a5 89 45 ?? 8d 85 ?? ff ff ff 8b 48 04 03 08 03 c3 01 4d fc 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AAC_2147660025_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAC"
        threat_id = "2147660025"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 ff 76 50 ff 76 34 ff 55 ?? 85 c0 75 13 6a 40 68 00 30 00 00 ff 76 50 6a 00 ff 55 ?? 85 c0 74 75 89 45 ?? fc 56 8b 4e 54 8b 75 08 8b 7d ?? 33 c0 f3 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AAD_2147660033_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAD"
        threat_id = "2147660033"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 81 ec 80 12 00 00 56 57 53 50 81 ec 00 10 00 00 6a ff 6a 00 67 8d 06 04 00 6a 00 f9 50 83 c8 ff 50 25 f8 05 00 00 50 54 ff 15 ?? ?? ?? ?? 8b d4 8d 52 30 8b fa 83 c7 1c f8 66 26 11 44 24 68 6a 01 c7 07 ?? 00 00 00 89 7a 04 c7 02 00 00 00 00 52 57 85 c0 74 0d 3d 50 02 00 00 77 06 36 be ?? ?? ?? ?? 3e f3 ff 16}  //weight: 5, accuracy: Low
        $x_1_2 = {f7 14 24 90 90 90 9c 80 24 24 fe 90 90 90 90 9d 26 0f 83}  //weight: 1, accuracy: High
        $x_1_3 = {31 04 24 87 d2 90 90 90 90 f2 f3 36 26 e9}  //weight: 1, accuracy: High
        $x_1_4 = {b9 65 00 00 00 50 8d 05 ?? ?? ?? ?? 87 04 24 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AAI_2147660439_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAI"
        threat_id = "2147660439"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f1 40 51 b9 00 20 00 00 81 e9 00 f0 ff ff 51 c1 e6 02 56}  //weight: 1, accuracy: High
        $x_1_2 = {8a 1c 06 42 2a 9a ?? ?? ?? ?? 80 24 37 00 88 1c 37 83 ea 01 74 04 39 c0 74 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AAJ_2147660581_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAJ"
        threat_id = "2147660581"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 10 0f b6 52 04 c1 e2 18 8b 4d 10 0f b6 49 05 c1 e1 10 31 ca 8b 4d 10 0f b6 49 06}  //weight: 1, accuracy: High
        $x_1_2 = {53 56 8b 44 24 0c 8b 54 24 10 8b 4c 24 14 0f b6 1a c1 e3 18 0f b6 72 01 c1 e6 10 31 f3 0f b6 72 02 c1 e6 08 31 f3}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 10 0f b6 12 c1 e2 18 8b 4d 10 0f b6 49 01 c1 e1 10 31 ca 8b 4d 10 0f b6 49 02 c1 e1 08 31 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AAK_2147660637_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAK"
        threat_id = "2147660637"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a4 33 c0 90 a8 01 8b 0d ?? ?? ?? ?? 74 11 8a 14 01 32 15 ?? ?? ?? ?? 80 f2 ?? 88 14 01 eb 0d 8a 1c 01 8a d0 80 c2 ?? 32 da 88 1c 01 40 3d ?? ?? ?? ?? 7c d0 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AAL_2147661123_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAL"
        threat_id = "2147661123"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 a4 81 7d a4 ?? 00 10 80 75 0e c7 45 a4 00 00 00 00 c7 45 e8 ?? ?? ?? ?? 83 7d d0 00 74}  //weight: 5, accuracy: Low
        $x_5_2 = {8a 08 88 0a 8b 55 10 03 55 f8 0f b6 02 8b 4d 08 03 4d fc 0f b6 11 03 d0 8b 45 08 03 45 fc 88 10 83 7d f8 05 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AAP_2147661318_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAP"
        threat_id = "2147661318"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 0a 8d a4 24 00 00 00 00 8d 49 00 8a 88 ?? ?? ?? ?? 01 b0 ?? ?? ?? ?? 02 ca 80 e9 07 83 c0 04 83 f8 76 88 0d ?? ?? ?? ?? 72 e1 ff 4c 24 14 75 8e 83 fb 07 74 2e 83 fb 13 74 1a}  //weight: 1, accuracy: Low
        $x_1_2 = {56 8b 74 24 1c 57 8d 5c 01 f9 c7 44 24 ?? 60 01 00 00 eb 05 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 f9 07 74 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AAR_2147661495_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAR"
        threat_id = "2147661495"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 e8 10 12 72 8e c7 45 f8 00 00 00 00 c7 45 f4 00 00 00 00 8b 45 10 89 45 f0 66 81 65 fc 6f c9 c6 45 e7 00 83 7d 0c 00 74 06 83 7d 08 00 75 02}  //weight: 1, accuracy: High
        $x_1_2 = {eb 49 eb 09 8b 45 e7 03 45 ef 89 45 e7 8b 45 e7 3b 45 f7 73 33 81 6d eb 22 5f e4 e8 8b 45 0c}  //weight: 1, accuracy: High
        $x_1_3 = {83 7d 14 00 75 08 83 c8 ff e9 ed 00 00 00 8b 4d 14 8b 01 89 45 f4 81 45 e0 42 c2 1e 87 83 7d 10 00 75 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AAS_2147661497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAS"
        threat_id = "2147661497"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0e 85 fb 30 17 85 fb 49 85 fb 47 85 fb eb ee}  //weight: 1, accuracy: High
        $x_1_2 = {b8 fb 81 ec bf f7 e1 89 d0 c1 e8 0e 89 45 08 8b 45 08 69 c0 5e 55 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZG_2147661598_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZG!upk"
        threat_id = "2147661598"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "upk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 40 8b 55 f8 03 d0 8b ca 49 8a 09 3a 8d ?? ff ff ff 75 ed 8a 0a 3a 8d ?? ff ff ff 75 e3 42 89 95 ?? ff ff ff 03 45 f8 40 05 ?? 00 00 00 89 45 0e 00 c6 85 ?? ff ff ff 54 c6 85 ?? ff ff ff 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 30 4e 85 f6 7c 1d 46 33 c0 8b 55 ?? 0f b6 14 02 8b 8d ?? ff ff ff 33 51 04 8b 4d ?? 88 14 01 40 4e 75 e6 8b 45 ?? 89 85 ?? ff ff ff 8b 85 ?? ff ff ff 66 81 38 4d 5a 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AAV_2147661659_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAV"
        threat_id = "2147661659"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 53 c1 c7 45}  //weight: 1, accuracy: High
        $x_1_2 = {0f 10 05 04 ?? ?? ?? c7 45 ?? ?? ?? ?? ?? (c7 45|8b 55)}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 11 05 04 ?? ?? ?? c7 45}  //weight: 1, accuracy: Low
        $x_1_4 = {33 d2 81 7d ?? ?? ?? ?? ?? 0f 9e c2}  //weight: 1, accuracy: Low
        $x_1_5 = {33 d2 3b c1 0f (95|9f) c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_AAY_2147661973_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAY"
        threat_id = "2147661973"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e1 05 be c7 45 ?? ?? e1 05 be ff 15 ?? ?? ?? ?? 6a ?? ff 15 ?? ?? ?? ?? 85 c0 0f 8f 04 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_2 = {e2 05 be 8b 45 ?? 8b 4d ?? 0f af c1 89 45 ?? 8d 45 ?? 56 89 45 ?? be ?? 68 62 7b e9 04 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 b8 3b e1 05 be [0-12] c7 45 f0 00 00 00 00 [0-24] c7 45 b8 3a e1 05 be}  //weight: 1, accuracy: Low
        $x_1_4 = {3d db e3 05 be [0-12] 0f 85 [0-12] 81 7d d8 2a e1 05 be [0-12] 0f 85 [0-12] 8b 45 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AAZ_2147662135_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AAZ"
        threat_id = "2147662135"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 ec 38 e1 05 be 68 ?? ?? ?? ?? c7 45 f4 3b e1 05 be ff d7 83 f8 30 0f 8e 39 00 00 00 8b 35 ?? ?? ?? ?? 6a 37 ff 35 ?? ?? ?? ?? ff d6 68 ?? ?? ?? ?? ff d7}  //weight: 10, accuracy: Low
        $x_1_2 = {30 38 39 30 38 39 38 37 00 00 00 00 33 37 36 32 38 37 34 38 32 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABA_2147662152_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABA"
        threat_id = "2147662152"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 21 00 ff 31 58 8b d0 6a 3c 01 04 24 [0-6] 8b 54 10 1c c1 ca 08 33 c0 ?? ?? ?? c2 ?? 77 09 90 90 90 [0-2] e9 ?? fb ff ff 6a 00 5c fb}  //weight: 1, accuracy: Low
        $x_1_2 = {58 2e ff 10 ?? 83 ec ?? 8b 2c 24 83 c4 04 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {bf fc ff ff ff 2b ?? 2b ?? 5f 0f cf eb e0 [0-7] 68 ?? ?? ?? ?? 58 2e ff 10 ?? 83 ec ?? 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABC_2147662657_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABC"
        threat_id = "2147662657"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 0e 6a 0a 6a 40 ff 15 ?? ?? ?? ?? 33 c0 c9 c3 53 56 68 28 14 00 00 6a 40}  //weight: 1, accuracy: Low
        $x_1_2 = {3b de 74 23 8d 45 fc 50 6a 40 ff 75 10 57 ff 15 ?? ?? ?? ?? 85 c0 74 0f ff 75 08 03 df ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABD_2147662671_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABD"
        threat_id = "2147662671"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 8b d8 43 6a 40 68 00 10 00 00 53 57 ff 15 ?? ?? ?? ?? 8d 4d f4 89 45 fc 51 50 8b fe 83 c9 ff 33 c0 f2 ae f7 d1}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 25 33 c0 59 8d bd ?? ?? ff ff f3 ab 8d 85 ?? ?? ff ff c7 85 ?? ?? ff ff 94 00 00 00 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8a d9 c0 fb 04 80 e3 03 c0 e0 02 0a d8 8b 45 10 88 1c 07 47 8a 04 16 46 3c 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABE_2147662946_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABE"
        threat_id = "2147662946"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 c1 6c c6 45 c2 41 c6 45 c5 6f c6 45 c6 63 c6 45 bb 56 c6 45 bc 69 c6 45 c7 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 c8 6d c6 45 ca 78 c6 45 c9 70 8a 85 a6 fe ff ff 3a 45 c8 75 2b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABF_2147662949_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABF"
        threat_id = "2147662949"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 b2 e6 0e 73 15 8b ?? ?? 0f af ?? ?? 89 ?? ?? 8b ?? ?? 83 ?? ?? 89 ?? ?? eb d9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 69 c0 ?? (6d|6e) 00 00 50 68 ?? ?? 40 00 8b ?? 08 d1 (e0|e1|e2) d1 (e8|e9|ea) (50|51|52) ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABG_2147662968_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABG"
        threat_id = "2147662968"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 61 63 65 74 2e 74 64 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 7d e0 13 01 00 00 75 17 68 48 91 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {03 76 3c 8b 46 34 6a 40 68 00 30 00 00 ff 76 50}  //weight: 1, accuracy: High
        $x_1_4 = {8b 46 28 03 85 ?? ?? ff ff ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_ABH_2147663274_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABH"
        threat_id = "2147663274"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 01 89 45 fc 81 7d fc 10 1e 05 00 0f 83 8d 00 00 00 8b 4d f4 8b 55 f0 8d 44 0a 4f 89 45 f8 8b 4d f4 83 c1 4c 81 f9 e9 01 00 00 76 19}  //weight: 2, accuracy: High
        $x_1_2 = {8b 02 05 6e 50 00 00 89 45 e0 8b 4d e4 83 c1 4c 8b 55 e8 81 e2 ff 00 00 00 2b ca 66 89 0d}  //weight: 1, accuracy: High
        $x_2_3 = {c7 45 f4 dd 01 00 00 c6 45 fc 00 33 c0 66 89 45 fd c7 45 e8 c9 00 00 00 33 c9 8a 0d ?? ?? 42 00 83 c1 63 39 4d f8 74 1a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ABI_2147663452_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABI"
        threat_id = "2147663452"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af d0 8b 45 e4 23 d0 c0 4d ff 04 89 55 d0 8b 45 c8 8a 55 ff 88 10 8b 45 f8 40 89 45 f8 3b 45 f4 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABJ_2147663597_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABJ"
        threat_id = "2147663597"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b3 5e 30 18 40 fe cb 84 db 75 02 b3 5e e2 f3}  //weight: 1, accuracy: High
        $x_1_2 = {0f ce 85 c3 83 da 73 c1 fe 62 c1 c7 46 0f ba f2 58 4f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABK_2147663667_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABK"
        threat_id = "2147663667"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 08 00 74 07 b8 ?? (21|22|23) 00 10 eb 05 b8 ?? (21|22|23) 00 10 8b e5 5d c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fb 00 00 00 00 0f b6 4d 10 83 f9 00 75 02 eb 4e eb 19 8b 4d fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABL_2147663881_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABL"
        threat_id = "2147663881"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b c6 75 04 33 c0 eb 37 50 56 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 0c 8d ?? ?? 33 d2 6a ?? 8b ?? 5f f7 f7 8a 82 ?? ?? ?? ?? 30 ?? ?? 3b ?? 24 10 76 e1 5f}  //weight: 1, accuracy: Low
        $x_1_3 = {66 3b 48 06 73 4d 8b 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABN_2147664104_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABN"
        threat_id = "2147664104"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 88 a4 00 00 00 83 f9 05 77 ?? 83 b8 a8 00 00 00 02 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 4d f4 51 ff 75 fc ff 75 cc 57 ff 75 c8 6a 02 ff d0 85 c0 78 ?? 83 7d f4 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 f7 c1 00 00 00 04 74 05 b8 00 02 00 00 f7 c1 00 00 00 20 74 22 f7 c1 00 00 00 40 74 0c 85 c9 79 04 83 c8 40 c3 83 c8 20 c3}  //weight: 1, accuracy: High
        $x_1_4 = {6e 74 64 6c 6c 00 00 00 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 52 74 6c 41 63 71 75 69 72 65 50 65 62 4c 6f 63 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ABO_2147664159_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABO"
        threat_id = "2147664159"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 5d f4 31 f6 8a 13 30 10 40 eb}  //weight: 2, accuracy: High
        $x_1_2 = {e8 00 00 00 00 58 89 45 fc c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? (c6 (00|2d|07)|64 8b 05 30 00)}  //weight: 1, accuracy: Low
        $x_1_3 = {03 ff 03 cf 66 8b 09 66 89 0a ff 45 e8 83 c2 02 48 75}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 fc 03 c3 8b c8 49 8a 09 3a (08|2d|0f) 75 (e0|2d|f1) 8a 08 3a (48|2d|4f) 01 75 [0-4] (40|2d|47) 8a (00|2d|3f) 3a ?? 02 75}  //weight: 1, accuracy: Low
        $x_2_5 = "\\Borland\\Delphi" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ABU_2147664337_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABU"
        threat_id = "2147664337"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4d 10 83 f9 00 75 02 eb ?? eb 09 8b 4d f7 03 4d fc 89 4d f7 8b 4d f7 3b 4d 0c 73 ?? 8a 4d 10 88 4d fb 8b 4d 08 03 4d f7 80 65 f3 ?? 8a 11}  //weight: 1, accuracy: Low
        $x_1_2 = {88 55 ee 0f b6 4d fb 0f b6 55 ee 33 ca 88 4d fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABV_2147664350_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABV"
        threat_id = "2147664350"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 02 33 c2 c1 e8 0a 33 c2 33 c1}  //weight: 1, accuracy: High
        $x_1_2 = {41 8b c1 99 bb ?? ?? 00 00 f7 fb 81 fa ?? ?? 00 00 75 02 33 c9 45 8b c5 99 bb ?? ?? 00 00 ?? ?? 81 fa ?? ?? 00 00 75 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABS_2147664435_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABS"
        threat_id = "2147664435"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4d 10 83 f9 00 75 02 eb ?? eb 09 8b 4d ?? 03 4d ?? 89 4d ?? 8b 4d ?? 3b 4d 0c 73 ?? 8a 4d 10}  //weight: 1, accuracy: Low
        $x_1_2 = {3b 4d f7 76 02 eb ?? 8b 4d 08 03 4d fc 8a 45 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABY_2147664905_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABY"
        threat_id = "2147664905"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 18 03 c3 8b ce c1 e9 18 32 d1 47 81 ff 20 a1 07 00 88 10 7c c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABZ_2147664908_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABZ"
        threat_id = "2147664908"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 0a 8d 58 01 0f af de 30 1c 02 40 3b c1 7c f2}  //weight: 1, accuracy: High
        $x_1_2 = {75 f1 68 3f 20 00 00 68 c3 06 00 00 68 28 91 40 00 e8 90 ff ff ff 83 c4 0c b8 28 91 40 00 ff d0 33 c0 5b 8b e5 5d c2 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ABZ_2147664908_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ABZ"
        threat_id = "2147664908"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 33 c0 f7 f0 61}  //weight: 1, accuracy: High
        $x_1_2 = {51 ff 75 dc c7 85 ?? fc ff ff 07 00 01 00 ff d0 85 c0 0f 88}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 41 3c 03 45 fc 8d ?? 08 f8 00 00 00 8b ?? 0c 03 45 f8 89 45 cc 8b ?? 08}  //weight: 1, accuracy: Low
        $x_1_4 = {2a 16 30 14 08 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ACA_2147665009_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACA"
        threat_id = "2147665009"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 83 e8 01 89 45 f8 83 7d f8 00 0f 86 ?? 00 00 00 81 7d e4 ?? ?? 00 00 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d f8 83 e9 01 89 4d f8 83 7d f8 00 0f 86 ?? 00 00 00 81 7d e4 ?? ?? 00 00 7d}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 09 8b 55 ec 83 c2 04 89 55 ec 81 7d ec ?? ?? 00 00 (73 ??|0f 83 ?? 00) 8b 45 08 03 45 ec 8b 88 ?? ?? ff ff 89 4d f0 19 00 c7 45 ec ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 09 8b 45 ec 83 c0 04 89 45 ec 81 7d ec ?? ?? 00 00 (73 ??|0f 83 ?? 00) 8b 4d 08 03 4d ec 8b 91 ?? ?? ff ff 89 55 f0 19 00 c7 45 ec ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {eb 09 8b 4d ec 83 c1 04 89 4d ec 81 7d ec ?? ?? 00 00 (73 ??|0f 83 ?? 00) 8b 55 08 03 55 ec 8b 82 ?? ?? ff ff 89 45 f0 19 00 c7 45 ec ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 45 f0 2d ?? ?? ?? ?? 89 45 f0}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 55 f0 81 ea ?? ?? ?? ?? 89 55 f0}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 45 08 03 45 ec 8b 4d f0 89 88 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 55 08 03 55 ec 8b 45 f0 89 82 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 4d 08 03 4d ec 8b 55 f0 89 91 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_ACE_2147665139_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACE"
        threat_id = "2147665139"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 70 02 56 8d b5 c9 00 00 00 89 f7 b9 53 00 00 00 ad 35}  //weight: 1, accuracy: High
        $x_1_2 = {8d b5 16 02 00 00 8d 1c 03 89 f7 b9 ?? ?? ?? ?? ad 31 d8 ab e2 fa e9}  //weight: 1, accuracy: Low
        $x_1_3 = {60 83 ec 6e fc 89 e7 56 e8 3b}  //weight: 1, accuracy: High
        $x_1_4 = {74 05 3c 9a 75 05 46 8d 74 1e 03 3c c8 74 06 24 f7 3c c2 75 02 46}  //weight: 1, accuracy: High
        $x_1_5 = {8d 73 0d 6a 64 59 0f a3 0b d6 73 01 ac aa e2 f6 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_ACF_2147665151_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACF"
        threat_id = "2147665151"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d0 2b d0 03 d0 03 d0 d1 c9 d1 c9 d1 c1 d1 c1 ff d0 87 f6 4b 75 b9 50 58 8b d2 60 90 90 48 83 c0 01 8b}  //weight: 1, accuracy: High
        $x_1_2 = {56 90 90 5f d1 c2 d1 ca 68 9b 00 00 00 59 85 c2 c1 c2 02 c1 ca 02 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ACD_2147665171_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACD"
        threat_id = "2147665171"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 89 45 fc c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? 64 8b 05 30 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-52] 66 8b 09 66 89 (08|2d|0f) ff 45 (d0|2d|ff) 83 (c0|2d|c7) 02 (48|2d|4f) 75 (e0|2d|ef) ?? ?? [0-224] 2e 00 [0-20] 66 3b (85|4d)}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 89 45 fc 64 8b 05 30 00 00 00 89 45 f8 c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-52] 66 8b 1b 66 89 (18|2d|1f) (40|2d|43) 83 (c0|2d|c7) 02 (48|2d|4f) 75 (e0|2d|ef) ?? ?? [0-224] 2e 00 [0-20] 66 3b (85|4d)}  //weight: 1, accuracy: Low
        $x_1_3 = {e8 00 00 00 00 58 89 45 fc 64 8b 05 30 00 00 00 89 45 f8 c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-52] 66 8b 36 66 89 (30|2d|37) (40|2d|43) 83 (c0|2d|c7) 02 (48|2d|4f) 75 (e0|2d|ef) ?? ?? [0-224] 2e 00 [0-20] 66 3b (85|4d)}  //weight: 1, accuracy: Low
        $x_1_4 = {e8 00 00 00 00 58 89 45 fc c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? 64 8b 05 30 00 00 00 89 45 f8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-52] 66 8b 1b 66 89 (18|2d|1f) (40|2d|43) 83 (c0|2d|c7) 02 (48|2d|4f) 75 (e0|2d|ef) ?? ?? [0-224] 2e 00 [0-20] 66 3b (85|4d)}  //weight: 1, accuracy: Low
        $x_1_5 = {e8 00 00 00 00 58 89 45 fc c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? 64 8b 05 30 00 00 00 89 45 f8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-52] 66 8b 36 66 89 (30|2d|37) (40|2d|43) 83 (c0|2d|c7) 02 (48|2d|4f) 75 (e0|2d|ef) ?? ?? [0-224] 2e 00 [0-20] 66 3b (85|4d)}  //weight: 1, accuracy: Low
        $x_10_6 = "\\Borland\\Delphi" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ACJ_2147666041_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACJ"
        threat_id = "2147666041"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 8b 55 0c 8d 44 0a ff a3 ?? ?? ?? ?? 8b 4d 0c 8b 55 fc 8d 44 0a ff a3 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ACK_2147666051_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACK"
        threat_id = "2147666051"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 5c 44 65 62 75 67 67 65 72 2e 66 67 68 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 34 8b 01 8b 11 03 50 3c 8b 45 0c 89 10 8b 10 8b 01 8b 09 03 82 a0 00 00 00 8b 55 30 2b ca 8b 55 08 89 0a 8b 4d 0c 8b 11 8b 4d 34 8b 09 03 4a 28}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 d2 0f b6 94 15 38 ff ff ff c1 e0 06 03 45 b8 41 c1 e0 06 03 c7 c1 e0 06 03 c2 3b 75 10 73 25 8b 7d 0c 8b d0 c1 ea 10 88 14 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ACL_2147666085_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACL"
        threat_id = "2147666085"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ad 31 d8 ab e2 fa e9}  //weight: 1, accuracy: High
        $x_1_2 = {89 e5 53 56 57 8b 7d 08 8b 5f 3c 8b 5c 1f 78 01 fb 8b 4b 18 8b 73 20 01 fe ad 01 f8 56 96 31 c0 99 ac 08 c0 74}  //weight: 1, accuracy: High
        $x_1_3 = {5e 3b 55 0c 75 1a 8b 43 18 29 c8 8b 53 24 01 fa 0f b7 14 42 8b 43 1c 01 f8 8b 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb 02 e2}  //weight: 1, accuracy: Low
        $x_1_4 = {50 e8 f7 01 00 00 8d 70 02 56 e8 2c 00 00 00 83 e8 02 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_ACN_2147666533_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACN"
        threat_id = "2147666533"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 8b 55 ?? 83 c0 04 8b 30 89 34 8a 8b 4d ?? 8b 55 08 33 cf 8d 8c 11 ?? ?? ?? ?? 89 4d 08 8b 4d 08 8b 55 14 3b ca 0f 85 d2 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f0 33 f8 03 fa 8d 94 37 ?? ?? ?? ?? 8b 75 ec 33 f0 03 f1 3b d6 0f 82 a0 ff ff ff 8b 45 f8 a3 ?? ?? ?? ?? 8b 45 f0 8b 0d ?? ?? ?? ?? 03 c1 21 45 fc a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 01 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ACP_2147666732_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACP"
        threat_id = "2147666732"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af fe 03 7d ?? 8d b2 ?? ?? ?? ?? 33 f0 89 7d ?? 81 fe ?? ?? ?? ?? 0f 85 0c 00 00 00 8b 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 75 ?? 8b 7d ?? 33 f0 33 f8 03 fa}  //weight: 1, accuracy: Low
        $x_1_2 = {63 62 7a 78 6e 61 73 6b 6a 64 68 62 63 7a 78 6d 6e 62 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d 08 8b 55 ?? 83 c0 04 8b 30 89 34 8a 8b 4d ?? 8b 55 08 33 cf 8d 8c 11 ?? ?? ?? ?? 89 4d 08 8b 4d 08 8b 55 14 3b ca 0f 85 d2 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {43 3a 5c 54 65 73 74 5c 46 69 6c 65 2e 74 78 74 00 00 00 00 ?? ?? ?? ?? 2a 2e 74 78 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2b df 8b 7c 24 ?? 0f af df 03 5c 24 ?? 81 c6 ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 89 5c 24 ?? 81 fe ?? ?? ?? ?? 0f 85 09 00 8b 7c 24 ?? bb}  //weight: 1, accuracy: Low
        $x_1_6 = {33 f9 33 d8 03 fe 13 da 89 7c 24 ?? 89 5c 24 ?? 8b 54 24 ?? 8b 74 24 ?? 8b 74 24 ?? 0f af d6 03 54 24}  //weight: 1, accuracy: Low
        $x_1_7 = {33 d1 33 f0 03 d3 89 54 24 ?? 13 f7 89 74 24 ?? 8b 54 24 ?? 8b 74 24 ?? 8b 74 24 ?? 0f af d6 03 54 24}  //weight: 1, accuracy: Low
        $x_1_8 = {01 30 8b 44 24 ?? 8b 74 24 ?? 33 c2 33 f1 05 ?? ?? ?? ?? 81 d6 ?? ?? ?? ?? 0b c6 0f 85}  //weight: 1, accuracy: Low
        $x_1_9 = {01 1a 8b 54 24 ?? 8b 5c 24 ?? 33 d1 33 d8 03 d7 13 de 0b d3 0f 85}  //weight: 1, accuracy: Low
        $x_1_10 = {5c 53 69 67 6e 75 6d 5c 4a 65 69 68 61 72 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {52 75 62 79 57 6f 72 6b 2e 65 78 65 00 41 63 74 69 6f 6e 50 6c 61 59 00}  //weight: 1, accuracy: High
        $x_1_12 = {01 32 8b 54 24 ?? 8b 74 24 ?? 33 d0 33 f7 03 d1 13 f7 0b d6 0f 85}  //weight: 1, accuracy: Low
        $x_1_13 = {01 1f 8b 7c 24 ?? 8b 5c 24 ?? 33 f8 33 d9 03 fe 13 da 0b fb 0f 85}  //weight: 1, accuracy: Low
        $x_1_14 = {30 39 73 61 38 64 69 70 61 73 6c 64 61 73 30 39 64 61 30 73 30 39 69 64 70 61 73 00}  //weight: 1, accuracy: High
        $x_1_15 = {01 32 8b 54 24 ?? 8b 74 24 ?? 8b 5c 24 ?? 33 d0 33 f7 03 d1 13 f7 89 5c 24 ?? 3b da 0f 85}  //weight: 1, accuracy: Low
        $x_1_16 = {89 0a 8b 4c 24 ?? 8b 54 24 ?? 33 c8 33 (d6|d7) 03 (ce|cf) 13 (d6|d7) 0b ca 0f 85}  //weight: 1, accuracy: Low
        $x_1_17 = {33 c6 33 cf 03 c2 8b 54 24 ?? 13 cf 3b d0 0f 85 ?? ?? ?? ?? 3b f9 0f 84}  //weight: 1, accuracy: Low
        $x_1_18 = {01 08 8b 44 24 ?? 8b 0d ?? ?? ?? ?? 8b 09 89 08 8b 44 24 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_19 = {77 65 39 32 33 38 34 37 32 39 38 37 72 65 33 32 39 34 37 38 32 39 33 38 75 74 30 32 33 34 39 38 00}  //weight: 1, accuracy: High
        $x_1_20 = {89 01 8b 44 24 ?? 8b 0d ?? ?? ?? ?? 8b 09 [0-1] 89 08 8b 44 24 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_21 = {37 32 68 64 61 73 6b 75 6a 68 64 62 61 6e 73 64 62 6d 61 6e 62 73 64 6b 61 6a 73 68 00}  //weight: 1, accuracy: High
        $x_1_22 = {2c 6d 78 63 6e 7a 78 6c 6b 6a 68 63 6b 6a 73 64 00}  //weight: 1, accuracy: High
        $x_1_23 = {01 08 8b 44 24 ?? 8b 0d ?? ?? ?? ?? 8b 09 5f 89 08 8b 44 24 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_24 = {35 38 37 36 35 38 37 36 30 39 37 2d 30 39 37 2d 30 36 30 38 36 00}  //weight: 1, accuracy: High
        $x_1_25 = {33 d1 03 d0 89 54 24 ?? 8b 54 24 ?? 85 d2 0f 84 ?? ?? 00 00 a1 08 00 8b 54 24 ?? 8b 74 24}  //weight: 1, accuracy: Low
        $x_1_26 = {33 d1 03 d0 89 54 24 ?? 83 44 24 ?? ?? 83 54 24 ?? ?? 8b 54 24 ?? 85 d2 0f 84 ?? ?? 00 00 a1 08 00 8b 54 24 ?? 8b 74 24}  //weight: 1, accuracy: Low
        $x_1_27 = {53 63 69 65 6e 63 65 4d 6f 6f 45 00}  //weight: 1, accuracy: High
        $x_1_28 = {33 d0 33 d9 81 c2 ?? ?? ?? ?? 13 df 0b d3 0f 85 ?? ?? ff ff 08 00 8b 54 24 ?? 8b 5c 24}  //weight: 1, accuracy: Low
        $x_1_29 = {30 00 34 00 39 00 31 00 32 00 2d 00 32 00 31 00 30 00 34 00 38 00 31 00 32 00 30 00 37 00 35 00 31 00 32 00 39 00 2d 00 32 00 00 00}  //weight: 1, accuracy: High
        $x_1_30 = {8b 09 5f 89 08 8b 44 24 ?? 8b 00 5e 5b 8b e5 5d c2 0a 00 8b 44 24 ?? 8b 0d}  //weight: 1, accuracy: Low
        $x_1_31 = {43 79 62 6f 72 67 41 72 65 61 2e (65|64) 00 4c 6f 77 53 6d 6f 6f 74 68 53 65 6e 73 45}  //weight: 1, accuracy: Low
        $x_1_32 = {33 d9 33 d0 be ?? ?? ?? ?? 03 d6 bf ?? ?? ?? ?? 13 df 89 5c 24 ?? 8b 5c 24 ?? 3b d3 0f 85 08 00 8b 54 24 ?? 8b 5c 24}  //weight: 1, accuracy: Low
        $x_1_33 = {4c 61 6e 64 69 6e 67 46 61 72 6d 2e 65 78 65 00 45 61 72 74 68 43 6f 6d 6d 6f 45}  //weight: 1, accuracy: High
        $x_1_34 = {33 d8 33 f9 be ?? ?? ?? ?? 03 fe ba ?? ?? ?? ?? 13 da 89 5c 24 ?? 8b 5c 24 ?? 3b fb 0f 85 08 00 8b 7c 24 ?? 8b 5c 24}  //weight: 1, accuracy: Low
        $x_1_35 = {33 d6 33 c1 03 c3 13 d7 0b c2 0f 85 ?? ?? ff ff 08 00 8b 44 24 ?? 8b 54 24}  //weight: 1, accuracy: Low
        $x_1_36 = {33 d7 33 c1 03 c6 13 d3 0b c2 0f 85 ?? ?? ff ff 08 00 8b 44 24 ?? 8b 54 24}  //weight: 1, accuracy: Low
        $x_1_37 = {43 6f 6e 74 72 46 69 72 65 2e (65|64) 00 48 69 67 68 57 61 79 53 65 45}  //weight: 1, accuracy: Low
        $x_1_38 = {33 c6 33 cf 05 ?? ?? ?? ?? 81 d1 ?? ?? ?? ?? 0b c1 0f 85 06 00 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_39 = {8b 45 b0 8b 4d d8 0f b7 04 48 8b 4d dc 8b 04 81 89 45 dc}  //weight: 1, accuracy: High
        $x_1_40 = {01 32 8b 54 24 ?? 8b 74 24 ?? 33 (d0|d1) 03 (d1|d0) 89 15 ?? ?? ?? ?? 8b 44 24 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_41 = "3098423=2349230=234" wide //weight: 1
        $x_1_42 = {33 f8 33 f1 03 fa 81 d6 ?? ?? ?? ?? 33 db 3b de 0f 82 0c 00 8b 7c 24 ?? 89 74 24 ?? 8b 74 24}  //weight: 1, accuracy: Low
        $x_1_43 = {4e 61 74 75 72 61 6c 4c 61 62 2e 65 78 65 00 45 78 6f 50 6f 72 74 61 6c 49 45}  //weight: 1, accuracy: High
        $x_1_44 = {01 31 8b 4c 24 ?? 8b 74 ?? 34 33 c8 03 ca 89 0d ?? ?? ?? ?? 8b 44 24 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_45 = {01 3e 8b 7c 24 ?? 8b 74 24 ?? 33 f8 33 f1 03 fa 81 d6 ?? ?? ?? ?? 33 db 3b de 0f 82}  //weight: 1, accuracy: Low
        $x_1_46 = {01 11 8b 4c 24 ?? 8b 54 24 ?? 33 c8 (03 (ce|cf)|81 e9 ?? ?? ?? ??) 89 0d ?? ?? ?? ?? 8b 44 24 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_47 = {33 f8 33 d1 03 fe 81 d2 ?? ?? ?? ?? 33 db 3b da 0f 82 04 00 8b 54 24}  //weight: 1, accuracy: Low
        $x_1_48 = {5c 32 33 35 39 38 32 33 37 39 35 38 37 32 38 33 00}  //weight: 1, accuracy: High
        $x_1_49 = {5c 00 63 00 68 00 69 00 6c 00 64 00 72 00 65 00 6e 00 5b 00 30 00 32 00 39 00 33 00 5d 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_50 = {33 c1 89 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 69 c0 ?? ?? ?? ?? 03 45}  //weight: 1, accuracy: Low
        $x_1_51 = {01 10 8b 44 24 ?? 8b 54 24 ?? 33 c1 (05 ?? ?? ?? ??|03 ??) a3 ?? ?? ?? ?? 8b 44 24 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_52 = {00 74 6f 72 65 64 53 69 72 65 57 75 67 65 72 74 2e 65 78 65 00 46 6f 72 54 69 72 65 45 78 70 6f 73 43 00}  //weight: 1, accuracy: High
        $x_1_53 = {01 30 8b 44 24 ?? 8b 74 24 ?? 33 c2 03 c1 a3 ?? ?? ?? ?? 8b 44 24 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_54 = {01 10 8b 44 24 ?? 8b 54 24 ?? 05 ?? ?? ?? ?? 81 d2 ?? ?? ?? ?? 33 c1 89 44 24 ?? 81 f2 ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 8b 54 24 ?? 33 c1 03 c6}  //weight: 1, accuracy: Low
        $x_1_55 = {33 c9 03 c2 13 cb 89 45 ?? 89 4d ?? 8b 8d ?? ?? ?? ?? 8b 45 ?? 39 4d ?? 0f 82 ?? ?? ?? ?? 0f 87}  //weight: 1, accuracy: Low
        $x_1_56 = {01 10 8b 54 24 ?? 8b 44 24 ?? 33 d1 35 ?? ?? ?? ?? 47 03 d6 15 ?? ?? ?? ?? 33 db 3b d8 0f 82 ?? ?? ?? ?? 0f 87}  //weight: 1, accuracy: Low
        $x_1_57 = "?militaryKeyA@@YGEU" ascii //weight: 1
        $x_1_58 = {03 c1 89 44 24 ?? 8b 44 24 ?? 33 f2 33 c7 03 f1 13 c7 3b f8 0f 87 ?? ?? ?? ?? 0f 83}  //weight: 1, accuracy: Low
        $x_1_59 = {01 30 8b 44 24 ?? 8b 74 24 ?? 33 c2 03 c1 a3 ?? ?? ?? ?? e9 8b 44 24 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_60 = {33 fa 33 f3 03 c1 03 f9 13 f3 3b de 0f 87 ?? 00 00 00 0f 83 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_61 = {03 cf 33 c0 33 ce 40 2b cb d3 e0 33 d2 89 45}  //weight: 1, accuracy: High
        $x_1_62 = {66 03 0a 81 f1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 66 89 4d ?? 66 8b 4d ?? 66 8b 55 ?? 66 3b ca 0f 85}  //weight: 1, accuracy: Low
        $x_1_63 = {33 c0 40 d3 e0 33 d2 89 45 ?? 8b c3 f7 75 ?? 29 55 ?? e9}  //weight: 1, accuracy: Low
        $x_1_64 = {01 08 8b 44 24 ?? 8b 4c 24 ?? (2d ?? ?? ?? ??|03 c6) 33 c2 2d ?? ?? ?? ?? a3 ?? ?? ?? ?? e9 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_65 = {8b 45 ec 69 c0 ?? ?? ?? ?? 03 45 08 0e 00 c7 45 ec ?? ?? ?? ?? c7 45 08}  //weight: 1, accuracy: Low
        $x_1_66 = {8b 45 ec 69 c0 ?? ?? ?? ?? 01 45 08 0e 00 c7 45 ec ?? ?? ?? ?? c7 45 08}  //weight: 1, accuracy: Low
        $x_1_67 = {01 08 8b 44 24 ?? 8b 4c 24 ?? 03 c7 33 c6 03 c2 a3 ?? ?? ?? ?? e9 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_68 = {e9 0d 00 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 01 08 8b 44 24 ?? 8b 00 05 00 a3}  //weight: 1, accuracy: Low
        $x_1_69 = {8b 1b 31 1f 8b 7c 24 ?? 03 f9 8b 4c 24 ?? 33 fe 81 ef ?? ?? ?? ?? 89 39}  //weight: 1, accuracy: Low
        $x_1_70 = {8b 36 89 31 8b 4c 24 ?? 8b 74 24 ?? 81 c1 ?? ?? ?? ?? 13 f3 33 ca 33 f3 03 c8 8b 44 24 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_71 = {0f b6 c0 01 45 f8 81 45 ?? ?? ?? ?? ?? 83 55 ?? ?? 8b 45 ?? 85 c0 0f 85 ?? ?? ff ff 8b 45}  //weight: 1, accuracy: Low
        $x_1_72 = {8b 80 dc 01 00 00 8b 08 a1 ?? ?? ?? ?? 09 08 07 00 01 08 a1}  //weight: 1, accuracy: Low
        $x_1_73 = {8b 00 99 83 d6 ff 3b c1 0f 85 ?? ?? 00 00 3b d6 0f 85}  //weight: 1, accuracy: Low
        $x_1_74 = {03 c6 33 c1 8d 84 18 ?? ?? ?? ?? 89 45 ?? a1 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 83 20 00}  //weight: 1, accuracy: Low
        $x_1_75 = {8b 1b 31 18 e9 ?? ?? ff ff 83 20 00 e9 ?? ?? ff ff 06 00 8b 80}  //weight: 1, accuracy: Low
        $x_1_76 = {2b d8 03 5d ?? 89 5d ?? e9 ?? ?? ff ff 83 20 00 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_77 = {2b d8 03 5d ?? 89 5d ?? 8b 45 ?? 8b 5d ?? 8b 1b 31 18 e9 ?? ?? ff ff 83 20 00 e9}  //weight: 1, accuracy: Low
        $x_1_78 = {8b 09 01 08 8b 45 ?? 8b 0d ?? ?? ?? ?? 8b 09 89 08 8b 45 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_79 = {8b 09 31 08 8b 45 ?? 83 20 00 06 00 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_80 = {8b 3f 31 3a 8b 55 ?? 03 d0 8b 45 ?? 33 d1 2b d6 89 10}  //weight: 1, accuracy: Low
        $x_1_81 = {8b 1b 31 1f 8b 7d ?? 03 f9 8b 4d ?? 33 fa 81 ef ?? ?? ?? ?? 89 39}  //weight: 1, accuracy: Low
        $x_1_82 = {8b 1b 31 18 8b 45 ?? 8b 5d ?? 04 ?? 34 ?? 2c ?? 88 45 ?? 8a 45 ?? 84 c0 0f 85}  //weight: 1, accuracy: Low
        $x_1_83 = {8b 1b 31 18 e9 ?? ?? ff ff 83 20 00 e9 ?? ?? ff ff 06 00 8b 45 ?? 8b 5d}  //weight: 1, accuracy: Low
        $x_1_84 = {8b 09 89 08 8b 45 ?? 8b 4d ?? 8b 09 01 08 8b 45 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_85 = {8b 3f 31 38 8b 45 ?? 03 c1 8b 4d ec 33 c2 ?? c6 89 01}  //weight: 1, accuracy: Low
        $x_1_86 = {8b 12 31 10 8b 45 ?? 8b 55 ?? 8b 55 ?? 03 c6 33 c1 8d 84 10 ?? ?? ?? ?? 89 45 ?? e9 ?? ?? ff ff 83 20 00 e9}  //weight: 1, accuracy: Low
        $x_1_87 = {8b 09 31 08 8b 45 ?? 8b 4d ?? 03 c2 33 c6 2b c7 89 01}  //weight: 1, accuracy: Low
        $x_1_88 = {8b 09 31 08 8b 45 ?? 8b 4d ?? 8b 09 01 08 06 00 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_89 = {8b 09 89 08 33 c0 8b 4c 24 24 ?? 0c 01 88 4c 04}  //weight: 1, accuracy: Low
        $x_1_90 = {8b 09 31 08 8b 45 ?? 8b 0d ?? ?? ?? ?? 01 08 8b 45 ?? 8b 00}  //weight: 1, accuracy: Low
        $x_1_91 = {33 ce 33 d0 03 cf 13 d0 3b d9 0f 85 ?? ?? 00 00 39 55 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_92 = {8b 3f 31 3e 8b 75 ?? 8b 7d ?? 03 f0 33 f1 2b f2 89 37}  //weight: 1, accuracy: Low
        $x_1_93 = {8b 12 89 10 8b 44 24 ?? 8b 00 99 05 ?? ?? ?? ?? 83 d2 ff 33 c1}  //weight: 1, accuracy: Low
        $x_1_94 = {33 c0 8b 4c 24 ?? 8a 54 04 ?? 88 14 01 40 83 f8 04 0f 82}  //weight: 1, accuracy: Low
        $x_1_95 = {03 c8 89 0e 8b 4d ?? 8b 75 ?? 03 f0 01 31 06 00 8b 4d ?? 8b 75}  //weight: 1, accuracy: Low
        $x_1_96 = {2b c8 89 0a 8b 55 ?? 8b 0a 8b 7d ?? 2b c8 03 f9 89 3a 8b 0d ?? ?? ?? ?? 46 3b f1}  //weight: 1, accuracy: Low
        $x_1_97 = {8b 12 89 10 8b 44 24 ?? 8b 00 99 05 ?? ?? ?? ?? 13 d7 33 c1}  //weight: 1, accuracy: Low
        $x_1_98 = {8b 12 31 11 8b 0d ?? ?? ?? ?? 33 f6 85 c9 0f 84}  //weight: 1, accuracy: Low
        $x_1_99 = {2b d0 03 fa 8b 55 ?? 89 3e 08 00 8b 75 ?? 8b 16 8b 7d}  //weight: 1, accuracy: Low
        $x_1_100 = {8b 12 89 10 8b 44 24 ?? 8b 00 99 05 ?? ?? ?? ?? 13 d3 33 c1}  //weight: 1, accuracy: Low
        $x_1_101 = {8b 12 31 11 8b 4d ?? 8b 15 ?? ?? ?? ?? 2b c8 3b ca 0f 83}  //weight: 1, accuracy: Low
        $x_1_102 = {8b 12 31 11 8b 4d ?? 8b 55 ?? 8b 31 3b 32 0f 85}  //weight: 1, accuracy: Low
        $x_1_103 = {2b d1 3b da 0f 85 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 9a ?? ?? ?? ?? 33 d2 89 13}  //weight: 1, accuracy: Low
        $x_1_104 = {8b 09 31 08 8b 45 ?? 33 ?? 3b f8 0f 85 06 00 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_105 = {8b 09 31 08 8b 45 ?? 3b f8 0f 85 06 00 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_106 = {8b 44 24 08 8b 74 24 08 8b 36 31 30 8b 44 24 10 3b c8 07 00 33 06 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ACQ_2147667235_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACQ"
        threat_id = "2147667235"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c6 2d db ae 53 72 89 45 f8 8b 45 fc 8b 4d f8 33 c7 03 c3 3b c8 0f 85 1f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ACR_2147667236_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACR"
        threat_id = "2147667236"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 08 8b 3d [0-32] 81 c1 f0 d0 f7 ff [0-16] 89 08 83 c0 04 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ACS_2147667544_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACS"
        threat_id = "2147667544"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 06 88 45 ?? 8b 45 ?? 8a 14 16 88 14 06 8b 45 ?? 8a 55 ?? 88 14 06 ff 45 ?? 81 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e8 03 00 00 8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 ff 77 ?? e8 ?? ?? ?? ?? 89 c6 09 f6 75 (04|07) 31 c0 (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 77 38 68 00 40 02 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 24 39 77 38 75 ?? 8d 05 ?? ?? ?? ?? 89 47 08 8d 05 ?? ?? ?? ?? 89 47 0c 8d 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ACV_2147667889_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACV"
        threat_id = "2147667889"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 0c 83 e2 07 83 fa 00 74}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 0c 83 e1 07 83 f9 00 74}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 0c 83 e0 07 83 f8 00 74}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 0c 23 45 c8 83 f8 00 74 05 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ACV_2147667889_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACV"
        threat_id = "2147667889"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 77 05 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {bb 77 05 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {bf 77 05 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {b9 77 05 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 05 00 00 06 00 c7 85}  //weight: 1, accuracy: Low
        $x_10_6 = "J:\\8756j.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ACV_2147667889_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACV"
        threat_id = "2147667889"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {c4 6a 02 00 03 00 c7 45 40 00 55 8b ec 83 ec ?? c7 45 [0-240] ff 75 ?? e8 [0-21] 8b e5 5d c2 10 00}  //weight: 100, accuracy: Low
        $x_100_2 = {68 4f 02 00 03 00 c7 45 40 00 55 8b ec 83 ec ?? c7 45 [0-240] ff 75 ?? e8 [0-21] 8b e5 5d c2 10 00}  //weight: 100, accuracy: Low
        $x_100_3 = {11 98 02 00 03 00 c7 45 40 00 55 8b ec 83 ec ?? c7 45 [0-240] ff 75 ?? e8 [0-21] 8b e5 5d c2 10 00}  //weight: 100, accuracy: Low
        $x_100_4 = {cc 9a 02 00 03 00 c7 45 40 00 55 8b ec 83 ec ?? c7 45 [0-240] ff 75 ?? e8 [0-21] 8b e5 5d c2 10 00}  //weight: 100, accuracy: Low
        $x_100_5 = {04 6b 02 00 03 00 c7 45 40 00 55 8b ec 83 ec ?? c7 45 [0-240] ff 75 ?? e8 [0-21] 8b e5 5d c2 10 00}  //weight: 100, accuracy: Low
        $x_100_6 = {dc 5d 02 00 03 00 c7 45 40 00 55 8b ec 83 ec ?? c7 45 [0-240] ff 75 ?? e8 [0-21] 8b e5 5d c2 10 00}  //weight: 100, accuracy: Low
        $x_100_7 = {b2 88 02 00 03 00 c7 45 40 00 55 8b ec 83 ec ?? c7 45 [0-240] ff 75 ?? e8 [0-21] 8b e5 5d c2 10 00}  //weight: 100, accuracy: Low
        $x_100_8 = {d4 24 02 00 03 00 c7 45 40 00 55 8b ec 83 ec ?? c7 45 [0-240] ff 75 ?? e8 [0-21] 8b e5 5d c2 10 00}  //weight: 100, accuracy: Low
        $x_10_9 = {c4 6a 02 00 8b 45 fc 8b e5 5d c3 09 00 55 8b ec 83 ec 04 c7 45 fc}  //weight: 10, accuracy: Low
        $x_10_10 = {11 98 02 00 8b 45 fc 8b e5 5d c3 09 00 55 8b ec 83 ec 04 c7 45 fc}  //weight: 10, accuracy: Low
        $x_10_11 = {b2 88 02 00 8b 45 fc 8b e5 5d c3 09 00 55 8b ec 83 ec 04 c7 45 fc}  //weight: 10, accuracy: Low
        $x_10_12 = {04 6b 02 00 8b 45 fc 8b e5 5d c3 09 00 55 8b ec 83 ec 04 c7 45 fc}  //weight: 10, accuracy: Low
        $x_1_13 = {ca 85 01 00 73 06 00 81 3d}  //weight: 1, accuracy: Low
        $x_1_14 = {93 04 00 73 01 00 e0 07 00 81 3d}  //weight: 1, accuracy: Low
        $x_1_15 = {86 01 00 73 01 00 a0 07 00 81 3d}  //weight: 1, accuracy: Low
        $x_1_16 = {86 01 00 0f 83 01 00 a0 07 00 81 3d}  //weight: 1, accuracy: Low
        $x_1_17 = {4f 02 00 75 05 e8 07 00 81 bd ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_18 = {6a 02 00 75 05 e8 04 00 81 7d ?? c4}  //weight: 1, accuracy: Low
        $x_1_19 = {4f 02 00 75 05 e8 04 00 81 7d ?? 68}  //weight: 1, accuracy: Low
        $x_1_20 = {9a 02 00 75 05 e8 04 00 81 7d ?? cc}  //weight: 1, accuracy: Low
        $x_1_21 = {5d 02 00 75 05 e8 04 00 81 7d ?? dc}  //weight: 1, accuracy: Low
        $x_1_22 = {24 02 00 75 05 e8 04 00 81 7d ?? d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ACW_2147668299_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACW"
        threat_id = "2147668299"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 22 07 e4 71 50 e8 ?? ?? 00 00 89 85 ?? ?? ff ff 58 68 b6 74 75 5d 50 e8 ?? ?? 00 00 89 85 ?? ?? ff ff b8 f4 1c 19 0f 50 57 e8 ?? ?? 00 00 92 6a 00 [0-2] ff d2}  //weight: 5, accuracy: Low
        $x_1_2 = {c7 42 08 40 90 90 90 c7 42 0c ff 74 e4 f0 c7 42 10 c3 90 90 90}  //weight: 1, accuracy: High
        $x_1_3 = {c7 42 10 c3 90 90 90 c7 42 0c ff 74 e4 f0 c7 42 08 40 90 90 90}  //weight: 1, accuracy: High
        $x_1_4 = {c7 42 10 c3 90 90 90 c7 42 04 e4 83 c4 10 c7 42 08 40 90 90 90}  //weight: 1, accuracy: High
        $x_5_5 = {51 81 fa 6b 6f 72 65 59}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ACX_2147668401_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACX"
        threat_id = "2147668401"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 fa 72 c6 45 fb 6f c6 45 fc 75}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 10 ff 51 10 89 45 e0 b8 00 00 00 00 b8 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ACY_2147670563_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACY"
        threat_id = "2147670563"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 45 00 00 74 08 8b 45 ?? e9 ?? ?? ?? ?? 83 7d ?? 00 75 ?? ff 75 ?? ff 75 ?? 8b 03 01 01 01 45 4d 55 ?? 8b 04 01 01 01 01 41 42 48 51 50 03 01 01 01 50 51 52 ff 75 ?? ff 55}  //weight: 10, accuracy: Low
        $x_10_2 = {ff 55 28 89 (85 ?? ff|45 ??) ff (b5 ?? ff|75 ??) ff 55 (18|1c)}  //weight: 10, accuracy: Low
        $x_1_3 = {8b 45 0c 2b (41|42) 34 [0-10] 89 45}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 55 0c 2b 51 34 [0-10] 89 55}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 4d 0c 2b 48 34 [0-10] 89 4d}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 42 50 50 ff 75 ?? ff 55 1c}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 4a 50 51 ff 75 ?? ff 55 1c}  //weight: 1, accuracy: Low
        $x_1_8 = {6b c0 28 03 45 03 00 8b 45}  //weight: 1, accuracy: Low
        $x_1_9 = {6b d2 28 03 55 03 00 8b 55}  //weight: 1, accuracy: Low
        $n_100_10 = {89 4d fc 8b 55 fc 83 ea 01 89 55 fc 8b 45 fc 03}  //weight: -100, accuracy: High
        $n_100_11 = {8b 89 45 c4 8b 55 dc 8b 4a 3c 8b 45 f4 03 48 54 81 4d e8 80 07 5b 4a 51 8b 55 dc 81 75 e8 6a 4c 36 2a 52 8b 4d c4 51 e8}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ACZ_2147670583_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ACZ"
        threat_id = "2147670583"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d e8 33 64 7a 7a 75 15}  //weight: 1, accuracy: High
        $x_1_2 = {4d 5a 00 00 74 08 8b 45 ?? e9 ?? ?? 00 00 8b ?? ?? 8b ?? 08 03 ?? 3c 89 ?? ?? 8b ?? ?? 81 ?? 50 45 00 00 74 08 8b 45}  //weight: 1, accuracy: Low
        $x_1_3 = {74 04 eb 18 eb 16 8b}  //weight: 1, accuracy: High
        $x_1_4 = {89 45 fc 83 f8 00 74 02 eb ?? ff 75 f8 ff 75 f8 ff 75 f8 ff 75 f8 8d 55 08 83 ea 10 52 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 55 0c 89 45 ?? 89 45 ?? 83 ?? ff 75 0c c7 45 ?? 00 00 00 00 e9 ?? 00 00 00 8b ?? ?? 83 ?? 00 74 19 8b ?? ?? 8b ?? e8 03 ?? 89 ?? ?? 8b ?? ?? 8b ?? e8 03 ?? 10 89 ?? ?? eb 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_ADG_2147673744_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADG"
        threat_id = "2147673744"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 75 f6 33 c0 b1 ?? 2a ca 28 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 75 ee 8d 05}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 77 50 ff 77 34 ff 75 ?? ff d0 89 45 ?? 8d 85 ?? ?? ?? ?? c7 00 57 72 69 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ADH_2147673909_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADH"
        threat_id = "2147673909"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 50 01 b2 c3 88 50 05 5d c3 09 00 c6 00 68 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {03 51 3c 89 55 e4 8b 45 e4 8b 48 78 03 4d 08 89 4d f8 8b 55 f8 8b 42 24 03 45 08}  //weight: 1, accuracy: High
        $x_1_3 = {03 48 28 89 0d ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ADL_2147676924_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADL"
        threat_id = "2147676924"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e3 10 b9 ff ff 00 00 53 e8 9a ff ff ff 3d ?? ?? ?? ?? 75 03 89 5d b4 43 e2 ed 61 83 7d b4 00 0f 84 00 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 b4 bb 95 64 19 00 33 d2 81 c3 78 01 00 00 f7 e3 05 5f f3 6e 3c 50 8f 45 b4 ad 33 45 b4 ab e2 de}  //weight: 1, accuracy: High
        $x_1_3 = {b9 fe ff 01 00 03 c3 33 45 08 d1 c0 43 e2 f6 89 44 24 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ADM_2147676927_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADM"
        threat_id = "2147676927"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c3 33 45 08 d1 c0 43 e2 f6 89 44 24 1c 61}  //weight: 1, accuracy: High
        $x_1_2 = {03 76 3c 8b 46 34 6a 40 68 00 30 00 00 ff 76 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ADO_2147678263_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADO"
        threat_id = "2147678263"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 27 47 c0 ec 04 2a c4 73 f6 8a 47 ff 24 0f 3c ?? 75 03 5a f7 d2 42 3c 00 74 42 3c 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0c 83 33 4d ?? 8b 55 ?? 89 0c 93}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ADP_2147678315_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADP"
        threat_id = "2147678315"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 11 81 0d ?? ?? ?? ?? ?? ?? ?? ?? f6 e9 8a 4c 24 ?? 0f b6 c0 81 0d ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c9 81 15 ?? ?? ?? ?? ?? ?? ?? ?? 99}  //weight: 1, accuracy: Low
        $x_1_2 = {61 73 65 65 73 4d 61 79 6f 72 79 65 20 00}  //weight: 1, accuracy: High
        $x_1_3 = "ConeJujuloopDe" ascii //weight: 1
        $x_1_4 = {b8 66 89 68 98 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 e4 c7 45 d0 ?? ?? ?? ?? 81}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 45 d0 5b 84 54 99 b8 68 89 a9 98 89 45 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ADP_2147678315_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADP"
        threat_id = "2147678315"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 fb 03 fa 88 9d ?? ?? ff ff 8a 1f 88 1e 88 07 33 db 8a 1e}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 5d 10 03 fb 8a 1f 88 1e 88 0f 33 db 8a 1e}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 c9 8d 34 39 8a 0e 02 d1 88 95 ?? ?? ?? ?? 0f b6 d2 03 fa 8a 17}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 d2 8d 3c 1a 8a 17 88 16 88 07 33 d2 8a 16}  //weight: 1, accuracy: High
        $x_1_5 = {03 d1 8b 4d 10 81 e2 ff 00 00 00 8a 14 0a 8b 4d 08 30 14 08}  //weight: 1, accuracy: High
        $x_1_6 = {03 c3 25 ff 00 00 00 8a 14 10 8b 45 08 30 14 01}  //weight: 1, accuracy: High
        $x_1_7 = {03 c2 25 ff 00 00 00 8a 14 18 8b 45 08 30 14 01}  //weight: 1, accuracy: High
        $x_1_8 = {03 c3 25 ff 00 00 00 8a 14 10 8b 45 08 8a 1c 01 32 da}  //weight: 1, accuracy: High
        $x_1_9 = {03 c2 8a 14 31 25 ff 00 00 00 8a 04 18 32 d0}  //weight: 1, accuracy: High
        $x_1_10 = {4a 88 07 89 95 ?? ?? ?? ?? 33 d2 8a 16 8b 75 08}  //weight: 1, accuracy: Low
        $x_1_11 = {03 d9 8b 4d 10 81 e3 ff 00 00 00 8a 1c 0b 8b 4d 08 30 1c 08}  //weight: 1, accuracy: High
        $x_1_12 = {03 d9 8b 4d 08 81 e3 ff 00 00 00 8a 14 13 8a 1c 08 32 da}  //weight: 1, accuracy: High
        $x_1_13 = {03 d1 81 e2 ff 00 00 00 8a 0c 1a 8a 14 30 [0-32] 32 d1}  //weight: 1, accuracy: Low
        $x_1_14 = {0f b6 d2 8d 3c 1a 8a 17 88 16 33 d2 88 0f 8a 16 8b 75 08}  //weight: 1, accuracy: High
        $x_1_15 = {8b 55 10 8d 34 11 8a 0e 02 d9 0f b6 fb 03 fa}  //weight: 1, accuracy: High
        $x_2_16 = {8b 75 10 03 f0 8a 06 02 d8 0f b6 fb 88 9d ?? ?? ?? ?? 8b 5d 10 03 fb 8a 1f 88 1e 88 07 33 db 8a 1e 8b 75 10}  //weight: 2, accuracy: Low
        $x_1_17 = {03 c2 8b 55 10 25 ff 00 00 00 8a 14 10 8b 45 08 30 14 01}  //weight: 1, accuracy: High
        $x_1_18 = {8b 55 10 8d 3c 10 8a 07 8a 95 ?? ?? ?? ?? 02 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ADQ_2147678432_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADQ"
        threat_id = "2147678432"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 51 6a 00 6a 00 56 6a 00 83 f8 00 75 02 ff 15 ?? ?? ?? ?? 8b c8 3d 00 00 10 00 36 72 ?? 8d 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ADT_2147678498_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADT"
        threat_id = "2147678498"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 5c 38 01 b3 65 b2 4d b0 46 b1 57}  //weight: 1, accuracy: High
        $x_1_2 = {ff d6 8b 3d ?? ?? ?? ?? 50 ff d7 a3 18 00 c6 45 ?? 43 c6 45 ?? 6f c6 45 ?? 75 c6 45 ?? 6e c6 45 ?? 74 c6 45 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ADU_2147678499_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADU"
        threat_id = "2147678499"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 0f b7 44 70 fe 24 0f 8b 55 fc 0f b7 54 5a fe 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 0f b7 54 5a fe 66 81 e2 f0 00 0f b6 4d f3 66 03 d1 66 89 54 58 fe 46 8b 45 f8 85 c0 74 05 83 e8 04 8b 00 3b c6 7d 05 be 01 00 00 00 43 4f 75 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ADW_2147678675_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADW"
        threat_id = "2147678675"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 d8 20 00 10 89 45 ec c6 45 fe 8b c6 45 ff 6a c6 45 eb 55 c6 45 f3 ff c7 45 a0 00 00 00 00 c7 85 64 ff ff ff 30 00 00 00 c7 85 68 ff ff ff 03 00 00 00 c7 85 6c ff ff ff 00 00 00 00 c7 85 70 ff ff ff 00 00 00 00 c7 85 74 ff ff ff 00 00 00 00 c7 85 78 ff ff ff 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 02 00 00 80 ff 15 ?? ?? ?? ?? [0-255] 68 ?? 63 00 10 68 02 00 00 08 30 ff 15 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ADY_2147678748_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADY"
        threat_id = "2147678748"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 fa 07 75 02 eb 06 42 e9}  //weight: 2, accuracy: High
        $x_1_2 = {83 c4 14 83 c8 ff eb 5f e8 24 02 00 00 6a 20 5b 03 c3 50 6a 01 e8 2f 03 00 00 59 59 89 75 fc e8 0d 02 00 00 03 c3}  //weight: 1, accuracy: High
        $x_1_3 = {e8 c3 06 00 00 83 c4 04 85 c0 74 0f 8b 55 08 6a 01 52 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ADX_2147678793_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADX"
        threat_id = "2147678793"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 8f c0 00 00 00 00 01 00 00 e9 16 00 00 00 c7 46 1c c2 00 00 00 81 a7 c0 00 00 00 ff fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 03 3c eb 0f 85 1c 00 00 00 0f b6 43 01 0f ba f0 07 0f 83 05 00 00 00 (2d 80 00|05 80 ff) 8d 44 03 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ADX_2147678793_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADX"
        threat_id = "2147678793"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 8b da c1 eb 18 32 c3 aa eb 0a 8b fd 03 f9 8b f7 ac 32 c1 aa 41 81 f9 ?? ?? ?? 00 72 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d6 8b fd 03 f9 8b f7 ac 8b da c1 eb 18 32 c3 aa 41 81 ?? ?? ?? ?? 00 72 02 ff e5}  //weight: 1, accuracy: Low
        $x_2_3 = {8b fb f3 a5 2d ?? 07 00 00 2c ?? 33 c9 66 a5 d0 e0 30 04 19 41 83 f9 ?? 7c f7 0a 00 b9 ?? 00 00 00 be}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 78 04 0f b6 18 0f b7 ca 66 0f be 3c 0f 66 33 fb 66 33 fa bb ff 00 00 00 66 23 fb 42 66 89 3c 4e 66 3b 50 02 72 d9 5f 5b 0f b7 40 02 33 c9 66 89 0c 46}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ADZ_2147678844_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADZ"
        threat_id = "2147678844"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 07 65 57 b0 81 fa 6b 08 7b 5d b5 0d d5 f6 d6 ca 31 e6 60 eb ea 3f d7 6c 36 b8 52 de ed 21 c6 8a 76 37 cc ce 90 8c 69 d5 91 3a a3 ef 4e 54 ad}  //weight: 1, accuracy: High
        $x_1_2 = {6f 25 2b 30 ba 93 ec 98 bd 47 d8 bd 88 36 f3 1b f4 45 ef 35 c4 62 8a 3f f1 39 60 4b 9a 2b 46 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEA_2147678889_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEA"
        threat_id = "2147678889"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 d8 50 8d 45 e8 50 8d 45 e0 50 ff 75 f8 ff 15 ?? ?? 40 00 83 bd c4 f7 ff ff ff 74 [0-16] 6a 0a 68 ?? ?? 40 00 6a 01 68 ?? ?? 40 00 68 01 00 00 80 ff 15 ?? ?? 40 00 81 bd c4 f7 ff ff ?? ?? ?? ?? 76 0b 81 7d dc 0c 75 cd 01 76 02 eb ?? 8b 85 c4 f7 ff ff 40 89 85 c4 f7 ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {a0 09 01 00 0f 8d af 00 00 00 66 c7 85 e0 f7 ff ff 4f 00 66 c7 85 e2 f7 ff ff 6e 00 c7 45 f4 f4 01 00 00 81 7d f4 f4 01 00 00 0f 85 84 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEB_2147678938_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEB"
        threat_id = "2147678938"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 c0 74 05 6a 00 ff 55 0c 68 ?? ?? ?? ?? 8b 4d 08 51 e8 ?? ?? ?? ?? 83 c4 08 85 c0 74 05 6a 00 ff 55 0c}  //weight: 2, accuracy: Low
        $x_1_2 = {53 00 41 00 4d 00 50 00 4c 00 45 00 00 00 00 00 56 00 49 00 52 00 55 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {70 17 00 00 7d 07 6a 00 ff 55 ?? eb e7 0e 00 eb 09 8b 45 ?? 83 c0 01 89 45 ?? 81 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AEC_2147678948_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEC"
        threat_id = "2147678948"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 50 b8 07 00 00 00 81 c4 04 f0 ff ff 50 48 75 f6 8b 45 fc 81 c4 ?? f2 ff ff 53 56 57 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEF_2147679008_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEF"
        threat_id = "2147679008"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 75 ec 69 c3 98 e7 e9 24 01 00 00 66 81 4d fe 5c cc dd 45 f4 e8 d1 35 00 00 66 31 45 fe 8a 55 f3 08 55 fd e8 8a fe ff ff be 84 a7 40 00 8d 7d b4 b9 04 00 00 00 f3 a5 81 75 ec 75 cb ae fd e9}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 e0 a0 02 00 00 81 75 ec 9e 30 9e 39 eb 6c 33 c0 8a 45 fd 33 c9 8a 4d f3 f7 e9 88 45 fd e8 63 fe ff ff 69 45 dc de 33 48 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AEH_2147679088_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEH"
        threat_id = "2147679088"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 80 38 01 00 76 0c 81 bd ?? fb ff ff 0c 75 cd 01 77}  //weight: 1, accuracy: Low
        $x_1_2 = {32 c0 88 95 08 fc ff ff 88 9d 09 fc ff ff 33 c9 38 94 0d fc fb ff ff 75 0b 38 9c 0d fd fb ff ff 75 02 b0 01 38 94 0d fd fb ff ff 75 0b 38 9c 0d fe fb ff ff 75 02 b0 01 38 94 0d fe fb ff ff 75 0b 38 9c 0d ff fb ff ff 75 02 b0 01 38 94 0d ff fb ff ff 75 0b 38 9c 0d 00 fc ff ff 75 02 b0 01 38 94 0d 00 fc ff ff 75 0b 38 9c 0d 01 fc ff ff 75 02 b0 01 83 c1 05 81 f9 f4 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {84 c0 74 1d a1 ?? 97 40 00 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? 97 40 00 c1 e8 10 32 04 37 88 06 83 c6 01 83 ad}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_PN_2147679091_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.PN!Alureon"
        threat_id = "2147679091"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "Alureon: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_GiveThisToThatMan@12" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEI_2147679179_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEI"
        threat_id = "2147679179"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 10 0f b6 01 03 d0 81 e2 ff 00 00 00 8a 4c 14 14 30 0c 3e 46 3b f5 72 c5}  //weight: 10, accuracy: High
        $x_2_2 = {8a 54 24 0f 0f b6 c3 8a 88 ?? ?? ?? ?? 02 0e 02 d1 0f b6 c2 8d 44 04 14 8b ce 88 54 24 0f e8 ?? ?? ?? ?? fe c3 80 fb ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEL_2147679258_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEL"
        threat_id = "2147679258"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c1 02 c0 32 c2 32 04 3e 3c 22 88 04 3e 83 f9 04 41 46 3b b5}  //weight: 1, accuracy: Low
        $x_1_2 = {8a c1 02 c0 32 04 3e 32 c2 3c 22 88 04 3e 83 f9 04 41 46 3b 75}  //weight: 1, accuracy: Low
        $x_1_3 = {53 8a d8 02 db 8d 14 08 32 d3 30 14 3e 83 f8 05 7e 07 b8 02 00 00 00 eb 01 40 46 3b f5 7c e2 5b}  //weight: 1, accuracy: High
        $x_1_4 = {74 29 8b 45 ?? 0f be 88 ?? ?? ?? ?? 8b 55 ?? 83 c2 01 83 f2 ?? 2b ca 8b 45 ?? 88 88 ?? ?? ?? ?? 8b 4d ?? 83 c1 01 89 4d ?? eb ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AEO_2147679355_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEO"
        threat_id = "2147679355"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 53 ff 35 90 d4 40 00 68 ?? ?? 40 00 e8 41 11 00 00 8b 2d 50 ae 40 00 8d 45 00 50 e8 f3 68 00 00 ff 35 90 d4 40 00 68 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 26 72 34 3b 68 c4 79 51 fb e8 1f 23 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEN_2147679372_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEN"
        threat_id = "2147679372"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 f4 b5 fb 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 f4 65 4f 4e 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 dc e4 fd 52 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEP_2147679388_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEP"
        threat_id = "2147679388"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 00 00 68 ?? ?? 40 00 e8 ?? ?? 00 00 83 c4 0c 68 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 f0 a1 81 51 e8 76 1c 00 00 dd d8}  //weight: 1, accuracy: High
        $x_1_3 = {68 9f 21 c2 5f e8 66 3a 00 00 dd d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AEP_2147679388_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEP"
        threat_id = "2147679388"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 ea 89 2c ?? 83 c1 04 81 (c2|ea) ?? ?? ?? ?? 40 81 f9 ?? ?? ?? ?? 7c}  //weight: 10, accuracy: Low
        $x_2_2 = {33 fa 89 3c ?? 83 c1 04 81 (c2|ea) ?? ?? ?? ?? 40 81 f9 ?? ?? ?? ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEQ_2147679389_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEQ"
        threat_id = "2147679389"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 ?? ?? ?? ?? c7 44 24 04 ?? ?? ?? ?? c7 04 24 ?? ff ff ff e8 ?? ?? ?? ?? 83 ec 10 4b 75 d1 31 c0 80 80 ?? ?? ?? ?? 48 40 3d ?? 06 00 00 75 f1 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? ff d0 0a 00 bb ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AER_2147679392_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AER"
        threat_id = "2147679392"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e3 00 33 c0 ?? ?? 40 00 00 c1 e0 08 b0 ?? 96 bf ?? ?? ?? ?? 03 fb [0-1] b9 00 04 00 00 f3 a5}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e3 00 33 c0 ?? ?? 9c 00 00 c1 e0 08 b0 ?? 96 8d bb ?? ?? ?? ?? b9 00 04 00 00 ?? f3 a5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AEU_2147679508_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEU"
        threat_id = "2147679508"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 24 c7 45 f8 01 00 00 00 c7 45 fc 7d df af 18}  //weight: 1, accuracy: High
        $x_1_2 = "LookCrypt" ascii //weight: 1
        $x_1_3 = {c6 05 40 55 01 10 03 c6 05 00 50 01 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEV_2147679509_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEV"
        threat_id = "2147679509"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 e0 7d df af 18 c7 45 ec c0 24 ce ba c7 45 f4 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "LookCrypt" ascii //weight: 1
        $x_1_3 = {83 ec 28 c7 45 e0 7d df af 18 c7 45 ec c0 24 ce ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEW_2147679532_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEW"
        threat_id = "2147679532"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 55 28 89 45 a4 ff 75 a4 ff 55 18 89 45 a4}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 08 03 55 eb 8a 45 f7 88 02 8b 55 fc 03 55 ef 89 55 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEY_2147679550_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEY"
        threat_id = "2147679550"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 85 04 00 00 03 4d 0c 81 e1 4e 61 bc 00 89 0d e0 7f 40 00 83 2d fd ad 40 00 01 0f 83 70 ff ff ff bb 08 43 00 00 2b 5d 14 89 1d f8 92 40 00 bb 0f 20 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AEZ_2147679588_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AEZ"
        threat_id = "2147679588"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 15 66 8b 46 ?? 86 e0 66 89 46 00 83 c6 ?? 83 c3 02 e8 e2 ff ff ff 07 00 58 3b 9a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AFB_2147679635_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFB"
        threat_id = "2147679635"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 60 61 51 00 58 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? c7 80 00 12 00 00 ?? ?? ?? ?? 03 88 00 12 00 00 c7 80 04 12 00 00 ?? ?? ?? ?? 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AFC_2147679812_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFC"
        threat_id = "2147679812"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d2 ba 00 ?? 40 00 92 e8 ?? ?? ?? ?? 68 ?? 10 40 00 5a ff e2 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6f 77 65 72 65 64 20 62 79 20 09 20 28 63 29}  //weight: 1, accuracy: High
        $x_1_3 = {00 70 72 74 6b 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AFD_2147679819_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFD"
        threat_id = "2147679819"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 68 97 c3 0a 00 e8 ?? ?? ff ff 83 c4 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {56 6a 02 5e 39 75 08 72 ?? 53 57 6a 02 5f 8d 1c 36}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AFD_2147679819_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFD"
        threat_id = "2147679819"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 10 8b 1d ?? ?? ?? ?? 83 fb ff 74 2d 85 db 74 13 8d 34 9d 00 66 90 ff 16 83 ee 04 83 eb 01 75 f6 c7 04 24}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 08 00 04 00 00 c7 44 24 04 60 50 40 00 c7 04 24 00 00 00 00 ff 15 40 50 40 00 83 ec 0c 8d 7c 24 12 be ?? 40 40 00 b9 0e 00 00 00 f3 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AFE_2147679833_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFE"
        threat_id = "2147679833"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "120"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {47 65 74 53 79 73 74 65 6d 50 6f 77 65 72 53 74 61 74 75 73 00}  //weight: 50, accuracy: High
        $x_50_2 = {4e 74 50 6f 77 65 72 49 6e 66 6f 72 6d 61 74 69 6f 6e 00}  //weight: 50, accuracy: High
        $x_10_3 = {c6 02 e9 b9 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b c8 83 e9 05 89 48 01 68}  //weight: 10, accuracy: Low
        $x_10_4 = {ff d6 50 ff d7 8d 55 ?? 52 ff d0}  //weight: 10, accuracy: Low
        $x_10_5 = {c6 00 e9 b9 ?? ?? ?? 00 a1 ?? ?? ?? 00 2b c8 83 e9 05 89 48 01}  //weight: 10, accuracy: Low
        $x_10_6 = {ff d6 50 ff d7 8d 4d d0 51 ff d0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AFF_2147679914_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFF"
        threat_id = "2147679914"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 6a 40 6a 05 50 ff 55 fc 85 c0 74 3f a1 ?? ?? ?? ?? 8a 08 8b 7d f8 88 0d ?? ?? ?? ?? 8b 48 01 89 0d ?? ?? ?? ?? c6 00 e9 a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 2b c8 83 e9 05 68 ?? ?? ?? ?? 89 48 01 e8 ?? ?? ?? ?? 59 8d 4d ?? 51 ff d0 5f 5e 33 c0 c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AFG_2147679919_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFG"
        threat_id = "2147679919"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5b 32 db 81 e3 99 f0 ff ff 32 db 89 5d fc 81 c3 00 0e 00 00 83 eb 04 8b 4d 08 89 0b}  //weight: 2, accuracy: High
        $x_2_2 = {68 2d 2d 2d 2d 89 65 dc 8b 45 dc e8 00 00 00 00 59 03 4d b8 83 c1 09 ff e1 50 50}  //weight: 2, accuracy: High
        $x_1_3 = {c9 83 c4 18 66 3d 34 12 75 19 c1 e8 10 87 04 24 50 68 00 40 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {eb 19 ff 75 ec ff 75 ec ff 75 ec ff 75 ec ff 55 dc 64 a1 18 00 00 00 3e 8b 40 34 83 e8 06 74}  //weight: 1, accuracy: High
        $x_1_5 = {80 04 24 f2 8b 04 24 8b 40 01 83 c0 05 01 04 24 58 89 45 f0 8b 04 24 6a 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_F_2147680024_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.gen!F"
        threat_id = "2147680024"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 45 fc 55 bb cf 54 81 7d ec c1 f2 b9 82}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 f0 ff 75 f0 81 45 fc b7 f1 bb de ff 15 ?? ?? ?? 00 89 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AFJ_2147680069_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFJ"
        threat_id = "2147680069"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 01 00 00 00 c3 5d 81 ed 28 24 40 00 45 bb 00 00 00 00 be 00 00 00 00 8d bb 00 41 7a 00 57 33 c9 81 f9 00 04 00 00 74 38 83 f9 00 75 21 60 bb 00 00 00 00 be 00 00 00 00 8d bb 00 41 7a 00 8d 8b 73 03 00 00 bb 00 86 42 00 03 f3 f3 a5 61 8a 07 88 07 8a 47 01 88 47 01 83 c7 04 83 c1 04 eb c0 33 c9 81 f9 00 00 f0 00 74 19 81 f9 23 00 30 00 75 0e 5e 81 ee 00 00 01 00 b8 00 00 60 00 ff e6 41 eb df 00 00 00 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AFK_2147680103_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFK"
        threat_id = "2147680103"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 8b 10 8b 40 04 83 e8 08 83 c1 08 d1 e8 74 ?? 89 45 08 0f b7 01 8b f8 81 e7 00 f0 00 00 bb 00 30 00 00 66 3b fb 75 11 8b 7d 0c 2b 7d 10 25 ff 0f 00 00 03 c2 03 c6 01 38 41 41 ff 4d 08}  //weight: 1, accuracy: Low
        $x_1_2 = {40 23 c1 8d b4 ?? ?? ?? ?? ?? 8a 16 89 45 f8 0f b6 c2 03 45 fc 23 c1 89 45 fc 8d 84 ?? ?? ?? ?? ?? 8a 18 88 10 88 1e 0f b6 00 0f b6 d3 03 d0 81 e2 ff 00 00 80 79 ?? 4a 81 ca 00 ff ff ff 42}  //weight: 1, accuracy: Low
        $x_1_3 = {47 65 74 50 c7 ?? ?? 72 6f 63 41 c7 ?? ?? 64 64 72 65 c7 ?? ?? 73 73 00 00 c7 ?? ?? 56 69 72 74 c7 ?? ?? 75 61 6c 50 c7 ?? ?? 72 6f 74 65 c7 ?? ?? 63 74 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_G_2147680121_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.gen!G"
        threat_id = "2147680121"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 72 79 72 63 79 39 74 63 3b 6c 2c 6a 73 6d 2c 6b 62 78 63 2c 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 83 ec 6e 54 ff 15 ?? 10 40 00 c9 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AFO_2147680264_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFO"
        threat_id = "2147680264"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 34 07 8a c1 02 c0 32 06 32 45 ?? 3c ?? 75 17 33 d2 3b f9 0f 94 c2 33 55 ?? 74 0b 83 7d ?? 03 7d 05 8a 55 ?? 88 16 88 06 83 f9 04 7e 05}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 14 07 d3 e2 31 c2 01 da 30 14 1e 40 39 45 ?? 77 ed 89 d8 ba 00 00 00 00 f7 75 ?? 8a 04 17 30 04 1e 43 39 5d ?? 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AFP_2147680294_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFP"
        threat_id = "2147680294"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 01 84 c0 74 ?? 32 45 ff 2a 45 f8 fe c8 88 04 0a}  //weight: 5, accuracy: Low
        $x_1_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 4e 74 23 25 64 3a 20 25 73 3a 20 25 73 00 4b 45 59 20 3d 20 30 78 25 58 2c 20 4c 65 6e 20 3d 20 25 64}  //weight: 1, accuracy: High
        $x_1_3 = "LoaderPE:#%d:Write & Protect 0x%X at addr:0x%X" ascii //weight: 1
        $x_1_4 = "FromBase64Crypto: OK" ascii //weight: 1
        $x_1_5 = "LoaderPE: AntidebugAndDecrypt=0x%X" ascii //weight: 1
        $x_1_6 = "Try NtGetContextThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AFS_2147680379_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFS"
        threat_id = "2147680379"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 2e 64 6c 6c 68 65 6c 33 32 68 6b 65 72 6e 54 8b 85 f0 fd ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "hllochualAhVirtTW" ascii //weight: 1
        $x_1_3 = "hdPtrhdReahIsBaTW" ascii //weight: 1
        $x_1_4 = {66 83 38 00 74 14 8a 08 80 f9 61 7c 03 80 e9 20 c1 c9 08 ?? ?? ?? ?? ?? eb e6 89 5c 24 1c}  //weight: 1, accuracy: Low
        $x_1_5 = {89 c1 ff b5 e0 fd ff ff [0-6] 67 3f 7a [0-6] 81 fa ?? 22 7a 3f 0f 84 [0-21] 75 2d 68 0f 84 ?? ?? 00 00 [0-4] fa ?? 7b 23 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Obfuscator_AFT_2147680430_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFT"
        threat_id = "2147680430"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {60 e8 00 00 00 00 5d 83 ed 06 80 bd 3e 05 00 00 01 0f 84 48 02 00 00 c6 85 3e 05 00 00 01 8b c5 2b 85 4b 05 00 00 89 ad ce 05 00 00 89 85 8b 05 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {c7 45 cc 01 00 00 00 c7 45 c4 02 00 00 00 ff 75 dc 8d 45 c4 50 ff 75 e8 ff 75 e0 e8 ?? ?? ff ff 8b d0 8d 4d d4 e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 8b d0 8d 4d dc e8 ?? ?? ff ff 8d 4d d4 e8 ?? ?? ff ff 8d 4d c4 e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_10_3 = {8b 45 e8 3b 45 ac 0f 8f ?? 00 00 00 c7 45 cc 01 00 00 00 c7 45 c4 02 00 00 00 6a 01}  //weight: 10, accuracy: Low
        $x_5_4 = {50 45 2d 50 41 43 4b 3a 20 49 4d 50 4f 52 54 20 4c 44 52 20 45 52 52 4f 52 00}  //weight: 5, accuracy: High
        $x_5_5 = {41 44 3a 5c 50 72 6f 79 65 63 74 6f 31 2e 76 62 70 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AFU_2147680972_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFU"
        threat_id = "2147680972"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 89 45 f8 c6 06 59 c6 46 01 2a c6 46 02 38 33 c0 40 8b 17 03 d0 83 c2 02 8b 1f 03 d8 4b 8a 1b 3a 1e 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AFX_2147681083_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AFX"
        threat_id = "2147681083"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 10 00 8b f0 e8 ?? ?? ?? ?? 83 c4 04 ?? ?? ?? ?? (74 1c 57 8b 46 0c 8b 4e 08 56 89 0c 83|74 1f 57 8d 49 00 8b 46 0c 8b 4e 08 89 0c 83 8b) e8 ?? ?? ?? ?? 83 c4 04 ?? ?? ?? ?? 75 e6 5f ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 fc 68 00 00 10 00 e8 ?? ?? ?? ?? 83 c4 04 89 45 f8 83 7d fc 00 74 34 8b 45 fc 8b 48 0c 8b 55 f8 8b 45 fc 8b 40 08 89 04 8a 8b 4d fc 8b 11 89 55 f4 8b 45 fc 89 45 f0 8b 4d f0 51 e8 ?? ?? ?? ?? 83 c4 04 8b 55 f4 89 55 fc eb c6 ff 55 f8}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 00 10 00 8b f0 e8 ?? ?? ?? ?? (85 f6 59|59 8b d8) 74 1a 57 8b 46 0c 8b 4e 08 (56 89 0c 83|89 0c 83 8b) e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 e8 5f ff d3}  //weight: 1, accuracy: Low
        $x_1_4 = {89 45 f8 68 00 00 10 00 e8 ?? ?? ?? ?? 83 c4 04 89 45 fc 83 7d f8 00 74 34 8b 45 f8 8b 48 0c 8b 55 fc 8b 45 f8 8b 40 08 89 04 8a 8b 4d f8 8b 11 89 55 f4 8b 45 f8 89 45 f0 8b 4d f0 51 e8 ?? ?? ?? ?? 83 c4 04 8b 55 f4 89 55 f8 eb c6 ff 55 fc}  //weight: 1, accuracy: Low
        $x_1_5 = {56 33 c0 be ?? ?? 00 00 56 50 e8 ?? ?? ?? ?? 83 c4 08 (4e|83 ee 01) 5e c3}  //weight: 1, accuracy: Low
        $x_1_6 = {c7 45 f8 00 00 00 00 c7 45 fc ?? ?? ?? ?? eb 09 8b 45 fc 83 e8 01 89 45 fc 83 7d fc 00 7c 15 8b 4d fc 51 8b 55 f8 52 e8 ?? ?? ?? ?? 83 c4 08 89 45 f8 eb dc}  //weight: 1, accuracy: Low
        $x_1_7 = {56 33 c0 be ?? ?? 00 00 56 50 e8 ?? ?? ?? ?? (59 4e|4e 59) 59 79 f4 5e c3}  //weight: 1, accuracy: Low
        $x_1_8 = {c7 45 fc 00 00 00 00 c7 45 f8 ?? ?? ?? ?? eb 09 8b 45 f8 83 e8 01 89 45 f8 83 7d f8 00 7c 15 8b 4d f8 51 8b 55 fc 52 e8 ?? ?? ?? ?? 83 c4 08 89 45 fc eb dc}  //weight: 1, accuracy: Low
        $x_1_9 = {57 68 00 80 00 00 e8 ?? ?? ?? ?? 8b d0 (b9 00 20 00 00|33 c0 b9 00 20) 8b fa f3 ab 8b 44 24 0c 83 c4 04 85 c0 89 02 5f 74 03 89 50 04 8b c2 c3}  //weight: 1, accuracy: Low
        $x_1_10 = {68 00 80 00 00 e8 ?? ?? ?? ?? 83 c4 04 89 45 f8 8b 45 f8 89 45 fc 68 00 80 00 00 6a 00 8b 4d fc 51 e8 ?? ?? ?? ?? 83 c4 0c 8b 55 fc 8b 45 08 89 02 83 7d 08 00 74 09}  //weight: 1, accuracy: Low
        $x_1_11 = {56 57 bf 00 80 00 00 57 e8 ?? ?? ?? ?? (8b|57) 6a 00 56 e8 ?? ?? ?? ?? 8b 44 24 1c 83 c4 10 (85 c0|89 06) 74 03 89 70 04}  //weight: 1, accuracy: Low
        $x_1_12 = {56 68 00 80 00 00 e8 ?? ?? ?? ?? 68 00 80 00 00 8b f0 6a 00 56 e8 ?? ?? ?? ?? 8b 44 24 18 83 c4 10 (89 06|85 c0) 74 03 89 70 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_XXX_2147681098_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.XXX"
        threat_id = "2147681098"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 03 33 07 f7 d0 03 c1 2d 6a 2b 1e 97 89 06 83 c7 04 42 8b c2 2b 45 18 0f 85 13 00 00 00 33 d2 8b 7d 14 e9 09 00 00 00 5b 5e 5f 8b e5 5d c2 14 00 83 c3 04 83 c6 04 49 75 c6 eb ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGA_2147681140_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGA"
        threat_id = "2147681140"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 2c c7 45 ?? ?? 00 00 00 33 c0 a0 ?? ?? 40 00 33 c9 3d e9 00 00 00 0f 94 c1 88 0d ?? ?? 40 00 c7 45 ?? ?? 00 00 00 33 d2 8a 15 ?? ?? 40 00 83 fa 01 75 ?? c7 45 ?? ?? 00 00 00 33 c0 eb}  //weight: 10, accuracy: Low
        $x_1_2 = {83 c4 04 c7 45 ?? ?? 00 00 00 e8 ?? ?? ff ff c7 45 ?? ?? ?? 00 00 e8 ?? ?? ff ff c7 45 ?? ?? ?? 00 00 e8 ?? ?? ff ff c7 45 ?? ?? ?? 00 00 68 ?? ?? ?? 00 6a 00 6a 00 68 ?? ?? 40 00 6a 00 6a 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 68 ?? ?? 40 00 6a 00 6a 00 ff 15 ?? ?? 40 00 89 45 ?? 6a ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AGB_2147681325_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGB"
        threat_id = "2147681325"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 14 f3 bb 51 89 02 83 c7 04 41 8b c1 2b 45 18 0f 85 05 00 00 00 e9 0b 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGE_2147681382_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGE"
        threat_id = "2147681382"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 42 08 8b 72 0c 8b 91 b0 00 00 00 8b b9 9c 00 00 00 2b c2 1b fe 75 60 ?? 10 27 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 45 a8 03 85 54 ff ff ff 89 85 50 ff ff ff 8b 4d 08 51 6a 01 8b 55 a8 52 ff 95 50 ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {68 b4 8b 96 4f e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AGF_2147681395_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGF"
        threat_id = "2147681395"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 57 4c 4f 53 44 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 10 83 ea 12 88 10 40 39 c8 75}  //weight: 1, accuracy: High
        $x_1_3 = {83 ec 10 8b 15 0c 50 40 00 42 89 15 0c 50 40 00 39 d3 7f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGH_2147681403_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGH"
        threat_id = "2147681403"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 8d 85 ?? ?? 00 00 50 57 ff d6 85 c0 75 ?? 8b 35 ?? ?? ?? 00 53 57 57 6a 02 57 6a 01 bb 00 00 00 80 53 8d 85 ?? ?? 00 00 50 ff d6 83 f8 ff 75 ?? 57 57 6a 03 57 6a 02 68 00 00 00 40 8d 85 ?? ?? 00 00 50 ff d6 83 f8 ff 75 ?? 57 57 6a 03 57 6a 01 53 8d 85 ?? ?? 00 00 50 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGI_2147681442_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGI"
        threat_id = "2147681442"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 1c c7 45 ?? ?? ?? 00 00 6a 00 e8 ?? ?? ?? ff 83 c4 04 c7 45 ?? ?? ?? 00 00 e8 ?? ?? ff ff c7 45 ?? ?? ?? 00 00 e8 ?? ?? ff ff c7 45 ?? ?? ?? 00 00 e8 ?? ?? ff ff c7 45 ?? ?? ?? 00 00 68 ?? ?? 40 00 6a 00 6a 00 68 ?? ?? 40 00 6a 00 6a 00 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 c7 45 ?? ?? ?? 00 00 6a ff a1 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 c7 45 ?? ?? ?? 00 00 33 c0 8b e5 5d c2 10 00}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 00 6a 00 68 ?? ?? 40 00 6a 00 6a 00 ff 15 ?? ?? 40 00 89 45 ?? 6a ff 8b 55 ?? 52 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGJ_2147681489_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGJ"
        threat_id = "2147681489"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 8b 7d 08 8b 47 3c 8b 54 38 78 8b 44 38 7c 89 45 f4 03 d7 89 55 ?? 01 55 ?? 8b 4a 18 8b 5a 20 03 df 0b c9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc c1 c0 ?? 89 45 fc 8b 06 33 45 fc 89 06 83 ee 04 3b 75 08 73 e8 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGM_2147681585_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGM"
        threat_id = "2147681585"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c2 8b c7 2b c6 51 5a e2 f6 61 81 (bd|7d) [0-4] ?? ?? 00 00 74 03 83 ef 04 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 f7 e3 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? ad 33 05 ?? ?? ?? ?? 89 (45|85) [0-4] a1 ?? ?? ?? ?? bb ?? ?? ?? ?? 33 d2 f7 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGO_2147681676_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGO"
        threat_id = "2147681676"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 33 db 8d bb 00 b1 6c 00 b9}  //weight: 1, accuracy: High
        $x_1_2 = {2b db 33 d2 b9 00 00 00 00 60 61 8d bb 00 b1 6b 00 57 be 00 00 00 00 b9 f0 ff 8f 00 bb ?? ?? ?? ?? 03 f3 60 f3 a4 61}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 06 88 07 46 47 49 eb ?? 33 db 8d bb 00 b1 6b 00 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGO_2147681676_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGO"
        threat_id = "2147681676"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a5 66 a5 83 c4 04 68 ?? ?? ?? 00 a4 ff 15 ?? ?? ?? 00 0f b7 ?? ?? ?? ?? 00 69 c0 f0 49 02 00 33 c9 85 c0 7e ?? 8b c1 99 be 03 00 00 00 f7 fe 85 d2 74 ?? 8a ?? ?? ?? ?? 00 a1 ?? ?? ?? 00 80 c2 ?? 30 14 08 0f b7 ?? ?? ?? ?? 00 69 c0 f0 49 02 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGN_2147681679_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGN"
        threat_id = "2147681679"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 c7 45 ?? ?? 00 00 00 e8 ?? ?? ff ff c7 45 ?? ?? ?? 00 00 e8 ?? ?? ff ff c7 45 ?? ?? ?? 00 00 e8 ?? ?? ff ff c7 45 ?? ?? ?? 00 00 68 ?? ?? ?? 00 6a 00 6a 00 68 ?? ?? 40 00 6a 00 6a 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 6a 00 68 ?? ?? 40 00 6a 00 6a 00 ff 15 ?? ?? 40 00 89 45 ?? 6a ff}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c9 3d e9 00 00 00 0f 94 c1 88 ?? ?? ?? 40 00 c7 ?? ?? ?? 00 00 00 33 d2 8a ?? ?? ?? 40 00 83 fa 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGP_2147681748_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGP"
        threat_id = "2147681748"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c9 63 39 00 00 c1 e9 0c 03 4d 08 8b 55 d0 8b 75 08 8a 04 06 88 44 11 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGQ_2147681784_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGQ"
        threat_id = "2147681784"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 45 08 8d 34 07 8a c1 02 c0 32 06 32 45 0c 3c ?? 75 17 33 d2 3b f9 0f 94 c2 33 55 0c 74 0b 83 7d 10 ?? 7d 05 8a 55 0c 88 16 88 06}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 45 08 8b 7d ?? 8a 1c 37 02 c1 8a d1 02 d2 32 c2 32 c3 88 04 37 39 75 08 7e 1d 8b 45 0c 99 6a 03 5f f7 ff 0f b6 c2}  //weight: 1, accuracy: Low
        $x_1_3 = {8a ca 02 c9 32 cb 32 08 80 f9 06 75 1e 8d 3c 06 3b fa 75 17 8b 7d ?? 81 e7 ?? ?? ?? ?? 79 05 4f 83 cf fc 47 83 ff 02 7d 02 88 18}  //weight: 1, accuracy: Low
        $x_1_4 = {02 c9 8d 34 07 32 0e 32 4d ?? 80 f9 04 75 1b 8b 45 ?? 39 45 ?? 75 13 8b 45 ?? 6a 03 99 5b f7 fb 83 f8}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 0e 02 d2 32 c2 32 c1 81 7d ?? ?? ?? 00 00 88 06 7e 2e 8b 7d ?? 03 7d ?? 0f b6 c0 fe c1 83 f7 02 88 0e 3d ?? ?? 00 00 7e 17 8a 45 ?? 8b 5d 0c 02 c3 02 c1 0f b6 c0 99 f7 fb 80 fa}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 06 8b 3f 8b 8d ?? ?? ff ff eb 07 8a 17 48 88 11 41 47 3b c3 75 f5 8b 06 8b b5 ?? ?? ff ff 01 85 ?? ?? ff ff 83 c6 08 89 b5 ?? ?? ff ff 8d 7e fc 39 1e}  //weight: 1, accuracy: Low
        $x_1_7 = {eb 07 8a 10 4e 88 11 41 40 3b f3 75 f5 8b 85 ?? ?? ff ff 8b 00 01 85 ?? ?? ff ff 8b 85 ?? ?? ff ff 83 c0 08 8d 48 fc}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 07 8b 7d ?? 01 45 0c 83 c7 08 8d 47 fc 89 7d ?? 89 45 10 39 37 75 b3 8b 55 ?? c7 42 01 ?? ?? ?? ?? 89 55 08 39 75 ?? 75 07 c7 45 08 ?? ?? ?? ?? 8b 7d 08 ff d7}  //weight: 1, accuracy: Low
        $x_1_9 = {8a 10 ff 4d 08 88 11 41 40 39 5d 08 75 f2 8b 07 8b 7d 10 01 45 ?? 83 c7 08 8d 47 ?? 89 7d 10 89 45 0c 39 1f}  //weight: 1, accuracy: Low
        $x_1_10 = {eb 07 8a 10 4e 88 11 41 40 3b f3 75 f5 8b 45 08 8b 00 01 45 ?? 8b 45 ?? 83 c0 08 8d 48 ?? 89 45 ?? 89 4d ?? 89 45 08}  //weight: 1, accuracy: Low
        $x_1_11 = {8a 10 ff 4d ?? 88 11 41 40 39 75 ?? 75 f2 8b 45 ?? 8b 00 01 45 ?? 8b 45 ?? 83 c0 08 8d 48 ?? 89 45 ?? 89 4d ?? 89 45 ?? 39 30}  //weight: 1, accuracy: Low
        $x_1_12 = {8a 17 48 88 11 41 47 3b c3 75 f5 8b 06 8b 75 ?? 01 45 ?? 83 c6 08 89 75 ?? 8d 7e fc 39 1e 75 ?? 8b 55}  //weight: 1, accuracy: Low
        $x_1_13 = {8a 17 48 88 11 41 47 3b c3 75 f5 8b 44 24 ?? 8b 00 01 44 24 ?? 8b 44 24 ?? 83 c0 08 89 44 24 ?? 8d 78 fc 89 44 24 ?? 39 18}  //weight: 1, accuracy: Low
        $x_1_14 = {8a 13 88 11 41 43 48 75 ?? 03 3e 8b 75 ?? 83 c6 08 83 3e 00 89 75 ?? 8d 5e fc 75 ?? 8b 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AGR_2147681800_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGR"
        threat_id = "2147681800"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 7d 08 8b c7 03 40 3c 8b 48 50 0f b7 40 16 c1 e8 0d 83 e0 01}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 30 00 00 00 8b 88 0c 02 00 00 89 4d f8 85 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGS_2147681848_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGS"
        threat_id = "2147681848"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 10 03 d7 89 14 8e 41 83 c0 04 83 f9 19 7c f0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 58 8d 4f 68 51 8b 4e 38 2b c8 51 50 ff 56 4c}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 fc 3d 00 00 80 00 0f 86 ?? ?? ?? ?? 8b 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGT_2147681858_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGT"
        threat_id = "2147681858"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f0 03 00 00 e8 24 00 00 8b ?? ?? ?? 40 00 c7 ?? f4 03 00 00 00 68 88 3f}  //weight: 1, accuracy: Low
        $x_1_2 = {55 89 e5 60 8b ?? ?? c7 ?? 04 ff 75 18 ff 8b ?? ?? c7 ?? 08 75 14 ff 75 8b ?? ?? c7 ?? 0c 10 ff 75 0c 8b ?? ?? c7 ?? 10 ff 55 08 c9 8b ?? ?? c7 ?? 14 c3 00 00 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {c8 03 00 00 00 00 68 d3 8b ?? ?? ?? ?? 00 c7 ?? cc 03 00 00 c7 a7 e8 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGU_2147681882_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGU"
        threat_id = "2147681882"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 2c 24 43 fe 7d 12 8d ?? ?? ?? ?? ?? ?? 81 2c 24 93 21 de 65 8d [0-64] ad 56 e3 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGV_2147681898_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGV"
        threat_id = "2147681898"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_CorExeMain" ascii //weight: 1
        $x_1_2 = {fe 09 00 00 fe 0e 00 00 fe 0c 00 00 20 90 ec 29 d8 66 65 20 e2 6f 19 66 61 20 77 83 30 be 61 65 65 3b ?? ?? ?? ?? fe 0c 00 00 20 8a 78 b6 93 66 66 20 7f 87 49 6c 61 65 65 65 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGW_2147681900_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGW"
        threat_id = "2147681900"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_CorExeMain" ascii //weight: 1
        $x_1_2 = {04 20 ee 82 99 3c 20 82 00 20 d2 61 20 8e 06 96 0f 61 66 66 20 b7 1a c1 b7 61 66 20 db 7b e9 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGX_2147681941_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGX"
        threat_id = "2147681941"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 c7 07 66 ad 83 f8 61 72 08 83 f8 7a 77 03 83 e0 df 81 c7 a0 af 0b 00 03 f8 49 0b c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AGY_2147681947_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGY"
        threat_id = "2147681947"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 f0 81 c2 ac 95 d5 01 89 55 f0 8b 45 ec 8b 4d f0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 05 df 74 01 00 33 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKI_2147681958_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKI"
        threat_id = "2147681958"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 8c 0e c0 08 00 00 88 4c 02 11 8b 55 ?? 83 c2 01 89 55 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {3b 91 bc 08 00 00 0f 83 9c 00 00 00 8b 45 ?? 03 45 ?? 33 c9 8a 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKI_2147681958_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKI"
        threat_id = "2147681958"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 3a 50 74}  //weight: 10, accuracy: High
        $x_10_2 = {80 38 4c 74}  //weight: 10, accuracy: High
        $x_10_3 = {b0 4c 6a 08 59}  //weight: 10, accuracy: High
        $x_10_4 = {b0 4c 6a 10 59}  //weight: 10, accuracy: High
        $x_10_5 = {ab b0 4c 6a 08}  //weight: 10, accuracy: High
        $x_1_6 = {8b d0 c1 c2 10}  //weight: 1, accuracy: High
        $x_1_7 = {8b d0 c1 e2 10}  //weight: 1, accuracy: High
        $x_1_8 = {8b f0 c1 e6 10}  //weight: 1, accuracy: High
        $x_1_9 = {c1 c6 10 64 ff 31}  //weight: 1, accuracy: High
        $x_1_10 = "mmcndmgr.dll" ascii //weight: 1
        $x_1_11 = "msftedit.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AGZ_2147681976_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AGZ"
        threat_id = "2147681976"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_CorExeMain" ascii //weight: 1
        $x_1_2 = {20 8b 3c 66 c3 20 ec c9 97 a0 61 20 a1 d1 52 c7 61 20 25 20 07 a1 61 66 66 20 8b 3b 9e 75 61 20 b5 45 e3 ae 61 66 20 78 85 26 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHA_2147681977_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHA"
        threat_id = "2147681977"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 bb 0f 00 00 61 d1 9d}  //weight: 1, accuracy: High
        $x_1_2 = {20 80 77 9f 5f 61 0c}  //weight: 1, accuracy: High
        $x_1_3 = {20 a6 7a 00 43 61 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHB_2147681991_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHB"
        threat_id = "2147681991"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 52 41 53 48 5f 4c [0-5] 28 64 77 54 65 6d 70 31 2c 20 64 77 31 2c 20 64 77 32 29 3b 0d 0a 0d 0a 09 72 65 74 75 72 6e 3b 0d 0a 7d 0d 0a 0d 0a 23 65 6e 64 69 66 0d 0a 0d 0a 23 65 6c 73 65 0d 0a 76 6f 69 64 20 4f 62 66 75 73 63 61 74 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHC_2147681996_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHC"
        threat_id = "2147681996"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8f 44 24 24 8d 64 24 08 61 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {2c 45 c0 c0 02 87 d2 87 d2 aa 8a ed d0 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHC_2147681996_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHC"
        threat_id = "2147681996"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4c 4f 4f 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 08 40 3d 00 e9 a4 35 75 d0 66 51 90 90 90 90 90 66 52 90 90 90 90 90 66 b9 5a 60 90 90 90 90 90 90 90 90 90 90 66 8b d1 90 90 90 90 90 e2 fe 90 90 90 90 90 66 8b ca 90 90 90 90 90 e2 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHD_2147681997_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHD"
        threat_id = "2147681997"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 8b 45 fc 8a 44 18 ff e8 ?? ?? ?? ?? 33 c7 50 8d 45 fc e8 ?? ?? ?? ?? 5a 88 54 18 ff 43 4e 75 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {db 75 ea 8d 05 18 00 bb ?? ?? ?? ?? b8 ?? ?? ?? ?? 8b cb ba ?? ?? 00 00 e8 ?? ?? ?? ?? 4b 85}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 18 89 45 fc c6 45 ?? 47 c6 45 ?? 50 c6 45 ?? 41 33 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 19 3a 5d ?? 75 3b 8a 59 03 3a 5d ?? 75 33 8a 49 07 3a 4d ?? 75 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_AHF_2147682033_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHF"
        threat_id = "2147682033"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 6b 66 6e 6b 77 65 64 6c 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 ec 2a c6 45 f4 63 c7 45 e8 28 3a 00 00 c7 45 f0 31 62 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHG_2147682061_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHG"
        threat_id = "2147682061"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 0f be 11 83 fa 41 ?? ?? 8b 45 08 0f be 08 83 f9 5a ?? ?? 8b 55 08 0f be 02 83 e8 34 99 b9 1a 00 00 00 f7 f9 83 c2 41 8b 45 08 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 68 6a 8e 08 20 6a 01 e8 ?? ?? ?? ?? 83 c4 08 89 ?? ?? 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHH_2147682062_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHH"
        threat_id = "2147682062"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "binary-smelt" ascii //weight: 1
        $x_2_2 = {8d 44 24 14 89 44 24 0c 8d 45 04 a3 80 94 40 00 a1 80 94 40 00 8b 40 04 68 ?? 94 40 00 68 ?? 94 40 00 a3 74 94 40 00 ff 15 ?? 80 40 00 85 c0 0f 84 0b 00 00 00 68 ?? 94 40 00 ff 15 ?? 80 40 00}  //weight: 2, accuracy: Low
        $x_2_3 = {a1 74 94 40 00 a3 28 94 40 00 a1 80 94 40 00 85 c0 0f 84 17 00 00 00 a1 80 94 40 00 8b 40 08 a3 78 94 40 00 a1 7c 94 40 00 a3 30 94 40 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHH_2147682062_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHH"
        threat_id = "2147682062"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "binary-smelt" ascii //weight: 1
        $x_1_2 = "LoftWirdthird" ascii //weight: 1
        $x_1_3 = "Mainstream.workgroup" ascii //weight: 1
        $x_2_4 = {68 c2 01 00 00 be 58 96 40 00 56 ff 15 ?? 80 40 00 6a 65 58 66 89 44 24 08 68 84 94 40 00 ff 15 ?? 80 40 00 68 9c 94 40 00 6a 64 56 68 a4 94 40 00 68 ac 94 40 00 68 b4 94 40 00 ff 15 ?? 80 40 00 68 bc 94 40 00 ff 15 ?? 80 40 00 8d 44 24 14 89 44 24 0c 8d 45 04 a3 80 94 40 00 a1 80 94 40 00 8b 40 04 68 cc 94 40 00 68 d8 94 40 00 a3 74 94 40 00 ff 15 ?? 80 40 00 85 c0 0f 84 0b 00 00 00 68 e4 94 40 00 ff 15 ?? 80 40 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHI_2147682079_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHI"
        threat_id = "2147682079"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {84 03 00 00 75 [0-15] 81 [0-5] 1b 01 00 00 [0-30] 83 [0-5] 0a 81 [0-5] 28 23 00 00 75 [0-10] c1 ?? 03}  //weight: 3, accuracy: Low
        $x_3_2 = {80 38 7a 75 22 80 78 01 31 75 1c 80 78 02 79 75 16 80 78 03 63 75 10 80 78 04 74 75 0a}  //weight: 3, accuracy: High
        $x_1_3 = {25 ff 0f 00 80 79 07 48 0d 00 f0 ff ff 40}  //weight: 1, accuracy: High
        $x_3_4 = {57 c1 e6 02 8a c3 02 c0 32 04 11 32 44 24 10 0f b6 f8 3b fe 75 02 fe c0 88 04 11 83 fb 04 7e 05 33 db 43 eb 01 43 41 3b 4c 24 14 7c d7 5f 5e}  //weight: 3, accuracy: High
        $x_3_5 = {6b c9 03 49 89 4d fc 8a c8 02 c9 32 4d 08 32 0c 3e 0f b6 d1 3b 55 fc 75 02 fe c1 88 0c 3e 83 f8 04 7e 06 8b 45 08 99 f7 ff 40 46 3b 75 0c 7c d7 5e}  //weight: 3, accuracy: High
        $x_3_6 = {02 d2 32 c2 8b ?? ?? ?? 32 ?? ?? 39 ?? ?? ?? 7e 02 fe c0 83 ?? ?? ?? 03 8b ?? ?? ?? 88 ?? ?? 7e [0-15] 7e ?? 83 ?? ?? ?? 08 7d ?? 83 ?? 05 7e}  //weight: 3, accuracy: Low
        $x_3_7 = {ff ff 7e 02 fe c0 83 bd ?? ?? ff ff 03 8b ?? ?? ?? ff ff 88 [0-3] 7e [0-18] 7e ?? 83 bd ?? ?? ff ff 08 7d ?? 83 ?? 05 7e [0-45] 83 bd ?? ?? ff ff 05 7e ?? c7 85 ?? ?? ff ff 02 00 00 00 eb}  //weight: 3, accuracy: Low
        $x_3_8 = {88 07 83 fe 03 7e ?? 33 [0-5] 7e ?? 83 fe 08 7d 09 83 ?? 05 7e 04 03 ?? 88 ?? ?? 3b ?? 7c [0-8] 83 bd ?? ?? ff ff 05 7e 0c c7 85 ?? ?? ff ff 02 00 00 00 eb 06}  //weight: 3, accuracy: Low
        $x_4_9 = {8a 0c 01 80 f9 79 75 ?? ff [0-5] 8a [0-5] 02 da 32 d9 8b [0-5] 88 1c 01 85 ff 75 ?? 85 c0 75 ?? 83 [0-5] 03 81 [0-5] d0 07 00 00 7e ?? 81 [0-5] f4 01 00 00 7e 07 4f 74 04 03 c7 33 ff 83 fa 03 7e 0a 33 d2 eb 07 ?? e9 ?? fe ff ff}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AHJ_2147682105_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHJ"
        threat_id = "2147682105"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ExportedMainFunction" ascii //weight: 1
        $x_1_2 = "FluetermAmylReefonusMumpscad" ascii //weight: 1
        $x_1_3 = "GobycrowsmugOvalBahtMoms" ascii //weight: 1
        $x_1_4 = "JokeSpewleasoatmm" ascii //weight: 1
        $x_2_5 = {55 8b ec 83 e4 f8 81 ec 8c 00 00 00 c7 44 24 18 d6 d5 f6 ff c7 44 24 50 d1 d5 f6 ff c7 44 24 4c 87 20 00 00 a1 ?? ?? ?? 00 8b 4c 24 4c 25 02 20 00 00 0d 21 4b 00 00 33 d2 f7 f1 53 56 57 89 54 24 20 66 99 6a 00 ff 15 ?? ?? ?? 00 c6 44 24 30 cb 8a 44 24 30 0f b6 c8 b8 8b 00 00 00 99 f7 f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHK_2147682106_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHK"
        threat_id = "2147682106"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 10 40 c1 ca 08 e2}  //weight: 1, accuracy: High
        $x_1_2 = {c6 02 68 89 42 01 c6 42 05 c3 83 c7 04 e2}  //weight: 1, accuracy: High
        $x_1_3 = {59 5e 89 c7 f3 a4 8b 75 ?? 8d bb ?? ?? ?? ?? 29 f7 01 f8 ff e0}  //weight: 1, accuracy: Low
        $x_1_4 = {30 c0 fc f3 aa 8b 75 ?? 89 f2 03 56 3c 8d 82 f8 00 00 00 0f b7 4a 06}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 10 80 ca 60 01 d3 d1 e3 03 45 10 8a 08 84 c9 e0 ee}  //weight: 1, accuracy: High
        $x_1_6 = {0f b7 0b 0f b7 6b 02 0f b7 d1 01 f2 66 83 f9 ff 89 6c 24 28 75 08}  //weight: 1, accuracy: High
        $x_1_7 = {66 01 da 6b d2 03 66 f7 d2 c1 ca 02 89 55 10 30 10 40 c1 ca 08 e2 df}  //weight: 1, accuracy: High
        $x_1_8 = {0f b6 4c 24 13 8b 54 24 30 01 d1 80 79 01 00 8a 11 75 0e 0f b6 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_AHL_2147682151_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHL"
        threat_id = "2147682151"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d2 e0 8a cb 80 c1 09 80 e1 1a 80 e9 04 d2 ea 8b 4d ec 0a c2 88 07 8b 45 08}  //weight: 10, accuracy: High
        $x_10_2 = {8b 45 ec 8a 04 03 3a 45 08 74 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 0f b7 45 f4 83 c0 40 3b d8 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHN_2147682164_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHN"
        threat_id = "2147682164"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 38 ff 74 13 8b 30 83 c0 04 8b 38 83 c0 04 8b 08 83 c0 04 f3 a4 eb e8 68 ?? ?? ?? ?? c3 10 00 e8 00 00 00 00 58 2d ?? ?? ?? ?? 05}  //weight: 1, accuracy: Low
        $x_1_2 = {66 33 c0 66 81 38 4d 5a 74 07 2d 00 00 01 00 eb f2 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 66 8b 48 3c 66 89 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHO_2147682181_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHO"
        threat_id = "2147682181"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 83 c0 04 32 d1 88 94 35 ?? ?? ?? ?? 46 3d ?? ?? ?? ?? 7c ea 8d 85 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c2 01 89 95 ?? ?? ?? ?? 81 bd ?? ?? ?? ?? ?? ?? 00 00 7d ?? 8b 85 ?? ?? ?? ?? 8b 8c 85 ?? ?? ?? ?? 33 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? ?? eb ?? 8d 85 ?? ?? ?? ?? ff d0 06 00 8b 95}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c2 01 89 95 ?? ?? ?? ?? 81 bd ?? ?? ?? ?? ?? ?? 00 00 7d ?? 8b 85 ?? ?? ?? ?? 8b 8c 85 ?? ?? ?? ?? 33 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 88 8a ?? ?? ?? ?? eb ?? b8 ?? ?? ?? ?? ff d0 06 00 8b 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AHP_2147682192_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHP"
        threat_id = "2147682192"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb ce 8b 45 98 33 c9 8a 4c 05 e4 03 4d a8 89 4d 94 8b 15 ?? ?? ?? ?? 83 c2 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 c8 8a 08 02 4d 94}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHQ_2147682209_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHQ"
        threat_id = "2147682209"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 11 83 fa 55 74 1c 8b 45 e8 0f b6 08 83 f9 6a 74 11 8b 55 e8 0f b6 02 3d ff 00 00 00 74 04 33 c0 eb 29 83 7d 08 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHR_2147682214_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHR"
        threat_id = "2147682214"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 c0 48 67 00 00 2b c7 33 c6 0f af c2 33 c1 39 45 f8 0f 82 91 ff ff ff 5b 5f 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHS_2147682220_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHS"
        threat_id = "2147682220"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 02 ad c1 c0 10 33 45 ?? ab 83 e9 06 75 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {73 06 83 f8 7f 77 02 41 41 95 89 e8 b3 01 56 89 fe 29 c6 f3 a4 5e eb 8e 00 d2 75 05 8a 16 46 10 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHU_2147682282_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHU"
        threat_id = "2147682282"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb 12 56 19 00 fc 81 c3 fa 0f 00 00 43 33 d2 f7 e3 05 5f ec 6e 3c 90 fc 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHU_2147682282_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHU"
        threat_id = "2147682282"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ad 90 89 45 e0 90 8b 45 dc bb d3 64 19 00 81 c3 3a 01 00 00 33 d2 f7 e3 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHV_2147682284_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHV"
        threat_id = "2147682284"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 10 3c 23 75 08 80 7c 0a 01 00 74 01 46 42 8a 04 0a}  //weight: 1, accuracy: High
        $x_1_2 = {8b 47 08 80 38 4d 59 59 0f 85 ?? ?? ?? ?? 80 78 01 5a 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AXA_2147682300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AXA"
        threat_id = "2147682300"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 73 00 00 00 8b 0d ?? ?? ?? 00 66 89 01 ba 6f 00 00 00 a1 00 00 66 89 50 02 b9 73 00 00 00 8b 15 00 00 66 89 4a 18 b8 73 00 00 00 8b 0d 00 00 66 89 41 1a ba 65 00 00 00 a1 00 00 66 89 50 1c b9 73 00 00 00 8b 15 00 00 66 89 4a 1e 68 ?? ?? ?? 00 a1 00 00 50 68 02 00 00 80 ff 15 ?? ?? ?? 00 85 c0 74 07 33 c0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHX_2147682368_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHX"
        threat_id = "2147682368"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 1c 05 00 00 00 00 e9 ?? ?? ff ff 89 f8 8d 3d ?? ?? 4a 00 ab eb 00 eb e1}  //weight: 1, accuracy: Low
        $x_1_2 = {cc cc cc cc 61 00 00 00 62 00 00 00 63 00 00 00 [0-15] 6c 64 61 70 5f 63 6f 75 6e 74 5f 76 61 6c 75 65 73 [0-15] 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHY_2147682439_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHY"
        threat_id = "2147682439"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 a8 5a 2a b2 66 20 03 be 22 f5 61 66 65 20 7c 1b f7 b8}  //weight: 1, accuracy: High
        $x_1_2 = {20 60 18 48 e6 66 66 20 bb e7 b7 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AHY_2147682439_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AHY"
        threat_id = "2147682439"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 05 80 05 41 00 ?? ?? 40 00 89 1d 84 05 41 00 c7 05 88 05 41 00 ?? ?? 40 00 c7 05 8c 05 41 00 ?? ?? 40 00 c7 05 90 05 41 00 ?? ?? 40 00 c7 05 94 05 41 00 ?? ?? 40 00 c7 05 98 05 41 00 ?? ?? 40 00 c7 05 9c 05 41 00 ?? ?? 40 00 ?? ?? 00 00 00 64 8b 1d 18 00 00 00 89 1d 70 05 41 00 a1 2c 0e 41 00 8b 0d 00 f0 40 00 33 f6 89 0d ac 05 41 00 3b c6 75 20 8b 15 9c 05 41 00 6a 40 68 00 30 00 00 8b 42 14 83 c0 10 50 56 ff 15 08 f0 40 00 a3 2c 0e 41 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 15 2c 0e 41 00 89 35 64 05 41 00 89 35 68 05 41 00 89 15 68 b1 41 00 e8 ?? ?? ?? ?? 68 78 05 41 00 ff 15 2c 0e 41 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b ce 8b 1d 48 0e 41 00 2b c8 8a 09 c6 05 ac 0e 41 00 00 88 0d 1c 0e 41 00 8b 0d 1c 0e 41 00 81 e1 ff 00 00 00 d3 e3 89 1d 48 0e 41 00 33 db 8a 1c 30 2b cb 8b 1d 48 0e 41 00 d3 eb 83 f9 0b 89 0d 68 05 41 00 89 1d 48 0e 41 00 75 44 8b 15 70 05 41 00 6a 00 89 aa 00 10 00 00 a1 70 05 41 00 8b 0d 48 0e 41 00 8b 80 04 10 00 00 41 a3 70 05 41 00 89 0d 48 0e 41 00 89 a8 00 10 00 00 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIA_2147682461_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIA"
        threat_id = "2147682461"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 db 8d bb 00 41 7a 00 b9 00 04 00 00 83 f9 00 74 0a 8a 07 34 55 49 88 07 47 75 f1 61 5e 87 fe ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIB_2147682488_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIB"
        threat_id = "2147682488"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Coded by BRIAN KREBS for personal use only. I love my job" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIC_2147682513_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIC"
        threat_id = "2147682513"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 6b 66 6e 6b 77 65 64 6c 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {01 75 68 68 38 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 e8 28 3a 00 00 c7 45 f0 31 62 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AID_2147682547_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AID"
        threat_id = "2147682547"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5d 01 45 32 d9 88 5c 38 02 40 3b c6 7c ?? 85 ff c6 07 4d c6 47 01 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIE_2147682557_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIE"
        threat_id = "2147682557"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 95 d8 f6 ff ff ff d2 33 c0 5f 5e 8b 4d dc}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec b8 1e 0c 00 00 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {8a 55 ff 88 95 ab f3 ff ff 8b 45 f0 8a 8d ab f3 ff ff 88 8c 05 b8 f3 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIF_2147682602_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIF"
        threat_id = "2147682602"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 75 ef c6 45 e6 53 c6 45 e7 65 c6 45 e8 74 c6 45 e9 50 c6 45 ea 69 c6 45 eb 78 c6 45 ec 65 c6 45 ed 6c c6 45 ee 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIG_2147682667_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIG"
        threat_id = "2147682667"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {90 90 90 38 9c 05 3c f4 ff ff 75 27 8a 94 05 3d f4 ff ff b1 d8 3a d1 75 1a 8a 94 05 3e f4 ff ff b1 54 3a d1 75 0d 8a 94 05 3f f4 ff ff b1 55 3a d1 74 0a 40}  //weight: 10, accuracy: High
        $x_10_2 = {90 90 90 38 1c 30 75 1e 8a 54 30 01 b1 d8 3a d1 75 14 8a 54 30 02 b1 54 3a d1 75 0a 8a 54 30 03 b1 55 3a d1 74 0a 40}  //weight: 10, accuracy: High
        $x_10_3 = {90 90 90 38 0c 30 75 18 b2 d8 38 54 30 01 75 10 b2 54 38 54 30 02 75 08 b2 55 38 54 30 03 74 07 40 3b c3}  //weight: 10, accuracy: High
        $x_10_4 = {c6 85 e0 fd ff ff 45 c6 85 e1 fd ff ff d8 c6 85 e2 fd ff ff 54 c6 85 e3 fd ff ff 55 [0-15] 33 c0 89 85 e5 fd ff ff 88 85 e9 fd ff ff}  //weight: 10, accuracy: Low
        $x_10_5 = {90 33 c0 8d 7d f5 c6 45 f0 45 c6 45 f1 d8 c6 45 f2 54 c6 45 f3 55 ab aa 90 90}  //weight: 10, accuracy: High
        $x_10_6 = {90 c6 45 f0 45 c6 45 f1 d8 c6 45 f2 54 c6 45 f3 55 c6 45 f4 00 33 c0}  //weight: 10, accuracy: High
        $x_10_7 = {38 0c 30 75 18 b2 d8 38 54 30 01 75 10 b2 54 38 54 30 02 75 08 b2 55 38 54 30 03}  //weight: 10, accuracy: High
        $x_10_8 = {33 c0 8d 7d dd c6 45 d8 a6 c6 45 da 34 c6 45 dc d1 33 f6 ab aa 8b 3d ?? ?? 40 00 89 75 d4 3b fb 0f 86 ?? ?? 00 00 a1 ?? ?? 40 00 8a 0c 30 3a 4d d8 75 12 8a 4c 30 02 3a 4d da 75 09}  //weight: 10, accuracy: Low
        $x_10_9 = {90 90 90 90 33 c0 8d 7d d9 ab 33 f6 39 1d c8 50 40 00 aa 89 75 e0 0f 86 2b 01 00 00 a1 cc 50 40 00 0f b6 0c 30 0f b6 54 30 02 8d 79 01 3b d7 75 24 0f b6 54 30 04 8d 79 02 3b d7 75 18 0f b6 54 30 06 8d 79 03 3b d7 75 0c 0f b6 54 30 08 83 c1 04 3b d1 74 11}  //weight: 10, accuracy: High
        $x_10_10 = {33 d2 8a 14 01 8b f2 33 d2 8a 54 01 02 8d 7e 01 3b d7 75 27 33 d2 8d 7e 02 8a 54 01 04 3b d7 75 1a 33 d2 8d 7e 03 8a 54 01 06 3b d7 75 0d 33 d2 83 c6 04 8a 54 01 08 3b d6 74 0d 8b 15 a8 50 40 00 40 3b c2}  //weight: 10, accuracy: High
        $x_10_11 = {40 00 33 c9 8a 0d ?? ?? 40 00 33 c1 8b 15 ?? ?? 40 00 86 82 ?? ?? 40 00 81 3d ?? ?? 40 00 56 08 00 00 7d 1c a1 ?? ?? 40 00 83 c0 01 a3 ?? ?? 40 00 6a 01 e8 ?? ?? ff ff 83 c4 04 e9 0f 02 00 00 b9 ?? e4 40 00 ff d1}  //weight: 10, accuracy: Low
        $x_10_12 = {a1 68 60 40 00 b9 ?? 02 00 00 03 c6 8d bd ?? ?? ff ff 8d 70 0a f3 a5 66 a5 8b f0 8d 7d ?? a5 a5 66 a5 33 c0 8a 4d ?? 30 8c ?? ?? ?? ff ff 40 3d ?? 09 00 00 7c ?? 8d 85 ?? ?? ff ff ff d0}  //weight: 10, accuracy: Low
        $x_10_13 = {61 40 00 50 e8 ?? fd ff ff 59 8b 0d ?? 61 40 00 81 f9 ?? 08 00 00 88 81 ?? 61 40 00 7d 14 41 6a 01 89 0d ?? 61 40 00 e8 ?? fd ff ff 59 e9 ?? ?? 00 00 b8 ?? 61 40 00 ff d0 c6 45 ?? ?? c6 45 ?? ?? c6 45}  //weight: 10, accuracy: Low
        $x_5_14 = {90 90 90 0f be c0 74 1f c7 45 fc 00 00 eb 13 c7 46 10 00 00 03 c2 eb 02 75 17 f6 c4 44}  //weight: 5, accuracy: High
        $x_5_15 = {38 0c 30 75 16 38 54 30 01 75 10 b3 65 38 5c 30 02 75 08 b3 54 38 5c 30 03 74 07}  //weight: 5, accuracy: High
        $x_4_16 = {45 d8 54 55}  //weight: 4, accuracy: High
        $x_5_17 = {00 00 00 00 00 4a 65 22 d5}  //weight: 5, accuracy: High
        $x_1_18 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 eb}  //weight: 1, accuracy: High
        $x_1_19 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 e8}  //weight: 1, accuracy: High
        $x_1_20 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AIH_2147682673_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIH"
        threat_id = "2147682673"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "d:\\s412412l" ascii //weight: 1
        $x_2_2 = {b9 53 00 00 00 8b 15 ?? ?? ?? 00 66 89 0a b8 4f 00 00 00 8b 0d ?? ?? ?? 00 66 89 41 02 ba 46 00 00 00 a1 ?? ?? 42 00 66 89 50 04 b9 54 00 00 00 8b 15 ?? ?? ?? 00 66 89 4a 06 b8 57 00 00 00 8b 0d ?? ?? ?? 00 66 89 41 08 ba 41 00 00 00 a1 ?? ?? ?? 00 66 89 50 0a b9 52 00 00 00 8b 15 ?? ?? ?? 00 66 89 4a 0c b8 45 00 00 00 8b 0d ?? ?? ?? 00 66 89 41 0e ba 43 00 00 00 a1 ?? ?? ?? 00 66 89 50 12 b9 6c 00 00 00 8b 15 ?? ?? ?? 00 66 89 4a 14 b8 61 00 00 00 8b 0d ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_3 = {b8 53 00 00 00 8b 0d ?? ?? ?? 00 66 89 01 ba 4f 00 00 00 a1 ?? ?? ?? 00 66 89 50 02 b9 46 00 00 00 8b 15 ?? ?? ?? 00 66 89 4a 04 b8 54 00 00 00 8b 0d ?? ?? ?? 00 66 89 41 06 ba 57 00 00 00 a1 ?? ?? ?? 00 66 89 50 08 b9 41 00 00 00 8b 15 ?? ?? ?? 00 66 89 4a 0a b8 52 00 00 00 8b 0d ?? ?? ?? 00 66 89 41 0c ba 45 00 00 00 a1 ?? ?? ?? 00 66 89 50 0e b9 43 00 00 00 8b 15 ?? ?? ?? 00 66 89 4a 12 b8 6c 00 00 00 8b 0d ?? ?? ?? 00 66 89 41 14 ba 61 00 00 00 a1 ?? ?? ?? 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AIJ_2147682764_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIJ"
        threat_id = "2147682764"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4d 08 51 6a 41 6a 6a 66 8b 55 08 52 e8 57 18 00 00 83 c4 10 6a 22 e8 f0 f7 ff ff 83 c4 04 6a 6e 6a a9 66 8b 45 08 50 e8 e3 1a 00 00 83 c4 0c 6a eb 8b 4d 14 51 6a 3b 8a 55 08 52 8a 45 10 50 e8 3d 00 00 00 83 c4 14 68 eb 00 00 00 68 e2 00 00 00 e8 a1 05 00 00 83 c4 08 6a 4e 6a ae}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 ff 15 10 40 40 00 c7 45 f0 fb 00 00 00 0f bf 45 08 8b 4d f0 0f af c8 89 4d f0 8b 55 f0 81 c2 29 57 00 00 89 55 f0 66 8b 45 f8 50 68 fa 00 00 00 66 8b 4d 08 51 8a 55 f8 52 66 8b 45 08 50 e8 37 1b 00 00 83 c4 14 0f bf 4d 08 51 8a 55 08 52 6a 40 e8 1a 1f 00 00 83 c4 0c}  //weight: 1, accuracy: High
        $x_1_3 = {45 4e 44 42 4c 4f 43 4b 64 00 00 00 63 00 00 00 72 65 74 79 6a 6b 6d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIK_2147682865_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIK"
        threat_id = "2147682865"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 40 00 b8 00 10 40 00 0f ea 08 ba ?? ?? ?? ?? 83 ef ?? 83 c0 ?? b9 ?? 00 00 00 00 d8 01 c0 89 f0 29 ff 01 c0 83 ef ?? 83 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 00 10 40 00 0f ea 08 ba ?? ?? ?? ?? 83 ef ?? 83 c0 ?? b9 ?? ?? 00 00 00 d8 89 f0 29 ff 01 c0 83 ef ?? 83 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 00 10 40 00 0f ea 08 ba ?? ?? ?? ?? 83 ef ?? 29 ff b8 ?? ?? 00 00 31 c0 (81 ef ?? ??|83 ef ??) 29 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 00 10 40 00 0f ea 08 68 00 01 00 00 8d 85 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 83 c0 10 83 f8 20 7f 09 6a 00 6a ff e8}  //weight: 1, accuracy: Low
        $x_1_5 = {83 f8 10 77 09 6a 00 6a ff e8 19 00 64 ff 30 64 89 20 68 00 01 00 00 8d 85 ?? ?? ff ff 50 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {83 f8 10 eb 09 6a 00 6a ff e8 19 00 64 ff 30 64 89 20 68 00 01 00 00 8d 85 ?? ?? ff ff 50 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AIL_2147682866_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIL"
        threat_id = "2147682866"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 58 ff ff ff 01 00 00 00 (90) [0-16] c7 c7 01 00 00 00 (90) [0-16] c7 85 5c ff ff ff 01 00 00 00 (90) [0-16] 31 c0 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 85 54 ff ff ff 01 00 00 00 (90) [0-16] c7 85 5c ff ff ff 01 00 00 00 (90) [0-16] c7 85 50 ff ff ff 01 00 00 00 (90) [0-16] 31 c0 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 85 54 ff ff ff 01 00 00 00 (90) [0-16] c7 c7 01 00 00 00 (90) [0-16] c7 85 5c ff ff ff 01 00 00 00 (90) [0-16] 31 c0 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 c6 01 00 00 00 (90) (90) [0-16] c7 c7 01 00 00 00 (90) (90) [0-16] c7 85 5c ff ff ff 01 00 00 00 (90) (90) [0-16] e9 ?? 00 00 00 e9 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 85 58 ff ff ff 01 00 00 00 c7 c7 01 00 00 00 (90) (90) [0-16] c7 85 5c ff ff ff 01 00 00 00 (90) (90) [0-16] 31 c0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AIM_2147682917_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIM"
        threat_id = "2147682917"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 0a a8 04 00 89 85 7c ff ff ff c7 45 8c 00 00 00 00 c7 45 c4 00 00 00 00 81 7d dc 03 0d 00 00 7f 2f}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 76 00 6b 00 6c 00 64 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {0d 6f 79 47 65 74 44 65 76 43 61 70 73 57 00 00 57 00 69 00 6e 00 6d 00 6d 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIN_2147682963_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIN"
        threat_id = "2147682963"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 e3 00 8b cb 81 c6 00 01 00 00 83 f9 40 74 07 80 36 1b 46 41 eb f4 33 c9 bb 00 00 00 00 be 00 00 00 00 8d bb 00 41 7a 00 57 33 c9 81 f9 00 00 1f 00 77 f8}  //weight: 2, accuracy: High
        $x_2_2 = {83 f9 40 60 be 00 50 4b 00 bf 00 10 51 00 b9 00 10 00 00 f3 a5 61 74 0e 33 db 80 34 1e ?? 83 c6 01 83 c1 01 eb d8}  //weight: 2, accuracy: Low
        $x_1_3 = {80 36 1b 46 41 eb}  //weight: 1, accuracy: High
        $x_1_4 = {0c 1b b3 1b f6 d3 f6 d4 0a e3 22 c4 88 06}  //weight: 1, accuracy: High
        $x_1_5 = {33 d2 83 f9 40 74 0c 80 34 16 1b 83 c6 01 83 c1 01 eb ed}  //weight: 1, accuracy: High
        $x_1_6 = {bf 00 10 51 00 ?? b9 00 10 00 00 f3 a4 61}  //weight: 1, accuracy: Low
        $x_1_7 = {bf 00 00 00 00 b0 90 b9 00 00 02 00 bb 00 41 7a 00 03 fb}  //weight: 1, accuracy: High
        $x_1_8 = {b8 44 44 44 00 b9 44 01 00 00 60 33 f6 8d b6 34 00 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AIO_2147682972_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIO"
        threat_id = "2147682972"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 b9 c8 00 00 00 30 06 46 e2 fb 8d 05 30 ?? 40 00 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ADB_2147683253_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADB"
        threat_id = "2147683253"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a5 71 19 a6}  //weight: 1, accuracy: High
        $x_1_2 = {b1 34 61 d5}  //weight: 1, accuracy: High
        $x_1_3 = {41 6e 6f 74 68 65 72 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ADB_2147683253_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADB"
        threat_id = "2147683253"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8e 72 19 a6}  //weight: 10, accuracy: High
        $x_10_2 = {9a 35 61 d5}  //weight: 10, accuracy: High
        $x_1_3 = {b9 e9 00 00 00 39 c8 75}  //weight: 1, accuracy: High
        $x_1_4 = {bb e9 00 00 00 be 05 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {b8 e9 00 00 00 39 c1 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ADB_2147683253_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADB"
        threat_id = "2147683253"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "winpe/Reveton.FB" ascii //weight: 10
        $x_1_2 = "communityahouse.pdb" ascii //weight: 1
        $x_1_3 = "hour4house.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ADB_2147683253_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADB"
        threat_id = "2147683253"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {9a 35 61 d5}  //weight: 10, accuracy: High
        $x_10_2 = {7c 35 61 d5}  //weight: 10, accuracy: High
        $x_1_3 = {64 6f 6f 72 44 6e 69 67 68 74 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 69 6d 65 78 67 6f 76 65 72 6e 6d 65 6e 74 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 6f 6d 6d 75 6e 69 74 79 61 68 6f 75 73 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 6f 75 72 34 68 6f 75 73 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_7 = "question6right.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ADB_2147683253_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADB"
        threat_id = "2147683253"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 66 2e 0f 1f 84 00 00 00 00 00 55 89 e5 83 ec ?? a1 ?? ?? ?? ?? ff d0 a1 ?? ?? ?? ?? ff d0}  //weight: 10, accuracy: Low
        $x_10_2 = {66 0f 1f 84 00 00 00 00 00 55 89 e5 83 ec 0c a1 ?? ?? ?? ?? ff d0 a1 ?? ?? ?? ?? ff d0 a1 ?? ?? ?? ?? ff d0}  //weight: 10, accuracy: Low
        $x_10_3 = {0f 1f 00 55 89 e5 83 ec 0c a1 ?? ?? ?? ?? ff d0 a1 ?? ?? ?? ?? ff d0}  //weight: 10, accuracy: Low
        $x_10_4 = {66 0f 1f 84 00 00 00 00 00 55 89 e5 83 ec ?? a1 ?? ?? ?? ?? ff d0 a1 ?? ?? ?? ?? ff d0}  //weight: 10, accuracy: Low
        $x_10_5 = {0f 1f 80 00 00 00 00 55 89 e5 83 ec ?? c7 45 ?? 00 00 00 00 a1 ?? ?? ?? ?? ff d0 a1 ?? ?? ?? ?? ff d0}  //weight: 10, accuracy: Low
        $x_1_6 = "pointbweek.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ADB_2147683253_5
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADB"
        threat_id = "2147683253"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 00 a3 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 00 a3 ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 35}  //weight: 10, accuracy: Low
        $x_10_3 = {8b 45 00 a3 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? 89 3d}  //weight: 10, accuracy: Low
        $x_10_4 = {8b 45 00 a3 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 3d}  //weight: 10, accuracy: Low
        $x_10_5 = {00 69 6e 69 74 69 61 6c 69 7a 65 31 2e 70 64 62}  //weight: 10, accuracy: High
        $x_10_6 = {00 69 6e 73 74 61 6c 6c 30 2e 70 64 62}  //weight: 10, accuracy: High
        $x_10_7 = {00 61 63 74 69 76 61 74 65 31 2e 70 64 62 00}  //weight: 10, accuracy: High
        $x_10_8 = {00 63 6f 6d 6d 75 6e 69 74 79 61 68 6f 75 73 65 2e 70 64 62 00}  //weight: 10, accuracy: High
        $x_1_9 = {8b 40 48 8a ?? ?? ?? ?? ?? 89 85 ?? ?? ?? ?? [0-64] 8b ad 01 ff e0}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 40 48 89 45 ?? [0-64] 8b 6d 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_11 = {8b 40 48 89 85 ?? ?? ?? ?? [0-64] 8b ad 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_12 = {8b 49 48 89 ?? ?? 89 8d ?? ?? ?? ?? [0-64] 8b ad 01 ff e0}  //weight: 1, accuracy: Low
        $x_1_13 = {8b 41 48 89 85 ?? ?? ?? ?? [0-64] 8b ad 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_14 = {8b 42 48 89 45 ?? [0-64] 8b 6d 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_15 = {8b 41 48 89 45 ?? [0-64] 8b 6d 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_16 = {8b 49 48 89 4d ?? [0-64] 8b 6d 00 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ADB_2147683253_6
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ADB"
        threat_id = "2147683253"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_300_1 = {89 41 04 c7 44 24 04 0f 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 1c}  //weight: 300, accuracy: Low
        $x_300_2 = {89 41 04 c7 45 ?? 00 00 00 00 c7 44 24 04 0f 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 1c}  //weight: 300, accuracy: Low
        $x_300_3 = {89 41 10 c7 44 24 04 0e 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 14}  //weight: 300, accuracy: Low
        $x_300_4 = {89 41 14 c7 44 24 04 0b 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 18}  //weight: 300, accuracy: Low
        $x_300_5 = {89 41 04 c7 44 24 04 0f 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? c7 45 ?? 00 00 00 00 89 41 1c}  //weight: 300, accuracy: Low
        $x_300_6 = {89 41 10 c7 44 24 04 0e 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? c7 45 ?? 00 00 00 00 89 41 14}  //weight: 300, accuracy: Low
        $x_300_7 = {89 41 10 c7 44 24 04 0e 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? c6 45 ?? ?? 8b 4d ?? 89 41 14}  //weight: 300, accuracy: Low
        $x_300_8 = {89 41 14 c7 45 ?? 00 00 00 00 c7 44 24 04 0b 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 18}  //weight: 300, accuracy: Low
        $x_300_9 = {89 41 18 c7 44 24 04 0c 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 01 c7 44 24 04 0e 00 00 00}  //weight: 300, accuracy: Low
        $x_300_10 = {89 41 34 c7 04 ?? 0b 00 00 00 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 ec 04 8b 4d [0-7] 89 41 38 c7 04 ?? 0c 00 00 00 b9}  //weight: 300, accuracy: Low
        $x_300_11 = {89 41 14 c7 44 24 04 0b 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? ?? ?? ?? ?? 8b 4d ?? ?? ?? ?? ?? 89 41 18}  //weight: 300, accuracy: Low
        $x_300_12 = {89 41 10 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 44 24 04 0e 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 14}  //weight: 300, accuracy: Low
        $x_300_13 = {89 41 10 ff [0-5] c7 44 24 04 0e 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 14 [0-7] c7 44 24 04 0b 00 00 00}  //weight: 300, accuracy: Low
        $x_300_14 = {89 41 14 83 [0-6] c7 44 24 04 0b 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 18 [0-7] c7 44 24 04 0c 00 00 00}  //weight: 300, accuracy: Low
        $x_300_15 = {89 41 14 83 ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 44 24 04 0b 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 18 ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 44 24 04 0c 00 00 00}  //weight: 300, accuracy: Low
        $x_300_16 = {c7 44 24 04 0e 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 04 ?? ?? ?? ?? c7 44 24 04 0f 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 89 41 1c}  //weight: 300, accuracy: Low
        $x_300_17 = {c7 44 24 04 0c 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 89 01 ?? ?? ?? ?? ?? ?? ?? c7 44 24 04 0e 00 00 00 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 89 41 04}  //weight: 300, accuracy: Low
        $x_100_18 = {c7 44 24 04 0c 00 00 00 c7 04 24 ?? ?? ?? ?? e8 [0-32] 89 41 10}  //weight: 100, accuracy: Low
        $x_100_19 = {c7 44 24 04 0e 00 00 00 c7 04 24 ?? ?? ?? ?? e8 [0-32] 89 41 14}  //weight: 100, accuracy: Low
        $x_100_20 = {c7 44 24 04 0b 00 00 00 c7 04 24 ?? ?? ?? ?? e8 [0-32] 89 41 18}  //weight: 100, accuracy: Low
        $x_1_21 = {70 6f 69 6e 74 62 77 65 65 6b 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_22 = {68 6f 75 72 34 68 6f 75 73 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_23 = "question6right.pdb" ascii //weight: 1
        $x_1_24 = "kindggroup.pdb" ascii //weight: 1
        $x_1_25 = "mother6book.pdb" ascii //weight: 1
        $x_1_26 = "name0result.pdb" ascii //weight: 1
        $x_1_27 = "doorFroom.pdb" ascii //weight: 1
        $x_1_28 = "idea-year.pdb" ascii //weight: 1
        $x_1_29 = "lawbservice.pdb" ascii //weight: 1
        $x_1_30 = "person3part.pdb" ascii //weight: 1
        $x_1_31 = "parentsmonth.pdb" ascii //weight: 1
        $x_1_32 = "gamebreason.pdb" ascii //weight: 1
        $x_1_33 = "place4family.pdb" ascii //weight: 1
        $x_1_34 = {b1 34 61 d5 e8}  //weight: 1, accuracy: High
        $x_1_35 = {bc 02 63 d5 e8}  //weight: 1, accuracy: High
        $x_1_36 = {26 35 61 d5 e8}  //weight: 1, accuracy: High
        $x_1_37 = {b5 31 61 d5 e8}  //weight: 1, accuracy: High
        $x_1_38 = {0d 89 63 d5 e8}  //weight: 1, accuracy: High
        $x_1_39 = {cd fe 62 d5 c7}  //weight: 1, accuracy: High
        $x_1_40 = {cd fe 62 d5 66}  //weight: 1, accuracy: High
        $x_1_41 = {cd fe 62 d5 c6}  //weight: 1, accuracy: High
        $x_1_42 = {9a 35 61 d5 e8}  //weight: 1, accuracy: High
        $x_1_43 = {e6 34 61 d5 66}  //weight: 1, accuracy: High
        $x_1_44 = {2c 32 61 d5 e8}  //weight: 1, accuracy: High
        $x_1_45 = {0d 89 63 d5 c7 45 ?? ?? ?? ?? ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_46 = {5d 35 61 d5 e8}  //weight: 1, accuracy: High
        $x_1_47 = {e6 34 61 d5 (c7|e8)}  //weight: 1, accuracy: Low
        $x_1_48 = {cd fe 62 d5 e8}  //weight: 1, accuracy: High
        $x_1_49 = "factWnight.pdb" ascii //weight: 1
        $x_1_50 = "law4history.pdb" ascii //weight: 1
        $x_1_51 = {8b 40 4c 89 [0-43] 8b 40 50 89 [0-43] 8b 40 54 89 [0-43] 8b 40 44 89 [0-43] 8b 40 48}  //weight: 1, accuracy: Low
        $x_1_52 = {8b 40 4c 89 [0-43] 8b 40 50 89 [0-43] 8b 40 54 89 [0-43] 8b 41 44 89 [0-43] 8b 40 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_100_*))) or
            ((1 of ($x_300_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_WZ_2147683290_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.WZ"
        threat_id = "2147683290"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 89 75 ?? 0f af 75 ?? 6a 40 68 00 10 00 00 c1 e6 02 56 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 8d 46 18 89 45 ?? 8b 40 38 68 00 30 00 00 50 6a 00 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIS_2147683348_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIS"
        threat_id = "2147683348"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 10 00 00 00 8b 46 50 8d 55 f8 52 6a 40 50 53 ff d7 8b 4e 50 6a 40 68 00 10 00 00 51 6a 00 ff 15 ?? ?? ?? ?? 8b 4e 50 8b d1 c1 e9 02 8b f8 8b f3 f3 a5 8b ca 83 e1 03 50 89 45 08 f3 a4 e8 ?? ?? ff ff 8b 45 10 8b 4d f4 50 8b 45 08 ba ?? ?? ?? ?? 51 2b d3 50 03 d0 ff d2}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 68 00 04 00 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ff ff 85 c0 75 13 8b 44 24 78 50 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f0 68 03 01 00 00 8d 8c 24 80 00 00 00 57 51 e8 ?? ?? 00 00 57 8d 94 24 8c 00 00 00 68 ?? ?? ?? ?? 52 89 2e ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIT_2147683371_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIT"
        threat_id = "2147683371"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\dusrweqrjtra\\ZngfzkL\\EHbu\\paPpxhk\\ixQxpyupa\\jrnny" wide //weight: 1
        $x_1_2 = "c:\\trbcl\\snphJk\\uvspQEVn\\jrrBiK" wide //weight: 1
        $x_1_3 = "C:\\Ttdcs\\mbezCtm\\Brjibjwn\\Mbpzip\\mkWsK.shv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIU_2147683378_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIU"
        threat_id = "2147683378"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 48 8b 54 24 4c 8a 54 24 13 2c 07 02 c2 83 44 24 40 01 88 44 24 13 8a 44 24 27 0f b6 c0 99 83 d1 00 3b ca 0f 82 ?? ff ff ff 0f 87 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 f4 65 54 00 00 c7 45 f8 7a 0c 00 00 c7 45 fc df 34 00 00 8b 45 fc 8b 75 f8 69 c0 bf 09 00 00 33 d2 f7 f6 8b 55 f4 8b 75 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIV_2147683405_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIV"
        threat_id = "2147683405"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 02 42 49 75 fa c3}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 f0 8b 45 fc 8b 40 28 03 45 f4 8b 55 f0 89 42 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIW_2147683493_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIW"
        threat_id = "2147683493"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d4 d8 40 00 e0 dc e0 dc e0 ab c9 d8 b4 d6 d3 c7 a5 c8 c8 d6 c9 d7 d7 e0 b0 d3 c5 c8 b0 cd c6 d6 c5 d6 dd a5 e0 d2 d8 c8 d0 d0 92 c8 d0 d0 e0 ab}  //weight: 1, accuracy: High
        $x_1_2 = {34 70 40 00 2b ?? 5c 71 40 00 [0-2] 30 70 40 00 03 ?? ?? 88 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIX_2147683495_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIX"
        threat_id = "2147683495"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 08 33 d2 33 c0 85 c9 76 3b 53 55 8b 6c 24 18 56 8b 74 24 10 57 8b 7c 24 1c 8d 64 24 00 8b ca 83 e1 1f bb 01 00 00 00 d3 e3 85 dd 74 09 8a 0e 88 0f 47 46 40 eb 01}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 66 8b 02 8b e8 81 e5 00 f0 00 00 81 fd 00 30 00 00 75 12 8b 29 25 ff 0f 00 00 03 c5 8b 2c 30 03 c6 03 ef 89 28 83 c2 02 4b 75 d3 8b 5c 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AIY_2147683601_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AIY"
        threat_id = "2147683601"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 11 32 d8 88 1c 11 a1 ?? ?? ?? ?? 40 83 f8 10 a3 ?? ?? ?? ?? 75 ?? 33 c0 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 41 4e 89 0d ?? ?? ?? ?? 75 ?? 5e 5b}  //weight: 1, accuracy: Low
        $x_1_2 = {64 8b 1d 18 00 00 00 89 1d [0-20] 8b ?? 30 ?? ?? ?? ?? ?? 8b ?? 0c a3 ?? ?? ?? ?? 8b ?? 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJA_2147683931_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJA"
        threat_id = "2147683931"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 08 32 01 90}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7d fc 90 ff e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJC_2147684140_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJC"
        threat_id = "2147684140"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b e5 58 8d 28 33 c0 8b c4 74 ff 20}  //weight: 1, accuracy: High
        $x_1_2 = {8b e5 59 8d 29 33 c9 8b cc 74 ff 21 55 8b fd 33 ec 33 ef 83 ec ?? [0-24] 2b c0 74 ff c0 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {b3 cd a1 b1 e5 fb 53 fa 2e ae 81 2b 5f db d7 1a 4e 31 62 31 65 bc b7 97 cb 11 43 6f a3 9d 97 14 48 f1 23 ed 21 7e 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AJE_2147684267_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJE"
        threat_id = "2147684267"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 28 d8 aa 83 c6 01 49 83 f9 00 75 f2 8b 5c 24 04 89 d9 8b 5b 0c 89 d8 8b 5b 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJF_2147684333_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJF"
        threat_id = "2147684333"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 37 8d 37 b9 22 00 00 00 42 81 fa 54 54 00 00 75 e8 08 00 33 d2 8d ba 00 00 60 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJG_2147684356_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJG"
        threat_id = "2147684356"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 15 30 00 00 00 8b 52 0c 8b 52 14 8b 72 28 b9 18 00 00 00 33 ff 33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e1 04 8b 55 ?? c1 ea 05 33 ca 03 4d ?? 89 4d ?? 8b 45 ?? c1 e8 0b 83 e0 03}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e1 04 8b 55 ?? c1 ea 05 33 ca 03 4d ?? 8b 45 ?? c1 e8 0b 83 e0 03}  //weight: 1, accuracy: Low
        $x_1_4 = {33 d2 b9 09 00 00 00 f7 f1 8b 54 95 ?? 52 68 04 01 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 10 85 c0 74 06}  //weight: 1, accuracy: Low
        $x_1_5 = {51 8b 55 08 83 c2 04 52 68 00 00 20 00 8b 45 fc 50 68 02 01 00 00 ff 55 24 89 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AJH_2147684368_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJH"
        threat_id = "2147684368"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 2e 64 6c 6c 68 65 6c 33 32 68 6b 65 72 6e 54 8b 85 f0 fd ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {68 75 61 6c 41 68 56 69 72 74 54 57 89 e8 8d 80}  //weight: 1, accuracy: High
        $x_1_3 = {68 64 52 65 61 58 50 68 49 73 42 61 54 57 8b 85}  //weight: 1, accuracy: High
        $x_1_4 = {66 83 38 00 74 ?? 8a 08 80 f9 61 7c ?? 80 e9 20 [0-1] c1 c9 08}  //weight: 1, accuracy: Low
        $x_1_5 = {81 ea 22 67 3f 7a 5a 0f 84 ?? ?? 00 00 52 81 ea 67 22 7a 3f 5a 0f 84 [0-8] 81 fa 28 6d 35 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJK_2147684482_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJK"
        threat_id = "2147684482"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 a4 01 00 00 bb ?? ?? ?? ?? 31 1e 81 eb ?? ?? ?? ?? a5 e2 f5 83 c0 06 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJM_2147684548_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJM"
        threat_id = "2147684548"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6c 4f 73 65 20 4e 65 77 20 54 79 50 65 20 57 41 56 65 41 55 44 69 4f 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 63 69 53 65 6e 64 53 74 72 69 6e 67 41 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 c3 ba 30 00 00 00 80 c3 02 81 f6 ?? ?? ?? ?? 31 f7 b9 ?? ?? ?? ?? 8a 06 00 d8 aa 83 c6 01 e2 f6 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJN_2147684565_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJN"
        threat_id = "2147684565"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 28 fc bf 07 00 9c 60 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 34 24 ((8a 0e 0f b6 c1 8d 76 01 ff 34 85 ?? ?? ?? ??|ac 0f b6 c0 ff 34 85 ?? ?? ?? ??)|(8a 06 0f b6 c0 46 ff 34 85 ?? ?? ?? ??|8a 06 46 0f b6 c0 8d 14 85 ?? ?? ?? ??))}  //weight: 1, accuracy: Low
        $x_1_2 = {68 eb 2f 76 e0 e8 ?? ?? ?? ?? 68 5e ce d6 e9 89 45 e4 e8 ?? ?? ?? ?? 68 f2 79 36 18 89 45 e8 e8 ?? ?? ?? ?? 8b 7d 08 33 f6 89 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJO_2147684628_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJO"
        threat_id = "2147684628"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 8b 02 81 38 04 00 00 80 0f 85 dd 01 00 00 8b 0d ?? ?? ?? 00 83 c1 01 89 0d ?? ?? ?? 00 83 3d ?? ?? ?? 00 26 0f 83 d2 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b1 3f 3e 30 0c 06 40 92 92 87 e4 3b c7 8b ff 72 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJR_2147684686_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJR"
        threat_id = "2147684686"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 48 50 8b c4 ff 10 06 00 ff 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJP_2147684822_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJP"
        threat_id = "2147684822"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 00 09 41 00 03 05 3c 09 41 00 8b 0d 3c 09 41 00 8a 10 88 91 00 f9 40 00 a1 3c 09 41 00 0f be 88 00 f9 40 00 0f b6 15 04 09 41 00 33 ca 88 4d ff a1 3c 09 41 00 8a 4d ff 88 88 00 f9 40 00 8b 15 3c 09 41 00 83 c2 01 89 15 3c 09 41 00 81 3d 3c 09 41 00 5e 01 00 00 72 a6 ff 25 08 09 41 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 f9 6b 75 14 8d 0d 09 10 40 00 89 0d 00 09 41 00 8d 05 41 11 40 00 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJU_2147684938_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJU"
        threat_id = "2147684938"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 f8 8d 7c 3d ?? 8a 17 80 f2 ?? 80 ea ?? 88 17 8b 55 ?? 8b 7d ?? 80 f2 ?? 80 ea ?? 02 c2 3c 08 72 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJV_2147684960_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJV"
        threat_id = "2147684960"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 25 ff 00 00 00 8a 04 10 3c ff 74 22 c1 e3 06 0a d8 58 c1 e8 08 49 75 e7 8b c3 c1 e0 08 86 e0 c1 c8 10 86 e0 ab 4f 59 49 75 ad}  //weight: 1, accuracy: High
        $x_1_2 = {68 3c 3d 3e 3f 68 38 39 3a 3b 68 34 35 36 37 68 30 31 32 33 68 2c 2d 2e 2f 68 28 29 2a 2b 68 24 25 26 27 68 20 21 22 23 68 1c 1d 1e 1f 68 18 19 1a 1b 68 14 15 16 17 68 10 11 12 13 68 0c 0d 0e 0f 68 08 09 0a 0b 68 04 05 06 07 68 00 01 02 03}  //weight: 1, accuracy: High
        $x_1_3 = {68 33 00 32 00 68 65 00 6c 00 68 72 00 6e 00 68 6b 00 65 00 54 68 10 00 12 00 8b cc 6a 00 8b c4 6a 00 8b dc 53 51 50 6a 00 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AJY_2147685197_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJY"
        threat_id = "2147685197"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 04 17 41 eb ed 89 fb 89 f7 b9 ?? ?? ?? ?? 31 d2 ac 32 04 13 (42 aa|aa 42) 89 d0 31 d2 bd ?? ?? ?? ?? f7 f5 e2 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJZ_2147685233_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJZ"
        threat_id = "2147685233"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 45 14 ab 83 e9 04 75 f3 6a 04 68 00 30 00 00 ff 75 18 6a 00 ff 93 ?? ?? ?? ?? 09 c0 0f 84 ?? ?? ?? ?? 89 45 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {66 8b 48 06 89 c2 81 c2 f8 00 00 00 ff 72 10 8b 42 14 03 45 f0 50 8b 42 0c 03 45 08 50 e8 ?? 00 00 00 83 c2 28 66 49 75 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AKB_2147685300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKB"
        threat_id = "2147685300"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 77 75 70 73 2e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_1_2 = {41 44 73 42 75 69 6c 64 45 6e 75 6d 65 72 61 74 6f 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKC_2147685674_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKC"
        threat_id = "2147685674"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 33 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 eb c3}  //weight: 1, accuracy: Low
        $x_1_2 = {7c ac 8b 7e 34 3b df 74 74 8b 86 a0 00 00 00 85 c0 74 6a 8b 8e a4 00 00 00 85 c9 74 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKD_2147685693_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKD"
        threat_id = "2147685693"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f8 ff 36 58 8d 76 04 89 c2 bb 01 00 00 00 83 7d fc 00 74 05 8b 5d fc eb 01}  //weight: 1, accuracy: High
        $x_1_2 = {ac 3c c2 75 fb ac 3c 14 75 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKE_2147686157_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKE"
        threat_id = "2147686157"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 00 6e 00 69 00 78 00 20 00 66 00 69 00 6c 00 65 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 74 00 61 00 72 00 67 00 65 00 74 00 6a 00 6f 00 62 00 00 00 5c 5c 76 6d 77 61 72 65 2d 68 6f 73 74 3a 59 20 00 00 00 00 44 6f 6d 61 69 6e 42 69 67 53 70 61 63 65 20 72 65 73 75 6c 74 69 69 74 65 6d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKG_2147687030_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKG"
        threat_id = "2147687030"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 89 45 e4 58 8b 45 e4 83 78 64 02 73 07 33 c0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKG_2147687030_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKG"
        threat_id = "2147687030"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StealthVirtualAlloc" ascii //weight: 1
        $x_1_2 = "StormVirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AKG_2147687030_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKG"
        threat_id = "2147687030"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 89 45 e4 58 8b 45 e4 83 78 64 02 73 07 33 c0 e9}  //weight: 1, accuracy: High
        $x_1_2 = "StealthVirtualAlloc" ascii //weight: 1
        $x_1_3 = "StormVirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKH_2147687070_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKH"
        threat_id = "2147687070"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 3e 05 8d 74 3e 0a 8a 06 ?? d3 32 d0 8b 45 f8 83 c6 02 88 94 05 c4 f3 ff ff 40 3d ?? ?? ?? ?? 89 45 f8 7e e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKK_2147687163_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKK"
        threat_id = "2147687163"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 80 94 01 00 00 8b 00 8b 89 94 01 00 00 8b 09 8b 40 3c 0f b7 44 01 06}  //weight: 1, accuracy: High
        $x_1_2 = {8b 8f 8c 01 00 00 53 eb 13 35 ?? ?? ?? ?? 05 ?? ?? ?? ?? 66 89 01 83 c1 02 83 c2 02 0f b7 02 bb ?? ?? ?? ?? 66 3b c3 75 e0 33 c0 66 89 01 8b 87 8c 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 86 8c 01 00 00 c1 e7 ?? 03 c7 eb 0a 80 f1 ?? 80 c1 ?? 88 08 40 42 8a 0a 80 f9 ?? 75 ef c6 00 00 8b 86 8c 01 00 00 03 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AKP_2147688195_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKP"
        threat_id = "2147688195"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 16 8b c7 8b 40 3c 03 c7 8b 40 29 3d ?? ?? 00 00 0f 84 ?? ?? ?? ?? 25 ?? 00 00 00 3d ?? 00 00 00 0f 84 ?? ?? ?? ?? cc}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8b c3 05 88 00 00 00 ff 10 85 d2 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKQ_2147688263_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKQ"
        threat_id = "2147688263"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8d 50 ec ff ff 8a 55 fe 88 94 0d 58 ec ff ff 8b 85 50 ec ff ff 83 c0 01 89 85 50 ec ff ff 8b 8d 50 ec ff ff 3b 8d a0 eb ff ff 0f 85 ?? ?? ff ff 8d 95 74 ec ff ff ff d2}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 07 50 c6 47 01 24 c6 47 02 78 e8 00 00 00 00 58 89 45 fc 33 db e9}  //weight: 1, accuracy: High
        $x_1_3 = {8a 10 3a 57 01 0f 85 ?? ?? ff ff 40 8a 00 3a 47 02 0f 85 ?? ?? ff ff e9}  //weight: 1, accuracy: Low
        $x_1_4 = {c6 07 50 c6 47 01 24 c6 47 02 78 e8 00 00 00 00 58 89 45 fc 33 c0 40 8b 0e 03 c8}  //weight: 1, accuracy: High
        $x_1_5 = {8a 1a 3a 5f 01 75 ?? 42 8a 12 3a 57 02 75 ?? 89 4d ?? 03 06}  //weight: 1, accuracy: Low
        $x_1_6 = {46 75 63 6b 69 6e 67 20 4e 4f 44 33 32 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AKR_2147688264_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKR"
        threat_id = "2147688264"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 31 89 85 ?? ?? ff ff 83 a5 ?? ?? ff ff 00 eb 0d 8b 85 ?? ?? ff ff 40 89 85 ?? ?? ff ff 8b 85 ?? ?? ff ff 35 ?? ?? ?? ?? (0f 84 ?? ??|74)}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 31 2b 85 ?? ?? ff ff 89 85 ?? ?? ff ff (b8|c7 85)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKU_2147688738_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKU"
        threat_id = "2147688738"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 89 c7 31 c7 89 f8 5f 8b 00 8b 64 24 08 64 8f 05 00 00 00 00 58 5b}  //weight: 1, accuracy: High
        $x_1_2 = {c7 04 24 01 00 00 00 59 d3 c0 8a dc b4 00 d3 cb 59 49 75 ea}  //weight: 1, accuracy: High
        $x_1_3 = {30 14 39 49 75 fa}  //weight: 1, accuracy: High
        $x_1_4 = {31 04 24 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_AKV_2147688770_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKV"
        threat_id = "2147688770"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 e4 a9 52 09 8b 45 ?? 50 e8 ?? ?? ?? ?? 83 c4 08 89 45 ?? 83 7d ?? 00 74 ?? c7 45 13 00 64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 40 08 89 45 ?? 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKW_2147688813_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKW"
        threat_id = "2147688813"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 21 43 34 12 b9 ff ff ff 77 8b 44 24 00 f7 d0 c1 c8 03 2b c1 89 04 24 49 75 ef 58 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AKX_2147688898_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AKX"
        threat_id = "2147688898"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0f 33 c0 57 51 50 68 80 01 00 00 ff 35 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 5f 47 47 47 47 4b 75 e0 6a 00 6a 04 68 97 01 00 00 ff 35}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 4a 23 c2 90 f7 d2 42 03 c2 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AJB_2147689129_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AJB"
        threat_id = "2147689129"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 41 4c 4c 45 47 41 54 4f 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 49 4e 53 45 52 49 4d 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5c 57 69 6e 64 77 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 62 26 68 73 67 32 33 35 36 64 67 2f 35 36 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b d0 8b 45 f8 0f b6 44 18 ff 33 d0 8d 45 f4 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? 83 c6 02 43 8b 45 f8 e8 ?? ?? ?? ?? 3b d8 7e 05 bb 01 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 3b f0 7e 96}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ALA_2147689170_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALA"
        threat_id = "2147689170"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 98 7f ff 79}  //weight: 1, accuracy: High
        $x_5_2 = {25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 0f b6 c0 8b [0-5] 0f be [0-5] 33 c8 8b [0-5] 88 [0-5] 8b [0-5] d1 e8 89 [0-5] 8b [0-5] 0f be [0-5] 8b [0-5] 41 89 [0-5] 85 c0 75}  //weight: 5, accuracy: Low
        $x_2_3 = {f3 a9 94 9d 9c 90 cd cd 51 db b3 83 f7 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ALA_2147689170_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALA"
        threat_id = "2147689170"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e3 cf 29 6f}  //weight: 2, accuracy: High
        $x_5_2 = {25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 0f b6 c0 8b [0-5] 0f be [0-5] 33 c8 8b [0-5] 88 [0-5] 8b [0-5] d1 e8 89 [0-5] 8b [0-5] 0f be [0-5] 8b [0-5] 41 89 [0-5] 85 c0 75}  //weight: 5, accuracy: Low
        $x_1_3 = {88 94 8a 92 9b 13 0c ad e1 83 1f 55 9c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {88 08 8b 45 f0 c1 e8 10 25 ff ff 00 00 0f b7 c0 89 45 e0 8b 45 f0 25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 0f b6 c0 0f af 45 e0 03 45 f0 03 45 e0 89 45 e0 8b 45 e0 05 17 54 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ALB_2147689207_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALB"
        threat_id = "2147689207"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 66 2e 0f 1f 84 00 00 00 00 00 55 89 e5 83 ec [0-8] e8 ?? ff ff ff [0-21] 8b 40 30 83 c4 ?? 5d c3 [0-5] 0f 1f}  //weight: 5, accuracy: Low
        $x_5_2 = {66 66 2e 0f 1f 84 00 00 00 00 00 55 89 e5 [0-3] 81 e4 ?? ff ff ff (81|83) ec}  //weight: 5, accuracy: Low
        $x_5_3 = {a7 6e 19 a6}  //weight: 5, accuracy: High
        $x_5_4 = {8c 61 10 b1}  //weight: 5, accuracy: High
        $x_2_5 = {0f 1f 84 00 00 00 00 00 55 89 e5 53 57 56}  //weight: 2, accuracy: High
        $x_1_6 = {89 04 24 c7 44 24 08 00 2e 01 00 c7 44 24 04 00 00 00 00 ff}  //weight: 1, accuracy: High
        $x_1_7 = {b9 00 5c 02 00 89 4c 24 08 31 ff 89 7c 24 04 89 04 24 ff d6 83 ec 0c}  //weight: 1, accuracy: High
        $x_1_8 = {24 08 ba 00 04 00 00 89 54 24 04 89 0c 24 ff d0 83 ec 10 31 c0 89 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ALF_2147689711_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALF"
        threat_id = "2147689711"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {51 53 8b c1 56 c7 44 24 08 00 00 00 00 bb ?? ?? ?? ?? 8d 70 01 8a 10 83 c0 01 84 d2 75 f7 2b c6 8b f0 33 c0 85 f6 7e 0a 30 1c 08 83 c0 01 3b c6 7c f6 8b c1 c7 47 18 0f 00 00 00 c7 47 14 00 00 00 00 c6 47 04 00 8d 70 01 8d a4 24 00 00 00 00 8a 10 83 c0 01 84 d2 75 f7 2b c6 50 51 8b cf e8 1c fc ff ff 5e 8b c7 5b 59 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ALM_2147690521_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALM"
        threat_id = "2147690521"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 13 8e c0 09 50 e8 ?? ?? 00 00 8b 4d ?? 68 ee 38 83 0c 51 a3 ?? ?? 40 00 e8 ?? ?? 00 00 68 f2 5d d3 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ALM_2147690521_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALM"
        threat_id = "2147690521"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 10 49 88 14 06 40 85 c9 75 f5}  //weight: 5, accuracy: High
        $x_10_2 = {8a 14 06 88 14 19 33 d2 8b c1 f7 35 ?? ?? ?? ?? 46 85 d2 75 06 03 35}  //weight: 10, accuracy: Low
        $x_5_3 = {25 ff 00 00 00 8a 8c 85 ?? ?? ff ff 8b 85 ?? ?? ff ff 30 0c 07}  //weight: 5, accuracy: Low
        $x_1_4 = {68 cd ac ce 26}  //weight: 1, accuracy: High
        $x_1_5 = {68 a7 5b 66 f0}  //weight: 1, accuracy: High
        $x_1_6 = {68 01 cb 89 40}  //weight: 1, accuracy: High
        $x_1_7 = {68 6d ab f0 38}  //weight: 1, accuracy: High
        $x_1_8 = {68 ae 75 d1 4d}  //weight: 1, accuracy: High
        $x_1_9 = {68 82 23 54 40}  //weight: 1, accuracy: High
        $x_1_10 = {68 28 6f 8e 42}  //weight: 1, accuracy: High
        $x_1_11 = {68 da 6e d6 50}  //weight: 1, accuracy: High
        $x_1_12 = {68 4f f8 ff b6}  //weight: 1, accuracy: High
        $x_1_13 = {68 e6 58 e1 68}  //weight: 1, accuracy: High
        $x_1_14 = {68 19 53 7c d2}  //weight: 1, accuracy: High
        $x_1_15 = {68 27 52 cb 5e}  //weight: 1, accuracy: High
        $x_1_16 = {68 05 3c 64 be}  //weight: 1, accuracy: High
        $x_1_17 = {68 db 03 e9 4a}  //weight: 1, accuracy: High
        $x_1_18 = {68 e4 65 e7 a3}  //weight: 1, accuracy: High
        $x_1_19 = {68 ff 52 c6 49}  //weight: 1, accuracy: High
        $x_1_20 = {68 86 0c f2 e3}  //weight: 1, accuracy: High
        $x_1_21 = {68 7b 5f 37 e2}  //weight: 1, accuracy: High
        $x_1_22 = {68 35 9a 81 7f}  //weight: 1, accuracy: High
        $x_1_23 = {68 e3 4e 83 ea}  //weight: 1, accuracy: High
        $x_1_24 = {68 6e e3 74 c0}  //weight: 1, accuracy: High
        $x_1_25 = {68 fb 70 0d dc}  //weight: 1, accuracy: High
        $x_1_26 = {68 d8 a4 30 27}  //weight: 1, accuracy: High
        $x_1_27 = {68 c2 5c b1 4f}  //weight: 1, accuracy: High
        $x_1_28 = {68 cc 04 7f 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((25 of ($x_1_*))) or
            ((1 of ($x_5_*) and 20 of ($x_1_*))) or
            ((2 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ALO_2147690831_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALO"
        threat_id = "2147690831"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 48 01 33 4b 08 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 8d 48 01 33 4b 04 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 8d 48 01 33 0b 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 40}  //weight: 1, accuracy: High
        $x_1_2 = {e8 00 00 00 00 58 89 45 ?? c6 45 ?? 42 c6 45 ?? 21 c6 45 ?? 33 33 c0 40 8b 55 ?? 03 d0 4a 8a 12 3a 55 ?? 75 f2}  //weight: 1, accuracy: Low
        $x_1_3 = {03 d0 c6 45 ?? 47 c6 45 ?? 41 c6 45 ?? 50 8b 42 ?? 48 83 f8 00 72 5f 8b 72 ?? 03 37 8b c8 c1 e1 02 03 f1 8b 4e ?? 03 0f 8a 49 03 3a 4d ?? 75 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_GTK_2147690940_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.GTK"
        threat_id = "2147690940"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 89 e3 81 ec 80 00 00 00 89 e6 46 89 f7 [0-8] 6a 01 e8 ?? ?? ff ff 83 c4 04 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ALR_2147691866_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALR"
        threat_id = "2147691866"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 01 00 00 81 fa 00 40 02 00 0f 84 ?? 00 00 00 81 fa 00 a0 06 00 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 04 c7 04 24 90 01 00 00 83 ec 04 89 34 24}  //weight: 1, accuracy: High
        $x_1_3 = {33 c9 8a 04 ?? 41 84 c0 75 f8 49 8b c1}  //weight: 1, accuracy: Low
        $x_1_4 = {83 ec 04 48 3d 0a 02 00 00 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ALS_2147691928_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALS"
        threat_id = "2147691928"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 07 35 c6 47 01 5e c6 47 02 74 8b 45 ?? 33 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1b 3a 5f 02 75 ?? 89 b5 ?? ?? ?? ?? 83 c1 02 83 c1 14 8b d1 8b 85 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ALV_2147692578_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALV"
        threat_id = "2147692578"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 02 10 80 f7 eb 03 d3 c1 fa 0a 8b ca c1 e9 1f 03 ca}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 16 74 02 33 c0 83 c0 01 33 d0 8b d1 83 45 ?? 21 83 75 ?? 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ALX_2147693919_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALX"
        threat_id = "2147693919"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 db}  //weight: 1, accuracy: High
        $x_1_2 = {8b 42 08 89 45 e0 8b 4d f0 8b 51 0c 89 55 e8 ff 75 e8 ff 75 e0 ff 75 dc ff 75 e4 8b 45 fc ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ALY_2147693922_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALY"
        threat_id = "2147693922"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 14 10 30 11}  //weight: 2, accuracy: High
        $x_3_2 = {83 40 70 01 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
        $x_3_3 = {83 41 70 01 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
        $x_3_4 = {83 42 70 01 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
        $x_3_5 = {83 43 70 01 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
        $x_3_6 = {83 46 70 01 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
        $x_3_7 = {ff 40 70 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
        $x_3_8 = {ff 41 70 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
        $x_3_9 = {ff 42 70 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
        $x_3_10 = {ff 43 70 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
        $x_3_11 = {ff 45 70 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
        $x_3_12 = {ff 46 70 8b ?? 04 0f b7 ?? 06 39 ?? 70}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AMD_2147694151_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AMD"
        threat_id = "2147694151"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 45 d8 3e 00 66 c7 45 da 4c 00 66 c7 45 dc 1d 00 c7 45 e4 03 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 08 25 ff ff 00 00 8a 44 45 d8 8a 1c 11 32 d8 88 1c 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AME_2147694240_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AME"
        threat_id = "2147694240"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d6 8b 45 f4 8a 0c 38 ff 05 ?? ?? ?? ?? 2a cb 80 f1 3f 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AMI_2147694469_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AMI"
        threat_id = "2147694469"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d2 83 ec 10 8b 95 ?? ?? ?? ?? 8a 8d ?? ?? ?? ?? 2a 8d ?? ?? ?? ?? 8b 52 34 8b b5 ?? ?? ?? ?? 03 56 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {89 4b 10 89 43 0c 89 7b 08 89 73 04 66 8b 85 ?? ?? ?? ?? 0f b7 c8 89 0b ff d2 83 ec 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AMK_2147695001_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AMK"
        threat_id = "2147695001"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 8b 0f ad 4e 4e 4e 33 c1 4a 59 75 04 5a 2b f2 52 aa 49 75 eb}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec b8 ?? ?? ?? ?? 6a 0f 03 c1 50 59 58 8f 05 ?? ?? ?? ?? 51 8b c8 41 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AML_2147695213_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AML"
        threat_id = "2147695213"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 33 c9 ac 0b c8 87 f7 ac 4b 33 c1 87 f7 8b cb e3 0b 4f aa 59 e2 e9 59 58 5b c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b d0 50 56 bf ?? ?? ?? ?? 57 53 b8 1c 00 00 00 e8 10 00 b9 (16|2d|2f) 0d 00 00 a1 ?? ?? ?? ?? 50 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AMM_2147695375_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AMM"
        threat_id = "2147695375"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 8b ce 03 c8 8a 09 88 0c 02 8d 48 01 33 4b 04 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 8d 48 01 33 0b 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 40 ff 8d 0c fe ff ff 75 cb}  //weight: 1, accuracy: High
        $x_1_2 = {50 ff 55 d0 8b d8 53 ff 55 cc 89 45 e8 46 83 ff 64 76 ca e8 00 00 00 00 58}  //weight: 1, accuracy: High
        $x_1_3 = {75 f2 8b 55 ec 03 d0 8a 12 3a 55 84 75 e6 8b 55 ec 03 d0 42 8a 12 3a 55 85 75 d9}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 ab 56 c6 45 ac 69 c6 45 ad 72 c6 45 ae 74 c6 45 af 75 c6 45 b0 61 c6 45 b1 6c c6 45 b2 41 c6 45 b3 6c c6 45 b4 6c c6 45 b5 6f c6 45 b6 63 c6 45 b7 00 8d 45 ab 50 53 ff 55 e8}  //weight: 1, accuracy: High
        $x_1_5 = {eb 28 ac d1 e8 74 4d 11 c9 eb 1c 91 48 c1 e0 08 ac e8 2c 00 00 00 3d 00 7d 00 00 73 0a 80 fc 05 73 06 83 f8 7f 77 02}  //weight: 1, accuracy: High
        $x_1_6 = {8b 55 f4 0f b6 14 02 33 57 04 8b 4d f4 88 14 01 40 4e 75 ec 8b 07 89 45 ec e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_AMO_2147695409_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AMO"
        threat_id = "2147695409"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 7a 6c 73 79 77 29 2b 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 7b 68 7c 6c 72 29 2b 00}  //weight: 1, accuracy: High
        $x_1_3 = {4e 6b 7a 71 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {03 f7 8a 0e 0f be c1 33 c3 69}  //weight: 1, accuracy: High
        $x_1_5 = {be bb b3 8a 68}  //weight: 1, accuracy: High
        $x_1_6 = {ba 4a af 3b 94}  //weight: 1, accuracy: High
        $x_1_7 = {ba 7e 00 3a 43}  //weight: 1, accuracy: High
        $x_1_8 = {ba b5 83 75 26}  //weight: 1, accuracy: High
        $x_1_9 = {ba 14 eb 45 17}  //weight: 1, accuracy: High
        $x_1_10 = {ba d2 18 ab be}  //weight: 1, accuracy: High
        $x_1_11 = {ba 24 9e 93 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_BZA_2147695430_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZA"
        threat_id = "2147695430"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8b 4d 0c 2b c8 8a 14 01 8a 18 32 da 88 18 40 4e 75}  //weight: 1, accuracy: High
        $x_1_2 = {40 48 60 83 e8 0a 83 c0 0a 61}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 c6 45 ?? 46 c6 45 ?? 75 c6 45 ?? 63 c6 45 ?? 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AMQ_2147695454_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AMQ"
        threat_id = "2147695454"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 89 d7 01 df 89 fa 5f 81 e3 ff ff 0f 00 53 31 04 24 58 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {81 04 24 f8 00 00 00 5f 53 89 d3 31 d3 89 da 5b 3b 44 3a 0c 74 2e}  //weight: 1, accuracy: High
        $x_1_3 = {51 52 c7 04 24 01 00 00 00 59 d3 c0 8a dc b4 00 d3 cb 59 49 75 ea}  //weight: 1, accuracy: High
        $x_1_4 = {74 2e 51 52 31 d2 33 55 e4 87 d1 5a 36 32 84 29 e4 fe ff ff ff 4d ec ff 45 e4}  //weight: 1, accuracy: High
        $x_1_5 = {33 50 04 87 d1 5a 51 51 83 04 24 f8 59 d1 e9 50 83 04 24 08 58 eb 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_AMR_2147695543_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AMR"
        threat_id = "2147695543"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 8b 35 ?? ?? 40 00 8b 3d ?? ?? 40 00 23 d6 8b 32 66 3b f7 74 08 81 ea 00 00 01 00 eb f1 89 55 f8 8b c2 66 3b d7 0f 85 ?? ?? ?? ?? 01 00 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 48 3c 03 c1 83 c0 78 8b 00 8b 75 f8 56 03 f0 8b 46 20 5f 03 f8 8b 46 14 89 45 ec 89 75 f4 33 c0 89 45 fc 8b c8 8b 75 0c}  //weight: 1, accuracy: High
        $x_2_3 = {ff 4d 5a a0 17 03 00 00 00 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AMV_2147696032_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AMV"
        threat_id = "2147696032"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 08 dd 45 08 b8 ab aa aa aa dd 55 f8 f7 65 fc d9 ee dd 5d 08 d1 ea 81 c2 93 78 9f 2a}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 08 8b 50 04 89 4d e8 89 55 ec 8b 45 08 50 8d 4d cc 51 ff 55 0c 83 c4 08 8d 4d cc e8 9f 27 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AMY_2147696073_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AMY"
        threat_id = "2147696073"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 8e a0 02 b2 (e8|e9)}  //weight: 1, accuracy: Low
        $x_1_2 = {68 de a9 e0 95 (e8|e9)}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 45 0c 2b 45 10 (05|2b|2d) ?? ?? ?? ?? 89 45 fc 68 ?? ?? 41 00 6a (06|2d|2f) 68 ?? ?? 41 00 b9 01 00 00 00 69 d1 ?? ?? 00 00 81 c2 ?? ?? 40 00 ff d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_BZB_2147696172_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZB"
        threat_id = "2147696172"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 4d 75 11 33 c9 8a 0d ?? ?? ?? ?? 83 f9 5a 0f 84 8e 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 33 c9 8a 88 ?? ?? ?? ?? 83 f1 30 8b 55 fc 88 8a ?? ?? ?? ?? 8b 45 fc 33 c9 8a 88 ?? ?? ?? ?? 83 e9 30 8b 55 fc 88 8a ?? ?? ?? ?? d9 05 ?? ?? ?? ?? d8 05 ?? ?? ?? ?? d8 05 ?? ?? ?? ?? d8 05 ?? ?? ?? ?? d9 1d ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZC_2147696174_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZC"
        threat_id = "2147696174"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 74 21 33 c0 05 00 00 00 00 8a 88 ?? ?? ?? ?? 80 f1 ?? 80 e9 ?? 88 88 ?? ?? ?? ?? 40 3d 00 2c 00 00 72 06 00 80 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 b8 49 00 00 00 f7 f1 ba 2e 06 00 00 2b d0 b8 4d 5a 00 00 89 15 ?? ?? ?? ?? 66 39 45 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANA_2147696206_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANA"
        threat_id = "2147696206"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 4b 61 74 65 72 69 6d 61 74 65 72 59 61 6d 65 6c 69 00 4e 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff d0 e8 15 00 00 00 47 65 74 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 49 6e 66 6f 00 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {83 7d 0c 01 0f 84 ?? ?? 00 00 83 7d 0c 02 0f 84 ?? ?? 00 00 81 7d 0c 13 01 00 00 0f 84 ?? ?? 00 00 83 7d 0c 05 0f 84 ?? ?? 00 00 81 7d 0c 95 05 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOA_2147696259_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOA"
        threat_id = "2147696259"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0f 4e 33 c1}  //weight: 1, accuracy: High
        $x_1_2 = {ac 8b 0f 3a c8 75 07 40 47 48 75 f4}  //weight: 1, accuracy: High
        $x_1_3 = {8b 48 3c 81 e1 ff ff 00 00 41 83 c0 77 03 c1 8b 00 5e 8b fe 03 f0 59 8b 04 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANB_2147696309_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANB"
        threat_id = "2147696309"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 ba 4d 5a 66 ad 66 33 d0 74 08 81 ee ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {0f c8 03 c2 5a ab 83 e9 07 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZD_2147696380_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZD"
        threat_id = "2147696380"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 27 d9 05 ?? ?? ?? ?? 33 c9 d9 1d ?? ?? ?? ?? 8d 81 ?? ?? ?? ?? 8a 10 80 f2 ?? 80 ea ?? 41 88 10 81 f9 00 2c 00 00 72 e7 07 00 80 3d ?? ?? ?? ?? 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 4d 5a 00 00 dc 05 ?? ?? ?? ?? dc 0d ?? ?? ?? ?? dc 2d ?? ?? ?? ?? d9 1d ?? ?? ?? ?? 66 39 08 75 ?? 53 8b 58 3c 03 d8 81 3b 50 45 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZE_2147696424_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZE"
        threat_id = "2147696424"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 1b 33 c9 8d 81 ?? ?? ?? ?? 8a 10 80 f2 ?? 80 ea ?? 41 88 10 81 f9 00 2c 00 00 72 07 00 80 3d ?? ?? ?? ?? 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 4d 5a 00 00 dc 25 ?? ?? ?? ?? d9 1d ?? ?? ?? ?? 66 39 08 75 dd 53 8b 58 3c 03 d8 81 3b 50 45 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANJ_2147696462_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANJ"
        threat_id = "2147696462"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 74 6c 44 c7 45 ?? 65 63 6f 6d c7 45 ?? 70 72 65 73 c7 45 ?? 73 42 75 66 66 c7 45 ?? 66 65 c6 45 ?? 72 c6 45 ?? 00 c7 45 ?? 6e 74 64 6c c7 45 ?? 6c 2e 64 6c c6 45 ?? 6c c6 45 ?? 00 60 e8 00 00 00 00 58 66 b8 00 00 66 bb 4d 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANK_2147696480_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANK"
        threat_id = "2147696480"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 03 48 20 51 e8 ?? ?? 00 00 eb 08 6a 00 ff 95 ?? ?? ff ff eb 08 6a 00 ff 95 ?? ?? ff ff 8b 95 ?? ?? ff ff 83 7a 08 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {75 08 6a 00 ff 95 ?? ?? ff ff 83 bd ?? ?? ff ff 05 75 09 83 bd ?? ?? ff ff 00 74 17 83 bd ?? ?? ff ff 05 75 09 83 bd ?? ?? ff ff 01 74 05}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 08 83 f9 4b 0f 85 ?? ?? 00 00 8b 55 dc 0f b6 42 01 83 f8 45 0f 85 ?? ?? 00 00 8b 4d dc 0f b6 51 02 83 fa 52 0f 85 ?? ?? 00 00 8b 45 dc 0f b6 48 03 83 f9 4e 0f 85}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 55 08 8b 42 04 ff d0 89 45 f8 8b 4d f4 8b 55 f8 89 11 8b 45 f4 83 c0 04 89 45 f4 eb 9b}  //weight: 1, accuracy: High
        $x_1_5 = {e8 00 00 00 00 58 2d ?? ?? 00 00 c3 64 a1 30 00 00 00 c7 80 2c 02 00 00 00 00 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_6 = {2b 2f 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 00 4b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 53 68 65 6c 6c 33 32 2e 64 6c 6c 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ANM_2147696642_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANM"
        threat_id = "2147696642"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 3a 85 ?? ?? ?? ?? 75 ?? ?? ?? ?? ?? ?? 8a 00 3a 85 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 03 8b 95 ?? ?? ?? ?? 0f af d6 2b c2 88 85 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANM_2147696642_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANM"
        threat_id = "2147696642"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 48 75 f6 8b 45 fc 81 c4 ?? ?? ff ff 53 56 57 8d bd ?? ?? ff ff eb}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8a 03 8b 95 d4 b1 ff ff 8d 14 92 0f af d6 2b c2 88 85 da b1 ff ff eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANM_2147696642_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANM"
        threat_id = "2147696642"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 3a 07 75 ?? ?? ?? ?? ?? ?? 8a 00 3a 47 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 09 8a 07 3a c8 75 c0 3a 47 01 74 bb 8b 4d fc 03 ce 8a 09 3a 4f 01 75 af}  //weight: 1, accuracy: High
        $x_1_3 = {8a 03 8b 95 ?? ?? ?? ?? 0f af d6 2b c2 88 85 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ANM_2147696642_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANM"
        threat_id = "2147696642"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 48 75 f6 8b 45 fc 81 c4 ?? ?? ff ff 53 56 57 8d bd ?? ?? ff ff eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 12 3a 17 75 ?? 8b 55 fc 03 d6 8a 12 3a 57 01 75 ?? 8b 55 fc 03 d6 42 8a 12 3a 57 02 75}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 8a 03 2b c6 88 85 ?? ?? ff ff eb}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c0 8a 03 8b 95 ?? ?? ff ff 8d 14 92 0f af d6 2b c2 88 85 ?? ?? ff ff eb 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ANR_2147696837_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANR"
        threat_id = "2147696837"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 78 64 00 02 00 00 75 0f 8b 04 24 c7 04 24 00 00 00 00 ff 74 24 04 50 33 c0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {74 12 ad 50 2d ?? ?? ?? ?? 0f c8 03 c2 5a ab 83 e9 03 e2 ?? 61 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZF_2147696849_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZF"
        threat_id = "2147696849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 46 d9 05 ?? ?? ?? 10 33 c9 dc 0d ?? ?? ?? 10 dc 05 ?? ?? ?? 10 dc 25 ?? ?? ?? 10 dc 25 ?? ?? ?? 10 d9 1d ?? ?? ?? 10 8d 81 ?? ?? ?? 10 8a 10 80 f2 ?? 80 ea ?? 41 88 10 81 f9 00 2c 00 00 72 e7 07 00 80 3d ?? ?? ?? 10 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 4d 5a 00 00 d9 1d ?? ?? ?? 10 d9 05 ?? ?? ?? 10 d9 1d ?? ?? ?? 10 66 39 08 75 da 53 8b 58 3c 03 d8 81 3b 50 45 00 00 74 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANS_2147696858_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANS"
        threat_id = "2147696858"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 83 c3 01 4e 46 64 8f 03 83 c6 01 83 ee 01 83 c6 01 83 ee 01 4e 46}  //weight: 1, accuracy: High
        $x_1_2 = {4b 83 c3 01 4b 83 c3 01 4b 83 c3 01 4b 83 c3 01 4e 46 4b 83 c3 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANU_2147696970_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANU"
        threat_id = "2147696970"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 01 2b 03 33 03 35 ff ff ff ff 89 55 c0 8b 15 ?? ?? ?? 10 d1 e2 89 15 ?? ?? ?? 10 8b 55 c0 03 05 ?? ?? ?? 10 89 45 bc 8b 45 bc 89 85 54 ff ff ff ff b5 54 ff ff ff 8f 02 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {47 43 99 7d 81 3d ?? ?? ?? 10 ee ab ed fe 75 05 e9 d0 f8 ff ff 06 00 81 05 ?? ?? ?? 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZG_2147696973_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZG"
        threat_id = "2147696973"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 04 28 de 73 75}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 04 be 35 84 36}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 04 d1 8a 31 46}  //weight: 1, accuracy: High
        $x_1_4 = {c7 44 24 04 61 d1 d4 9e}  //weight: 1, accuracy: High
        $x_1_5 = {c7 44 24 04 a6 b8 bf 9a}  //weight: 1, accuracy: High
        $x_10_6 = {c1 c8 19 0f be c9 31 c8 83 c2 01 0f b6 0a 84 c9 75 ee}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_BZH_2147696976_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZH"
        threat_id = "2147696976"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 98 7f ff 79 68 ?? ?? ?? 00 e8 ?? ?? ff ff 59 59 68 98 7f ff 79 68 ?? ?? ?? 00 e8 ?? ?? ff ff 59 59}  //weight: 1, accuracy: Low
        $x_1_2 = {68 f0 3a 49 5f 68 ?? ?? ?? 00 e8 ?? ?? ff ff 59 59 68 f0 3a 49 5f 68 ?? ?? ?? 00 e8 ?? ?? ff ff 59 59}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 0c 25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 50 8b 45 08 03 45 fc 0f b6 00 50 e8 ?? fe ff ff 59 59 8b 4d 08 03 4d fc 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ANV_2147697002_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANV"
        threat_id = "2147697002"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 d3 80 fa ?? 88 94 34 ?? ?? 00 00 73 09 fe ca 88 94 34 ?? ?? 00 00 46}  //weight: 1, accuracy: Low
        $x_1_2 = {df e0 f6 c4 41 75 16 68 ?? ?? ?? ?? 6a 00 8d 94 24 ?? ?? 00 00 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANV_2147697002_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANV"
        threat_id = "2147697002"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 88 00 a0 02 10 80 f1 ?? 80 e9 ?? 88 88 00 a0 02 10 40 3d 00 2c 00 00 72 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 4d 5a 00 00 d9 1d ?? ?? ?? 10 66 39 45 00 74 17 81 3d ?? ?? ?? 10 00 36 00 00 75 07 c6 05 ?? ?? ?? 10 4a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANW_2147697077_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANW"
        threat_id = "2147697077"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 db 89 d2 90 90 90 90 [0-16] e8 ?? ?? ?? ff [0-255] 5d c3 00 [0-7] ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (30|2d|39|41|2d|5a|61|2d|7a) (30|2d|39|41|2d|5a|61|2d|7a) [0-432] 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 45 f4 81 7d f4 ?? ?? ?? (01|2d|ff) 75 (d8|2d|f0) 20 00 [0-32] 90 90 [0-24] ff 45 f4 81 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANX_2147697148_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANX"
        threat_id = "2147697148"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00 0f be c0 0f b7 c0 89 04 24 89 f1 e8 ?? ?? ?? ?? 83 ec 04 8a 07 47 84 c0 75 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ANY_2147697166_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANY"
        threat_id = "2147697166"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 00 2c 00 00 72 e7}  //weight: 1, accuracy: High
        $x_1_2 = {81 fa 00 2c 00 00 72 e0}  //weight: 1, accuracy: High
        $x_2_3 = {7e 11 ff 75 10 ff 75 0c 68 05 0d 00 00 ff d0 5d c2 0c 00 5d ff e0}  //weight: 2, accuracy: High
        $x_1_4 = {8b 4d fc 47 83 45 08 02 83 c1 04 89 4d fc 3b 7e 18 72 da}  //weight: 1, accuracy: High
        $x_1_5 = {74 11 8b 7e 20 8b 5e 24 03 f9 03 d9 89 55 08 3b c2 77 0a}  //weight: 1, accuracy: High
        $x_1_6 = {6a 6e 59 0f 44 c1 ff 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 85 c9 75 0b}  //weight: 1, accuracy: Low
        $x_1_7 = {6a 58 5a 0f 44 c2 a2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ANZ_2147697168_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ANZ"
        threat_id = "2147697168"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ec 5d e8 fb ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 fd 00 fd (72|0f)}  //weight: 1, accuracy: Low
        $x_1_3 = {66 81 fd 00 fe 0f 82 ?? ?? ?? ?? 8b ?? 81 ?? 00 08 00 00 76 08 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOE_2147697201_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOE"
        threat_id = "2147697201"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 8b d8 56 53 51 8b 0f 8b 06 46 33 c8 8b c1 aa 59 4b 74 07 49 75 ee 5b 5e 5b c3 5b 2b f3 53 eb f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOC_2147697203_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOC"
        threat_id = "2147697203"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 31 32 cb 85 d2 8b 55 fc 74 05 88 0c 32 eb 06}  //weight: 1, accuracy: High
        $x_1_2 = {8a 0c 11 32 cb 85 ff 74 08 8b 75 fc 88 0c 16 eb 06 8b 4d fc 88 14 11}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 70 01 00 6a 08 52 ff d3}  //weight: 1, accuracy: High
        $x_3_4 = "\\Lot\\provides\\temporary\\URI\\miti.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AOF_2147697206_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOF"
        threat_id = "2147697206"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 50 8b 45 08 03 45 fc 0f b6 00 50 e8 ?? ?? ff ff 59 59 8b 4d 08 03 4d fc 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOG_2147697207_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOG"
        threat_id = "2147697207"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 0f ?? ?? ?? ?? 30 14 38 90 90 90 90}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 88 5c 24 ?? c6 44 24 ?? 72 c6 44 24 ?? 6e 88 5c 24 ?? c6 44 24 ?? 6c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 6c c6 44 24 ?? 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOH_2147697220_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOH"
        threat_id = "2147697220"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 fd 00 fd 89 ec 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 fd 00 fe 89 ec 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOH_2147697220_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOH"
        threat_id = "2147697220"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f9 79 0c dd 05 ?? ?? ?? ?? dd 05 ?? ?? ?? ?? d9 c1 d8 e1 d8 c1 d8 c1 d8 c1 d8 e1 d8 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOD_2147697226_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOD"
        threat_id = "2147697226"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 d1 80 fa f2 88 94 35 ?? ?? ff ff 77 ?? fe ca 88 94 35 ?? ?? ff ff 46}  //weight: 1, accuracy: Low
        $x_1_2 = {df e0 f6 c4 41 75 ?? 68 ?? ?? ?? ?? 6a 00 8d 8d ?? ?? ff ff ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOI_2147697268_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOI"
        threat_id = "2147697268"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 10 0f be 14 10 33 ca 07 00 99 f7 bd}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 0f 8b 85 ?? ?? ff ff 83 c0 01 89 85 00 ff ff 81 bd 00 ff ff ?? ?? ?? ?? 7d 11 8b 8d 00 ff ff 83 c1 01 89 8d 00 ff ff eb d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOJ_2147697277_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOJ"
        threat_id = "2147697277"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 b2 32 85 f6 74 0d 30 14 38 8d 0c 38 40 fe c2 3b c6 72 f3 81 fb ff ff 01 00 74 0b 43 81 fb 00 00 00 01 7c da eb 15 33 c9 b2 33 85 f6 74 0d 30 14 39 8d 04 39 41 fe c2 3b ce 72 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOK_2147697278_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOK"
        threat_id = "2147697278"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 74 24 08 83 fe 08 7e ?? ff 15 ?? ?? ?? ?? 6a 2c ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c1 8a 4c 24 10 03 c6 8a 10 32 d1 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOP_2147697289_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOP"
        threat_id = "2147697289"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 08 83 e9 53 8b 55 e8 03 55 a4 88 0a eb d9 c7 45 fc ee ff 00 00 ff 75 ec 8b 45 e8 89 45 cc ff 55 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOP_2147697289_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOP"
        threat_id = "2147697289"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fb 8b cf 66 0f ef c0 8d b6 00 00 00 00 8d bf 00 00 00 00 b8 67 66 66 66 f7 e9 8b d9 c1 fb 1f c1 fa 02 2b d3 8d 04 92 03 c0 f7 d8 03 c1 0f b6 1c 30 b8 67 66 66 66 f7 ef 41 30 9c 3c}  //weight: 1, accuracy: High
        $x_1_2 = {ff d0 6a 40 68 00 30 00 00 [0-24] ff 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AON_2147697412_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AON"
        threat_id = "2147697412"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 00 6a 30 66 c7 40 02 5e 64 66 c7 40 04 ad 8b 66 c7 40 06 40 10 66 c7 40 08 8b 70 66 c7 40 0a 3c 0f 66 c7 40 0c b7 48 66 c7 40 0e 38 8b 66 c7 40 10 7c 24 66 c7 40 12 04 89 66 c7 40 14 4f fc 66 c7 40 16 fc f3 66 c7 40 18 a4 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOR_2147697718_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOR"
        threat_id = "2147697718"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 85 ?? ?? ff ff 81 bd ?? ?? ?? ?? ?? ?? ?? ?? 7d 1c 8b 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 8a 04 95 ?? ?? ?? ?? 88 84 0d ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {df e0 f6 c4 41 75 ?? 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOT_2147697783_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOT"
        threat_id = "2147697783"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 4d f8 81 c1 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
        $x_1_2 = {03 55 f8 81 ea ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 03 45 f8}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 45 f8 05 ?? ?? ?? ?? a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? 0f b6 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AOT_2147697783_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOT"
        threat_id = "2147697783"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 d2 74 01 46 49 75 f8 [0-20] 8b 1d ?? ?? (40|2d|47) 00 50 52 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {85 f6 74 01 42 49 75 f8 f8 [0-20] 8b 1d ?? ?? (40|2d|47) 00 50 56 ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = {7e 07 03 f1 41 3b ca 7c f9 [0-48] 81 e2 ff 01 00 00 03 c2 [0-48] ff 15 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_APA_2147705495_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APA"
        threat_id = "2147705495"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d2 ab e2 (a0|2d|c0) 61 c9 c2 10 00 55 89 e5 56 51 57}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 5b [0-64] (70|2d|7f) 06 (70|2d|7f) 04 [0-64] (70|2d|7f) 06 (70|2d|7f) 04 [0-127] 64 a1 30 00 00 00 [0-255] 8b 83 ?? ?? 00 00 50 ff 93 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_APB_2147705526_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APB"
        threat_id = "2147705526"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 65 d4 ff 75 d8 ff 75 e8 68 01 00 00 00 68 00 00 00 00 ff 75 f4 ff 75 f8 ff 15 ?? ?? ?? ?? [0-7] 39 65 d4 74 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {68 5a 00 00 00 68 41 00 00 00 e8 ?? ?? ?? ?? 68 01 01 00 80}  //weight: 1, accuracy: Low
        $x_1_3 = {68 39 00 00 00 68 30 00 00 00 e8 ?? ?? ?? ?? 68 01 01 00 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APC_2147705592_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APC"
        threat_id = "2147705592"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {dd 45 f8 dc 05 ?? ?? ?? ?? dd 5d f8 dd 45 f8 dc 05 00 dd 5d f8 dd 45 f8 dc 25 00 dd 5d f8 dd 45 f8 dc 25 00 dd 5d f8 [0-64] df e0 f6 c4 41 75 [0-32] 68 04 01 00 00 50 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {d8 c1 d8 c1 d8 e1 d8 e1 [0-32] df e0 9e 76 [0-48] 68 04 01 00 00 50 [0-32] 68 00 00 00 80}  //weight: 1, accuracy: Low
        $x_1_3 = {7d 11 ff 55 ?? ff 55 00 8b 4d fc 83 c1 01 89 4d fc 80 00 [0-64] c6 45 e0 ?? c6 45 e1 ?? c6 45 e2 ?? c6 45 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_BZI_2147705722_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZI"
        threat_id = "2147705722"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 4d 5a 00 00 c6 05 ?? ?? ?? ?? ?? 66 39 45 00 75 ea 53 8b 5d 3c 03 dd 81 3b 50 45 00 00 74 05}  //weight: 1, accuracy: Low
        $x_2_2 = {d8 e2 80 f1 ?? 80 e9 ?? 88 88 ?? ?? ?? 10 d8 e1 40 d9 1d ?? ?? ?? 10 3d 00 2c 00 00 72 d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOS_2147705746_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOS"
        threat_id = "2147705746"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 53 50 8b d8 51 8b 0f 8b 06 33 c1 aa 46 59 4b 74 07 49 75 f0 58 5b 5e c3 5b 2b f3 53 eb f3}  //weight: 1, accuracy: High
        $x_1_2 = {87 f7 ac 8b c8 87 f7 ac 49 48 3b c8 75 09 40 75 ef 5d 5f 5e c2 08 00 8b c2 eb f6}  //weight: 1, accuracy: High
        $x_1_3 = {66 ad 66 2b c2 74 04 2b f1 eb f5 0f b7 4e 3a 4e 8b c6 48 89 45 fc 8d 44 01 18 b9 09 01 00 00 57 41 41 66 39 08 0f 85 a1 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 f8 ff 45 f8 47 47 40 47 47 8b 4d f4 3b c1 72 c3 8b 45 f8 3b 45 f4 73 24 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AOV_2147705758_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOV"
        threat_id = "2147705758"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ec 5d eb fe}  //weight: 1, accuracy: High
        $x_1_2 = "dyncui.dll" ascii //weight: 1
        $x_1_3 = "najuikla.pdb" ascii //weight: 1
        $x_1_4 = {8b 09 81 e9 10 08 00 00 0f 86 ?? ?? ?? ?? e9 ?? ?? ?? ?? c6 05}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 3f 81 ef 10 08 00 00 0f 86 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AOX_2147705789_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOX"
        threat_id = "2147705789"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 02 33 c8 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 0a}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 [0-16] 6a 00 6a 00 6a 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AOY_2147705795_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AOY"
        threat_id = "2147705795"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 38 32 0c 13 32 ca 40 83}  //weight: 1, accuracy: High
        $x_1_2 = {8a 0a 88 0c 03 8b 4d fc 8b 54 8d ac 42 89 54 8d ac 41 83 f9 08}  //weight: 1, accuracy: High
        $x_1_3 = {8a 11 88 14 03 8b 4d f8 8b 54 8d ac 42 89 54 8d ac 41 83 f9 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_APF_2147705828_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APF"
        threat_id = "2147705828"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APM_2147705849_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APM"
        threat_id = "2147705849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b cf 83 c1 (74|2d|76) [0-24] 6a 14 [0-4] 8b 04 30 03 c7 8b f8 (58|2d|59)}  //weight: 5, accuracy: Low
        $x_1_2 = {8b c6 46 41 8b 00 fe c0 3c 01 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APM_2147705849_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APM"
        threat_id = "2147705849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 16 8d 45 9c [0-24] eb d9 8b ?? 9c ff 02 02 01 65 9c e2 c7 45 c8 00 00 00 00 8b 4d fc 51 e8 ?? ?? ff ff 5f 5e 5b 8b e5 5d c2 04 00 55 8b ec a1 ?? ?? 40 00 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APM_2147705849_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APM"
        threat_id = "2147705849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b cf 83 c1 77 [0-24] 03 f8 8b 46 14}  //weight: 5, accuracy: Low
        $x_1_2 = {f3 33 c2 5a 47 [0-24] e2 (18|2d|38) [0-64] ad 4e 4e 4e 75}  //weight: 1, accuracy: Low
        $x_1_3 = {54 5f 41 89 07 51 58 [0-16] 8b 06 03 f2 89 07 03 fa e2 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_APM_2147705849_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APM"
        threat_id = "2147705849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b cf 41 83 c1 76 [0-24] 03 f8 8b 46 14}  //weight: 5, accuracy: Low
        $x_5_2 = {8b cf 41 83 c1 (74|2d|76) [0-24] 6a 14 8b 04 31 03 c7 8b f8 58 8b 04 30}  //weight: 5, accuracy: Low
        $x_1_3 = {41 8b 06 fe c0 46 fe c8 75 f6}  //weight: 1, accuracy: High
        $x_1_4 = {8b c8 41 8b 06 46 3c 00 75 f8 49 89 4d ?? 8b c1 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_APM_2147705849_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APM"
        threat_id = "2147705849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 46 3c 4f 23 c7 40 8b ce 83 c1 77 03 c1 8b 00 5e 8b fe 03 f0 59 8b 04 31 03 f8 8b 46 14}  //weight: 1, accuracy: High
        $x_1_2 = {57 8b 47 3c 4a 23 c2 40 8b cf 83 c1 77 03 c1 8b 00 5e 8b fe 03 f0 59 8b 04 31 03 f8 8b 46 14}  //weight: 1, accuracy: High
        $x_1_3 = {47 8b 47 3b 4a 4f 23 c2 [0-24] 83 c1 77 03 c1 8b 00 5e 8b fe 03 f0 59 [0-32] 8b 04 31 03 f8 8b 46 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_APN_2147705920_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APN"
        threat_id = "2147705920"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 09 b9 dd ff ff ff 2b cf d3 fe 88 03 8b 45 14 33 ff 43 48 89 45 14 75 b9}  //weight: 1, accuracy: High
        $x_1_2 = {88 04 0a 8b cb 23 cf 8b d6 d3 ff 8b cb 8b c3 d3 fa 0b c6 2b d8 8b 45 0c 8b ca 8b d6 d3 ff 8a 4d 17 88 08}  //weight: 1, accuracy: High
        $x_1_3 = {d3 fa 8b ca d3 f8 a3 ?? ?? ?? ?? e8 ?? ?? ?? ff e8 ?? ?? ?? ff e8 ?? ?? ?? ff e8 ?? ?? ?? ff e8 ?? ?? ?? ff e8 ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_APO_2147705998_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APO"
        threat_id = "2147705998"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 45 08 0f be 4d 0c 33 c1 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 02 88 45 fb 8b 4d 08 03 4d}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 10 8b 65 08 8b 6d 0c ff e0 8b e5 5d c2 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APR_2147706040_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APR"
        threat_id = "2147706040"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 83 c4 0b 44 89 c6}  //weight: 1, accuracy: High
        $x_1_2 = {68 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "ht32." ascii //weight: 1
        $x_1_4 = {6a 40 68 00 30 00 00 56 57 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APT_2147706071_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APT"
        threat_id = "2147706071"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 74 64 6c 6c 2e 64 6c 6c 20 00 00 15 00 00 00 5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {6c 0c 00 43 74 ff 4b 4a 00 6c 74 ff f4 01 f4 ff fe 5d 20 00 f4 01 f4 01 0b 00 00 04 00 e7 04 74 ff f5 00 00 00 00 fc 76 f4 01 fd 3d 6c 74 ff f5 00 00 00 00 fb 3d 1c 3f 00 ff 2f 10 00 02 00 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APU_2147706121_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APU"
        threat_id = "2147706121"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 9d 28 ff ff ff 8b 1b 53 5e 31 fe 83 c7 01 81 fe 66 b8 00 00 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {8b b5 34 ff ff ff 89 f7 8b 85 44 ff ff ff bb 04 00 00 00 f6 f3 89 c1 8b 9d 54 ff ff ff ad 31 d8 ab e2 fa ff a5 34 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APX_2147706130_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APX"
        threat_id = "2147706130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 3f 2b d2 81 c2 ?? ?? ?? ?? 2b d2 81 c2 00 [0-16] 89 7d fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APX_2147706130_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APX"
        threat_id = "2147706130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 5c 0a 05 83 c1 06 88 58 05 83 c0 06 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = {84 c9 74 0c fe c1 88 08 8a 48 01 40 84 c9 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APX_2147706130_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APX"
        threat_id = "2147706130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {8d 54 24 0c 52 6a 40 [0-24] 51 c7 44 24 1c 40 00 00 00 ff d0}  //weight: 9, accuracy: Low
        $x_1_2 = {2b f6 81 c6 ?? ?? 00 00 81 ef 00 00 00 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APX_2147706130_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APX"
        threat_id = "2147706130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 8b 45 ec 03 45 f0 89 45 ec [0-255] 68 ?? 34 00 00 e8 ?? ?? ?? ff [0-3] 8b (75|7d) ec [0-8] 81 (c0|2d|c7) ?? ?? ?? ?? (56|57) [0-3] 07 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APZ_2147706135_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APZ"
        threat_id = "2147706135"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 10 8b c9 8b 65 08 8b c9 8b 6d 0c ff e1 8b e5 5d c2 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQC_2147706168_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQC"
        threat_id = "2147706168"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 d0 8b 45 d0 2d ?? ?? ?? ?? 89 45 ec 8b 45 d0 2d ?? ?? ?? ?? 89 45 e0 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 55 e8 8b 45 0c 81 ea ?? ?? ?? ?? 8b 55 d0 81 c2 ?? ?? ?? ?? 23 c2 74 12 00 55 8b ec 83 ec 3c 8b 15 ?? ?? ?? ?? 81 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQB_2147706174_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQB"
        threat_id = "2147706174"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 7e 1b 00 00 33 c8 69 c9 d9 14 00 00 81 f1 54 0a 34 07 89 4d fc a0 ?? ?? ?? ?? 0f b6 c0 99 6a 03 59 f7 f9 0f b6 c8 a0 ?? ?? ?? ?? 0f b6 c0 33 c1 8b 4d fc 8a 89 ?? ?? ?? ?? 0f b6 c9 99 f7 f9 c9 c2 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0d 70 c1 40 00 b8 24 77 00 00 33 d2 f7 f1 8b 0d ?? ?? ?? ?? 8d 84 01 15 7a 00 00 c2 18 00 66 a1 ?? ?? ?? ?? b9 bd 29 00 00 66 2b c8 69 c9 17 77 00 00 66 8b c1 c2 14 00 8a 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? d3 e8 8b 0d ?? ?? ?? ?? 2b c1 c1 e8 1b c2 1c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQD_2147706175_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQD"
        threat_id = "2147706175"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f8 7b 00 00 00 8b 45 f8 35 28 1e 00 00 89 45 f8 8b 4d 10 81 c1 f6 06 00 00 89 4d f8 eb 27 c7 45 fc 14 00 00 00 0f be 55 14 81 f2 27 1a 00 00 89 55 fc 81 7d 10 8b 00 00 00 7d 0a 0f be 45 14 23 45 fc 89 45 fc 8b 0d ?? ?? ?? ?? 81 c1 2c 01 00 00 89 0d ?? ?? ?? ?? 0f b6 55 14 52 6a 05 e8 a5 0a 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {66 89 4d f8 83 7d 14 78 7e 0e 0f bf 55 f8 81 f2 1c 3a 00 00 66 89 55 f8 81 7d 14 ec 00 00 00 7c 0d 0f bf 45 f8 25 27 69 00 00 66 89 45 f8 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQE_2147706186_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQE"
        threat_id = "2147706186"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 65 64 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {69 6e 67 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {52 65 66 6c 65 63 74 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00 (41|2d|5a) [0-48] (41|2d|5a) [0-48] 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQF_2147706190_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQF"
        threat_id = "2147706190"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 40 8b 8d 48 fd ff ff 83 c1 52 89 8d 5c fd ff ff 8b 95 f4 fd ff ff 52 8b 85 38 fe ff ff 50 8b 8d 58 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {74 1c 8b 8d 3c ff ff ff 8b 95 20 fe ff ff 8d 84 0a 95 00 00 00 66 89 85 e4 fe ff ff eb 40}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 44 24 ef 3c ff 75 02 eb}  //weight: 1, accuracy: High
        $x_1_4 = {8b 8d ec fe ff ff 8d 54 01 3e 66 89 95 dc fe ff ff 8b 45 f0 50 6a 40 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_APG_2147706271_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APG"
        threat_id = "2147706271"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 24 ?? 3c ?? 75 02 eb 1c 00 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APH_2147706283_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APH"
        threat_id = "2147706283"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f8 ff 15 ?? ?? ?? ?? 03 c7 31 45 ?? 8d 45 01 50 68 ?? ?? ?? ?? 68 04 00 00 80 ff 15 ?? ?? ?? ?? 83 f8 06 0f 85}  //weight: 1, accuracy: Low
        $x_2_2 = {0f 31 89 55 f4 89 45 f0 ff 15 ?? ?? ?? ?? 0f 31 89 55 fc 89 45 f8 8b 45 f8 2b 45 f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_API_2147706290_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.API"
        threat_id = "2147706290"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c7 04 83 e9 04 83 f9 00 31}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c7 04 83 e9 04 8b 02 83 c2 04 89 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_API_2147706290_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.API"
        threat_id = "2147706290"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 83 c4 f0 b8 3b 00 00 00 [0-16] 93 e8 ?? ?? ff ff e8 ?? ?? ff ff a3 ?? ?? ?? ?? e8 ?? ?? ff ff ff 15 ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 f8 57 74 05 e8}  //weight: 1, accuracy: Low
        $x_2_3 = {e8 00 00 00 00 5b 89 de 81 eb ?? ?? ?? ?? 83 ee 05 8d 93 ?? ?? ?? ?? b9 ae 00 00 00 80 32 ?? 42 e2 fa}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_APJ_2147706364_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APJ"
        threat_id = "2147706364"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 00 00 00 31 13 81 3b c3 (c3|90 90) 74 ?? 83 f8 00 75 ?? 31 13 29 c3 [0-1] 31 c0 [0-1] 31 c9 ff 05 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {31 13 ff 33 [0-3] 8f 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? [0-1] 31 13 83 eb 08 3d ac 04 00 00 73 08 83 c0 04 83 c3 04 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZL_2147706508_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZL"
        threat_id = "2147706508"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c2 5a 47 5a 88 27 46 4a 8b c2 85 c0 75 07 8b 55 14 8b 75 10 4e e2}  //weight: 1, accuracy: High
        $x_1_2 = {8d 78 18 b9 0a 00 00 00 f3 8b 06 52 8b 17 52 85 c9 75 2e a5}  //weight: 1, accuracy: High
        $x_1_3 = {5f 5e 8b 06 50 57 ff d1}  //weight: 1, accuracy: High
        $x_1_4 = {89 07 58 47 48 47 47 47 (ab|6a) 5a 8b 06 (03 f2 89 07|89 07 03 fa) 49 75 f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_BZM_2147706515_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZM"
        threat_id = "2147706515"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 8b d5 66 81 fa 01 ff 76 f2}  //weight: 1, accuracy: High
        $x_1_2 = {3d 00 00 09 00 0f 87 ?? 00 00 00 ba ?? ?? ?? ?? 3b c2 0f 87 ?? 00 00 00 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_APP_2147706556_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.APP"
        threat_id = "2147706556"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 30 8d 01 00 52 f4 80 2d ?? ?? ?? ?? 36 5a 83 25 ?? ?? ?? ?? ?? 83 ea 01 75 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZN_2147706687_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZN"
        threat_id = "2147706687"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 00 2f 2f 2f 2f 05 04 00 00 00 c7 00 2f 2f 2f 2f 05 04 00 00 00 c7 00 77 73 65 63 05 04 00 00 00 c7 00 65 64 69 74}  //weight: 1, accuracy: High
        $x_1_2 = {8a 06 5e 59 4a 04 f9 8a d9 fe cb d1 cb 81 e3 00 00 00 a0 d1 c3 32 c3 34 f6 88 44 0e ff 83 e9 01 83 f9 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZN_2147706687_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZN"
        threat_id = "2147706687"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 00 2f 73 79 73 05 04 00 00 00 c7 00 75 65 6d 34 81 28 01 00 00 01 05 04 00 00 00 c7 00 32 2f 77 73 05 04 00 00 00 c7 00 65 63 65 64}  //weight: 1, accuracy: High
        $x_1_2 = {8a 0e 5e 58 4b c0 c1 02 80 c1 f9 8a d0 fe ca 80 e2 01 32 ca 80 f1 03 88 4c 06 ff 2d 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZN_2147706687_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZN"
        threat_id = "2147706687"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 83 c4 04 50 56 03 f0 4e 8a 0e 5e 58 4b c0 c1 02 80 c1 f9 8a d0 fe ca 80 e2 01 32 ca 80 f1 03 81 e1 ff 00 00 00 80 64 06 ff 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 b5 7f b3 7e b1 61 e9 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 00 09 00 0f 87 2f 00 00 00 ba 00 50 02 00 3b c2 0f}  //weight: 1, accuracy: High
        $x_1_4 = {81 c6 f4 da ff ff ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_BZO_2147706690_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZO"
        threat_id = "2147706690"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 0b 8b 45 08 03 45 0c 8a 4d 10 88 08 8b e5}  //weight: 1, accuracy: High
        $x_1_2 = {eb df 8b 4d 9c ff e1}  //weight: 1, accuracy: High
        $x_1_3 = {76 30 51 c7 45 90 00 00 00 00 eb 09 8b 4d 90 83 c1 01}  //weight: 1, accuracy: Low
        $x_1_4 = {75 45 6a 01 6a 00 ff 15 ?? ?? ?? ?? 85 c0 75 13 8d 55 e0 52 a1 ?? ?? ?? ?? 50 8b 4d f8 51 e8 ?? ?? ?? ?? 8a 55 e0 52 a1 ?? ?? ?? ?? 50 8b 4d fc 51 e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 c2 01 89 15 ?? ?? ?? ?? eb b2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AQI_2147706703_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQI"
        threat_id = "2147706703"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 fc 0f be 08 8b 55 10 03 55 f8 0f be 02 33 c1 8b 4d 10 03 4d f8 88 01}  //weight: 1, accuracy: High
        $x_1_2 = {da e9 df e0 f6 c4 44 32 00 d9 05 ?? ?? ?? 00 dc 0d ?? ?? ?? 00 d9 05 ?? ?? ?? 00 dc 0d ?? ?? ?? 00 d8 0d ?? ?? ?? 00 dc 0d ?? ?? ?? 00 dc 0d ?? ?? ?? 00 de c1 dd 05 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQJ_2147706755_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQJ"
        threat_id = "2147706755"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 ec ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? ?? c6 85}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc 00 00 00 00 81 7d fc 40 42 0f 00 7d 17 ff 95 ?? ff ff ff ff 95 ?? ff ff ff 8b 4d fc 83 c1 01 89 4d fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZP_2147706783_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZP"
        threat_id = "2147706783"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c1 0b 04 04 f6 e9 8a d3 02 d2 02 c2 30 04 3b a1}  //weight: 1, accuracy: High
        $x_1_2 = {b8 00 f4 12 00 e9 e6 11 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZP_2147706783_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZP"
        threat_id = "2147706783"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 00 eb 02 03 fe eb 02 2b f9 68 ?? ?? ?? ?? c3 33 d5 c1 e8 00 8b c0 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f8 33 0a 8b 45 f8 89 08 5f 5e 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZQ_2147706822_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZQ"
        threat_id = "2147706822"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 84 24 b4 00 00 00 8a 04 30 8b 4c 24 24 88 04 31 46 3b 74 24 3c 7c d1 39}  //weight: 1, accuracy: High
        $x_1_2 = {75 03 8a 4d e8 88 0f 8b cb 0f af 4d f8 33 ff 47 2b f9 0f af f8 56}  //weight: 1, accuracy: High
        $x_1_3 = {75 0e 8b 45 f8 0f af c7 8d 0c 1b 2b c1 89 45 ec ff 45 f4 8b 45 f4 3b 45 0c 7c 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQK_2147706829_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQK"
        threat_id = "2147706829"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 54 5f 41 ab 51 58 6a 05 48 ab 5a 4a 8b 06 03 f2 89 07 03 fa e2 f6 06 00 41 8d 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQL_2147706994_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQL"
        threat_id = "2147706994"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {14 8a 04 02 30 01 41}  //weight: 2, accuracy: Low
        $x_1_2 = {51 89 d2 59 49 75 f9}  //weight: 1, accuracy: High
        $x_1_3 = {52 5a 89 c9 48 75 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_BZS_2147707070_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZS"
        threat_id = "2147707070"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 55 f4 8b 4d 08 2a d0 8b 45 fc 2a d0 02 d3 8b 5d 10 03 ce 02 d3 30 11 3b de 8b}  //weight: 1, accuracy: High
        $x_1_2 = {7c 0a 8b fa 2b fe 8d 7c 1f 02 eb 07 8b f9}  //weight: 1, accuracy: High
        $x_1_3 = {ff d0 8b 45 c4 8b 8d ac 27 00 00 83 c4 0c ff}  //weight: 1, accuracy: High
        $x_1_4 = {75 0b 03 de 53 ff b5 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_AQN_2147707073_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQN"
        threat_id = "2147707073"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 1d 58 54 41 00 74 52 b8 e9 a2 8b 2e f7 6d c0 c1 fa 02 8b c2 c1 e8 1f 03 c2 33 c9 3b c3 7e 10 8b 55 e8 3b d3 0f 84 ad 01 00 00 41 3b c8 7c f3}  //weight: 1, accuracy: High
        $x_1_2 = {83 7d ec 00 c7 45 f0 00 00 00 00 0f 8e 47 01 00 00 8b 45 f0 8b 4d c8 8a 14 01 a1 44 54 41 00 8b 75 08 50 56 88 55 17 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a c3 32 45 17 85 ff 74 0b 8b 4d c8 8b 55 f0 88 04 11 eb 09 8b 45 c8 8b 4d f0 88 04 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQO_2147707082_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQO"
        threat_id = "2147707082"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 10 8b 94 24 28 02 00 00 8a 04 11 8b f5 8d 5d 03 0f af f7 0f af df 03 de 32 c3 85 ff 74 05 88 04 11 eb 03 88 14 11}  //weight: 1, accuracy: High
        $x_1_2 = {8b c3 99 2b c2 d1 f8 8b ce 2b cf 0f af c8 8b 44 24 10 8d 55 04 0f af ca 03 ce 0f af cb 03 cf 40 03 e9 3b 84 24 2c 02 00 00 89 44 24 10 7c 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQP_2147707085_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQP"
        threat_id = "2147707085"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 0f af c7 99 8d 5e 02 f7 fb 8d 0c 37 8b d8 8b 45 f4 0f af c1 8b 4d 08 c1 e0 02 2b d8 8b 45 f8 8d 14 08 8a 02 32 c3 85 f6 74 04 88 02 eb 02}  //weight: 1, accuracy: High
        $x_1_2 = {33 c9 41 2b cf 2b ce 8d 04 37 0f af c8 8b c3 0f af c7 03 c8 0f af cb 8b c6 c1 e0 02 03 c8 0f af 4d f4 03 f9 ff 45 f8 8b 45 f8 3b 45 0c 0f 8c 20 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQQ_2147707086_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQQ"
        threat_id = "2147707086"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 f6 51 56 a9 f4 ee 21 37 5e 59 53 81 f5 00 00 00 00 5b b9 ?? ?? ?? 00 a9 0a b3 50 46 7e 02 22 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQQ_2147707086_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQQ"
        threat_id = "2147707086"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 08 a1 98 0e 42 00 8b f3 0f af f7 88 54 24 0b 99 8d 4e 02 f7 f9 03 05 9c 0e 42 00 3b 05 b0 0e 42 00 7e 06 ff 0d 9c 0e 42 00 83 c3 03 0f af df 03 de 8a c3 32 44 24 0b 8d 54 24 20 88 44 24 18}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 0c 88 04 10 8b c3 99 2b c2 d1 f8 8b ce 2b cf 0f af c8 8b 44 24 14 8d 50 04 0f af ca 03 ce 0f af cb 03 cf 03 c1 89 44 24 14 8b 44 24 0c 40 3b 45 0c 89 44 24 0c 0f 8c 3f ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQR_2147707087_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQR"
        threat_id = "2147707087"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 83 c6 04 8b 5d ee 31 d8 89 07 83 c7 04 49 85 c9 75 ec 8b 45 e2 66 b8 00 00 66 bb 4d 5a 66 39 18 74 07 2d 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 06 83 c6 04 8b 5d ee 31 d8 89 07 83 c7 04 49 85 c9 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQS_2147707088_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQS"
        threat_id = "2147707088"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {51 c3 c3 55 89 e5 83 ec 28 c7 45 ec 00 00 00 00 b9 ?? ?? 1d 02}  //weight: 2, accuracy: Low
        $x_1_2 = {55 89 e5 c9 c2 10 00 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01}  //weight: 1, accuracy: High
        $x_1_3 = {55 89 e5 c9 c2 10 00 c3 c3 c3 c3 c3 c3 c3 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_AQS_2147707088_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQS"
        threat_id = "2147707088"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3d 00 b0 02 10 4d 74 47 66 0f 6f 0d e0 01 02 10 33 c0 f3 0f 6f 80 00 b0 02 10 66 0f ef c1 f3 0f 7f 80 00 b0 02 10 f3 0f 6f 80 00 b0 02 10 66 0f f8 c1 f3 0f 7f 80 00 b0 02 10 83 c0 10 3d 00 2c 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 3d 0c dc 02 10 c5 19 00 00 0f 44 c2 a2 bc ed 02 10 8b 16 8b c2 c1 e8 1e 83 e0 01 8d 0c 48 8b c2 c1 e8 1f 8d 04 48 8b 7c 85 dc f7 c2 00 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQT_2147707131_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQT"
        threat_id = "2147707131"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 f8 8b 45 f8 83 c0 01 89 45 f4 8b 4d f8 8a 11 88 55 f3 83 45 f8 01 80 7d f3 00}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 f7 75 ec 8b 0d ?? ?? ?? ?? 0f be 14 11 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQT_2147707131_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQT"
        threat_id = "2147707131"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 3c 08 0f af fe 8d 0c 12 8b df 2b d9 0f af da 03 d8 8a c3 32 85 cf e9 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8a 85 1c ea ff ff 8b 8d 0c ea ff ff 8b 95 04 ea ff ff 88 04 11 eb 0f 8b 85 0c ea ff ff 8b 8d 04 ea ff ff 88 04 08}  //weight: 1, accuracy: High
        $x_1_3 = {8b 85 18 ea ff ff 8d 34 02 0f af b5 d4 e9 ff ff 0f af f7 0f af f0 8b 85 04 ea ff ff 8d 0c 9b 03 f1 43 0f af de 40 3b 85 c0 e9 ff ff 89 9d f4 e9 ff ff 89 85 04 ea ff ff 0f 8c 17 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZU_2147707352_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZU"
        threat_id = "2147707352"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 94 50 8b 4d f8 51 e8 ?? 00 00 00 88 45 e0 8b 55 fc 03 15 ?? ?? ?? ?? 8a 45 e0 88 02 8a 4d e0}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 09 8b 45 8c 83 c0 01 89 45 8c 8b 4d 8c 3b 4d fc 73 38 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d fc 83 e9 01 39 4d 8c 75 0d 53 ff 75 fc 6a 00 ff 15 ?? ?? ?? ?? c3 eb b7}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 08 88 4d fc 8b 55 fc 81 e2 ff 00 00 00 33 c0 a0 70 45 41 00 33 d0 88 55 fc 8a 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_BZV_2147707353_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZV"
        threat_id = "2147707353"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 c2 50 ff 55 de 8d 45 ca 50 ff 55 de 8b 45 c2 8b 5d ca 39 d8 74 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 06 83 c6 04 8b 5d f2 31 d8 89 07 83 c7 04 [0-10] ff 65 ba}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 10 00 00 ff 75 d6 6a 00 ff 95 00 ff ff ff 89 85 fc fe ff ff 8b 4d d6 8b 75 da 8b bd fc fe ff ff f3 a4 6a 40 68 00 10 00 00 ff 75 d6 6a 00 ff 95 00 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_BZW_2147707359_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZW"
        threat_id = "2147707359"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 8a 45 10 88 45 fc 8b 4d 08 03 4d 0c 8a 55 fc 88 11 8b e5}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 b0 25 ff 00 00 00 8b 4d c8 8d 54 08 7b 88 55 b0 8b 85 68 ff ff ff 83 c0 01 89 85 68 ff ff ff 83 bd 68 ff ff ff 04 75 0a}  //weight: 1, accuracy: High
        $x_1_3 = {75 09 8b 45 94 83 e8 01 89 45 94 8d 4d 94 51 ff 15 ?? ?? ?? ?? 8b 55 fc 52 8d 45 94 50 ff 15 ?? ?? ?? ?? eb ae ff d3}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 09 8b 45 90 83 c0 01 89 45 90 8b 4d fc 03 4d fc 39 4d 90 73 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Obfuscator_BZX_2147707360_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZX"
        threat_id = "2147707360"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 1c ff ff ff 56 c6 85 1d ff ff ff 69 c6 85 1e ff ff ff 72 c6 85 1f ff ff ff 74 c6 85 20 ff ff ff 75 c6 85 21 ff ff ff 61 c6 85 22 ff ff ff 6c c6 85 23 ff ff ff 41 c6 85 24 ff ff ff 6c c6 85 25 ff ff ff 6c c6 85 26 ff ff ff 6f c6 85 27 ff ff ff 63}  //weight: 1, accuracy: High
        $x_1_2 = {ff 55 fc 89 85 c4 fe ff ff 8d 8d 2c ff ff ff 51 8b 55 f8 52 ff 55 fc 89 85 94 fe ff ff 8d 45 9c 50 8b 4d f8 51 ff 55 fc 89 85 c4 fe ff ff 8d 95 48 ff ff ff 52 8b 45 f8 50 ff 55 fc}  //weight: 1, accuracy: High
        $x_1_3 = {58 ff d0 6a 00 ff 95 7c fe ff ff 8b e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_BZY_2147707377_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.BZY"
        threat_id = "2147707377"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 34 24 57 44 12 ac 58 05 ?? ?? ?? ?? 8b 00 48 36 ff d0 b8 ?? ?? ?? ?? d1 e0 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQV_2147707522_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQV"
        threat_id = "2147707522"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 f4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? [0-56] ff 75 f0 c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? [0-96] 6a 00 c7 05 00 ?? ?? ?? ?? c7 05 00 ff 01 ff 75 (f8|2d|fc) c7 05 00 ?? ?? ?? ?? c3 c7 05 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 f4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? [0-56] ff 75 f0 c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? c7 05 00 ?? ?? ?? ?? [0-96] 6a 00 c7 05 00 ?? ?? ?? ?? c7 05 00 [0-255] ff 75 (f8|2d|fc) c3 89 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AQW_2147707670_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQW!Upatre"
        threat_id = "2147707670"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "Upatre: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 2f 00 00 00 ff 04 24 ff 04 24 58 05 0b 00 00 00 ff 34 07 58 03 c7 6a 1e 5e 83 ee 02}  //weight: 1, accuracy: High
        $x_1_2 = {8a 16 5e 58 49 fe ca 8a d8 fe cb 50 8b c3 25 01 00 00 00 32 d0 b8 0d 00 00 00 32 d0}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 83 ec 04 c7 04 24 00 00 00 80 81 c7 7d 2b 00 00 83 ec 04 89 3c 24 33 db 81 c3 ?? ?? ?? ?? be ?? ?? ?? ?? ff 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_AQX_2147707715_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQX"
        threat_id = "2147707715"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 ?? 40 89 45 ?? 8b 45 ?? 3b 45 ?? 73 18 8b 45 ?? 03 45 ?? 0f b6 00 05 ?? 00 00 00 8b 4d ?? 03 4d ?? 88 01 eb d9 [0-24] ff 75 ?? 83 7d ?? 00 76 03 ff 55 07 33 c0 8b 8d ?? ?? ff ff e8}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 09 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 3b 55 ?? 73 1a 8b 45 ?? 03 45 ?? 33 c9 8a 08 81 c1 ?? 00 00 00 8b 55 ?? 03 55 ?? 88 0a eb d5 ff 75 ?? 53 53 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d fc ff 55 fc eb [0-32] c7 45 ?? 00 00 00 00 eb 09 8b 4d ?? 83 c1 01 89 4d ?? 83 7d ?? ?? 7d [0-24] 8a 15 ?? ?? ?? ?? 80 ea 01 88 15 ?? ?? ?? ?? eb (d8|2d|e8)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_AQZ_2147707747_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQZ"
        threat_id = "2147707747"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 34 66 66 (67|2d|7a) 33 35 33 30 30 30 [0-4] 30 [0-4] 30 [0-4] 30 [0-4] 30 [0-4] 35 [0-4] 38 [0-4] 38 [0-4] 62 [0-4] 34 [0-4] 30 [0-4] 30 [0-4] 63 [0-4] 38 [0-4] 62 [0-4] 34 [0-4] 38 [0-4] 30 [0-4] 63 [0-4] 38 [0-4] 62 [0-4] 31 [0-4] 31 [0-4] 38 [0-4] 62 [0-4] 34 [0-4] 31 [0-4] 33 [0-4] 30 [0-4] 36 [0-4] 61 [0-4] 30 [0-4] 32 [0-4] 38 [0-4] 62 [0-4] 37 [0-4] 64 [0-4] 30 [0-4] 38 [0-4] 35 [0-4] 37 [0-4] 35 [0-4] 30 [0-4] 65 [0-4] 38}  //weight: 1, accuracy: Low
        $x_1_2 = {65 38 30 64 30 32 [0-8] 30 [0-2] 30 [0-2] 33 [0-2] 33 [0-2] 63 [0-2] 30 [0-2] 63 [0-2] 33 [0-2] 38 [0-2] 62 [0-2] 35 [0-2] 34 [0-2] 32 [0-2] 34 [0-2] 30 [0-2] 63 [0-2] 38 [0-2] 62 [0-2] 34 [0-2] 63 [0-2] 32 [0-2] 34 [0-2] 30 [0-2] 34 [0-2] 38 [0-2] 62 [0-2] 63 [0-2] 32 [0-2] 34 [0-2] 61 [0-2] 35 [0-2] 37 [0-2] 38 [0-2] 62 [0-2] 66 [0-2] 39 [0-2] 38 [0-2] 35 [0-2] 63 [0-2] 30 [0-2] 37 [0-2] 34 [0-2] 31 [0-2] 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ARA_2147707792_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ARA"
        threat_id = "2147707792"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 ff 30 58 31 d8 83 eb ff 3d}  //weight: 1, accuracy: High
        $x_1_2 = {66 b8 00 00 66 bb 4d 5a 66 39 18 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ARB_2147707896_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ARB"
        threat_id = "2147707896"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 6a 02 0f bf f0 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 98 3b 45 ?? 74 ?? 3b f1 76 ?? 85 c9 74}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 31 0c c3 30 f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 c2 3b c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AQY_2147708137_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AQY"
        threat_id = "2147708137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ca 89 8d ?? ?? ff ff 1a 00 0f be 8d ?? ?? ?? ?? 33 8d ?? ?? ?? ?? 0f be 95}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d0 33 c0 5f 5e 5b 8b 4d f8}  //weight: 1, accuracy: High
        $x_1_3 = {df e0 f6 c4 41 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ARF_2147708157_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ARF"
        threat_id = "2147708157"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 31 89 55 f4 89 45 f0 ff 15 ?? ?? ?? ?? 0f 31 89 55 fc 89 45 f8 8b 45 f8 2b 45 f0 c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ARG_2147708287_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ARG"
        threat_id = "2147708287"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 3a 5c 62 43 49 6e 58 55 63 6f 69 45 48 5c 65 4f 62 76 41 6d 64 54 69 50 77 73 5c 62 68 79 34 37 78 00 64 44 42 58 7a 47 79 73 74 73 00 5a 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CAE_2147708886_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAE"
        threat_id = "2147708886"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 db 4b 75 fb}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f 6e d2 31 d2 66 0f 7e d2}  //weight: 1, accuracy: High
        $x_1_3 = {89 d2 90 89 f6 90 89 c9 90 4b 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_CAF_2147708985_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAF!bit"
        threat_id = "2147708985"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb d5 ff 75 c4 ff 55 fc 26 00 83 ?? 01 89 ?? dc 8b ?? dc 3b ?? bc 73 1a 8b ?? e4 03 ?? dc 33 ?? 8a ?? 81 ?? ?? 00 00 00 8b ?? fc 03 ?? dc 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CAG_2147709040_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAG"
        threat_id = "2147709040"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 40 02 89 45 ?? c7 45 ?? 00 00 00 00 8b 45 ?? 3b 45 ?? 73 (30|2d|50) 8b 45 ?? 8b 4d ?? 0f b6 04 01 [0-16] 8b 55 ?? 89 45 ?? 89 d0 31 d2 f7 35 ?? ?? ?? ?? 01 d1 0f b6 0c 0d ?? ?? ?? ?? 8b 55 ?? 29 ca 88 d3 8b 4d ?? 8b 55 ?? 88 1c 0a 8b 45 ?? 83 c0 01 89 45 ?? eb (a0|2d|c0)}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 49 02 89 4d [0-16] c7 45 ?? 00 00 00 00 89 45 ?? 8b 45 ?? 3b 45 ?? 73 (30|2d|50) 8b 45 ?? 8b 4d ?? 0f b6 04 01 [0-16] 8b 55 ?? 89 45 ?? 89 d0 31 d2 f7 35 ?? ?? ?? ?? 01 d1 0f b6 0c 0d ?? ?? ?? ?? 8b 55 ?? 29 ca 88 d3 8b 4d ?? 8b 55 ?? 88 1c 0a 8b 45 ?? 83 c0 01 89 45 ?? eb (a0|2d|c0)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_CAH_2147709209_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAH"
        threat_id = "2147709209"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 85 cc fe ff ff 83 bd cc fe ff ff 06 75 24 dd 05 ?? ?? 41 00 e8 ?? ?? 00 00 d9 9d c4 fe ff ff d9 85 c4 fe ff ff dc 1d ?? ?? 41 00 df e0 f6 c4 41 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-6] ff b5 cc fe ff ff e8 ?? ?? ff ff 83 c4 10 89 45 f0 e9 ?? ff ff ff ff 75 ec ff 15 ?? ?? 41 00 59 6a 00 ff 15 ?? ?? 41 00 83 f8 65 75 20 e8 ?? ?? ff ff 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {57 0f 31 8b ff 89 55 f4 8b ff 89 45 f0 8b ff ff 15 ?? ?? ?? 00 0f 31 8b ff 89 55 fc 8b ff 89 45 f8 8b ff 8b 45 f8 2b 45 f0 8b 4d fc 1b 4d f4 5f c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZAC_2147709237_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZAC!bit"
        threat_id = "2147709237"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e8 00 00 00 00 5b 89 de 81 eb ?? ?? ?? ?? 83 ee 05 8d 93 ?? ?? ?? ?? b9 ?? 00 00 00 bb ?? 00 00 00 30 1a 42 e2 fb}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 05 ?? ?? ?? ?? ff 10 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ARI_2147709371_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ARI"
        threat_id = "2147709371"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a c3 02 c1 8a d1 8b 4d 10 2a d1 04 04 f6 ea 8b 55 08 f6 e9 32 04 13}  //weight: 2, accuracy: High
        $x_1_2 = {74 0c 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 6a 00 57 68 23 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CAI_2147709395_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAI!bit"
        threat_id = "2147709395"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb d8 c7 45 23 00 83 ?? 01 89 ?? ec 8b ?? ec 3b ?? cc 73 17 8b ?? f4 03 ?? ec 33 ?? 8a ?? 83 ?? 45 8b ?? fc 03 ?? ec 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ARJ_2147709397_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ARJ!bit"
        threat_id = "2147709397"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 ?? ec 8b 4d ?? 3b 4d ?? 73 ?? 8b 55 ?? 03 55 ?? 33 c0 8a 02 05 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ARJ_2147709701_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ARJ"
        threat_id = "2147709701"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 42 28 89 45 ?? 6a 00 6a 01 8b 4d ?? 51 ff 55 ?? 68 00 80 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {85 c0 75 05 e9 ?? ?? ?? ?? 8d 45 ?? 50 68 01 00 80 00 8b 4d ?? 51 68 0e 66 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ARK_2147709868_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ARK"
        threat_id = "2147709868"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 0f b6 55 ?? 33 ca 8b 45 ?? 89 45 ?? 88 08 89 45 ?? 8b 55 ?? 81 c2 ?? ?? ?? ?? 39 55 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 4d f8 81 c1 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CAI_2147710009_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAI"
        threat_id = "2147710009"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 9d 8b d8 8d 85 ?? ?? ff ff 90 50 33 db 3e ff 15 ?? ?? ?? ?? 9c 58 90 8b d8 05 ?? ?? ?? ?? 2d 46 02 00 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZAF_2147710756_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZAF!bit"
        threat_id = "2147710756"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 01 39 05 ?? ?? ?? ?? 0f 84 15 00 eb ?? 8a 15 ?? ?? ?? ?? 80 f2 ?? 88 15 ?? ?? ?? ?? 8b 45 ?? 83}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 c4 61 c6 45 c5 75 c6 45 c6 78 c6 45 c7 53 c6 45 c8 65 c6 45 c9 74 c6 45 ca 56 c6 45 cb 6f c6 45 cc 6c c6 45 cd 75 c6 45 ce 6d c6 45 cf 65 c6 45 d0 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CAJ_2147710788_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAJ"
        threat_id = "2147710788"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 54 89 1d ?? ?? ?? ?? 8f 05 ?? ?? ?? ?? 8f 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? ff e0 cc 0f 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ALX_2147711628_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALX!!ObfuscatorAlx.gen!A"
        threat_id = "2147711628"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "ObfuscatorAlx: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 db}  //weight: 1, accuracy: High
        $x_1_2 = {8b 42 08 89 45 e0 8b 4d f0 8b 51 0c 89 55 e8 ff 75 e8 ff 75 e0 ff 75 dc ff 75 e4 8b 45 fc ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {e8 00 00 00 00 58 83 c0 05 c3}  //weight: 1, accuracy: High
        $x_1_4 = {e8 05 fe ff ff 89 45 f8 8b 45 f8 8b 48 0c 89 4d f4 ff 75 0c ff 75 08 ff 55 f4 89 45 fc 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_5 = {89 51 1c 68 d8 26 fe 52}  //weight: 1, accuracy: High
        $x_1_6 = {c6 45 f6 90 c6 45 f7 8b c6 45 f8 ff c6 45 f9 55 6a 06 8d 45 f4}  //weight: 1, accuracy: High
        $x_1_7 = {b6 08 66 d1 eb 66 d1 d8 73 09 66 35 20 83 66 81 f3 b8 ed fe ce 75 eb}  //weight: 1, accuracy: High
        $x_1_8 = {ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a}  //weight: 1, accuracy: High
        $x_1_9 = {c6 45 dc 6e c6 45 dd 74 c6 45 de 64 c6 45 df 6c c6 45 e0 6c c6 45 e1 00 8d 45 dc 50 e8}  //weight: 1, accuracy: High
        $x_1_10 = {89 51 04 68 23 f9 35 9d}  //weight: 1, accuracy: High
        $x_1_11 = {89 51 44 68 d7 70 a4 37}  //weight: 1, accuracy: High
        $x_1_12 = {89 51 10 68 af b6 1a 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_ALX_2147711628_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALX!!ObfuscatorAlx.gen!A"
        threat_id = "2147711628"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "ObfuscatorAlx: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 21 01 63 64 21 73 74 6f 21 68 01 6f 21 45 4e 52 21 6c 6e 81 65 64 2f}  //weight: 1, accuracy: High
        $x_1_2 = {76 22 02 60 67 22 70 77 6c 22 6b 02 6c 22 46 4d 51 22 6f 6d 82 66 67 2c}  //weight: 1, accuracy: High
        $x_1_3 = {77 23 03 61 66 23 71 76 6d 23 6a 03 6d 23 47 4c 50 23 6e 6c 83 67 66 2d}  //weight: 1, accuracy: High
        $x_1_4 = {70 24 04 66 61 24 76 71 6a 24 6d 04 6a 24 40 4b 57 24 69 6b 84 60 61 2a}  //weight: 1, accuracy: High
        $x_1_5 = {71 25 05 67 60 25 77 70 6b 25 6c 05 6b 25 41 4a 56 25 68 6a 85 61 60 2b}  //weight: 1, accuracy: High
        $x_1_6 = {72 26 06 64 63 26 74 73 68 26 6f 06 68 26 42 49 55 26 6b 69 86 62 63 28}  //weight: 1, accuracy: High
        $x_1_7 = {73 27 07 65 62 27 75 72 69 27 6e 07 69 27 43 48 54 27 6a 68 87 63 62 29}  //weight: 1, accuracy: High
        $x_1_8 = {7c 28 08 6a 6d 28 7a 7d 66 28 61 08 66 28 4c 47 5b 28 65 67 88 6c 6d 26}  //weight: 1, accuracy: High
        $x_1_9 = {7d 29 09 6b 6c 29 7b 7c 67 29 60 09 67 29 4d 46 5a 29 64 66 89 6d 6c 27}  //weight: 1, accuracy: High
        $x_1_10 = {7e 2a 0a 68 6f 2a 78 7f 64 2a 63 0a 64 2a 4e 45 59 2a 67 65 8a 6e 6f 24}  //weight: 1, accuracy: High
        $x_1_11 = {7f 2b 0b 69 6e 2b 79 7e 65 2b 62 0b 65 2b 4f 44 58 2b 66 64 8b 6f 6e 25}  //weight: 1, accuracy: High
        $x_1_12 = {78 2c 0c 6e 69 2c 7e 79 62 2c 65 0c 62 2c 48 43 5f 2c 61 63 8c 68 69 22}  //weight: 1, accuracy: High
        $x_1_13 = {79 2d 0d 6f 68 2d 7f 78 63 2d 64 0d 63 2d 49 42 5e 2d 60 62 8d 69 68 23}  //weight: 1, accuracy: High
        $x_1_14 = {7a 2e 0e 6c 6b 2e 7c 7b 60 2e 67 0e 60 2e 4a 41 5d 2e 63 61 8e 6a 6b 20}  //weight: 1, accuracy: High
        $x_1_15 = {7b 2f 0f 6d 6a 2f 7d 7a 61 2f 66 0f 61 2f 4b 40 5c 2f 62 60 8f 6b 6a 21}  //weight: 1, accuracy: High
        $x_1_16 = {64 30 10 72 75 30 62 65 7e 30 79 10 7e 30 54 5f 43 30 7d 7f 90 74 75 3e}  //weight: 1, accuracy: High
        $x_1_17 = {65 31 11 73 74 31 63 64 7f 31 78 11 7f 31 55 5e 42 31 7c 7e 91 75 74 3f}  //weight: 1, accuracy: High
        $x_1_18 = {66 32 12 70 77 32 60 67 7c 32 7b 12 7c 32 56 5d 41 32 7f 7d 92 76 77 3c}  //weight: 1, accuracy: High
        $x_1_19 = {67 33 13 71 76 33 61 66 7d 33 7a 13 7d 33 57 5c 40 33 7e 7c 93 77 76 3d}  //weight: 1, accuracy: High
        $x_1_20 = {60 34 14 76 71 34 66 61 7a 34 7d 14 7a 34 50 5b 47 34 79 7b 94 70 71 3a}  //weight: 1, accuracy: High
        $x_1_21 = {61 35 15 77 70 35 67 60 7b 35 7c 15 7b 35 51 5a 46 35 78 7a 95 71 70 3b}  //weight: 1, accuracy: High
        $x_1_22 = {62 36 16 74 73 36 64 63 78 36 7f 16 78 36 52 59 45 36 7b 79 96 72 73 38}  //weight: 1, accuracy: High
        $x_1_23 = {63 37 17 75 72 37 65 62 79 37 7e 17 79 37 53 58 44 37 7a 78 97 73 72 39}  //weight: 1, accuracy: High
        $x_1_24 = {6c 38 18 7a 7d 38 6a 6d 76 38 71 18 76 38 5c 57 4b 38 75 77 98 7c 7d 36}  //weight: 1, accuracy: High
        $x_1_25 = {6d 39 19 7b 7c 39 6b 6c 77 39 70 19 77 39 5d 56 4a 39 74 76 99 7d 7c 37}  //weight: 1, accuracy: High
        $x_1_26 = {6e 3a 1a 78 7f 3a 68 6f 74 3a 73 1a 74 3a 5e 55 49 3a 77 75 9a 7e 7f 34}  //weight: 1, accuracy: High
        $x_1_27 = {6f 3b 1b 79 7e 3b 69 6e 75 3b 72 1b 75 3b 5f 54 48 3b 76 74 9b 7f 7e 35}  //weight: 1, accuracy: High
        $x_1_28 = {68 3c 1c 7e 79 3c 6e 69 72 3c 75 1c 72 3c 58 53 4f 3c 71 73 9c 78 79 32}  //weight: 1, accuracy: High
        $x_1_29 = {69 3d 1d 7f 78 3d 6f 68 73 3d 74 1d 73 3d 59 52 4e 3d 70 72 9d 79 78 33}  //weight: 1, accuracy: High
        $x_1_30 = {6a 3e 1e 7c 7b 3e 6c 6b 70 3e 77 1e 70 3e 5a 51 4d 3e 73 71 9e 7a 7b 30}  //weight: 1, accuracy: High
        $x_1_31 = {6b 3f 1f 7d 7a 3f 6d 6a 71 3f 76 1f 71 3f 5b 50 4c 3f 72 70 9f 7b 7a 31}  //weight: 1, accuracy: High
        $x_1_32 = {54 00 20 42 45 00 52 55 4e 00 49 20 4e 00 64 6f 73 00 4d 4f a0 44 45 0e}  //weight: 1, accuracy: High
        $x_1_33 = {55 01 21 43 44 01 53 54 4f 01 48 21 4f 01 65 6e 72 01 4c 4e a1 45 44 0f}  //weight: 1, accuracy: High
        $x_1_34 = {56 02 22 40 47 02 50 57 4c 02 4b 22 4c 02 66 6d 71 02 4f 4d a2 46 47 0c}  //weight: 1, accuracy: High
        $x_1_35 = {57 03 23 41 46 03 51 56 4d 03 4a 23 4d 03 67 6c 70 03 4e 4c a3 47 46 0d}  //weight: 1, accuracy: High
        $x_1_36 = {50 04 24 46 41 04 56 51 4a 04 4d 24 4a 04 60 6b 77 04 49 4b a4 40 41 0a}  //weight: 1, accuracy: High
        $x_1_37 = {51 05 25 47 40 05 57 50 4b 05 4c 25 4b 05 61 6a 76 05 48 4a a5 41 40 0b}  //weight: 1, accuracy: High
        $x_1_38 = {52 06 26 44 43 06 54 53 48 06 4f 26 48 06 62 69 75 06 4b 49 a6 42 43 08}  //weight: 1, accuracy: High
        $x_1_39 = {53 07 27 45 42 07 55 52 49 07 4e 27 49 07 63 68 74 07 4a 48 a7 43 42 09}  //weight: 1, accuracy: High
        $x_1_40 = {5c 08 28 4a 4d 08 5a 5d 46 08 41 28 46 08 6c 67 7b 08 45 47 a8 4c 4d 06}  //weight: 1, accuracy: High
        $x_1_41 = {5d 09 29 4b 4c 09 5b 5c 47 09 40 29 47 09 6d 66 7a 09 44 46 a9 4d 4c 07}  //weight: 1, accuracy: High
        $x_1_42 = {5e 0a 2a 48 4f 0a 58 5f 44 0a 43 2a 44 0a 6e 65 79 0a 47 45 aa 4e 4f 04}  //weight: 1, accuracy: High
        $x_1_43 = {5f 0b 2b 49 4e 0b 59 5e 45 0b 42 2b 45 0b 6f 64 78 0b 46 44 ab 4f 4e 05}  //weight: 1, accuracy: High
        $x_1_44 = {58 0c 2c 4e 49 0c 5e 59 42 0c 45 2c 42 0c 68 63 7f 0c 41 43 ac 48 49 02}  //weight: 1, accuracy: High
        $x_1_45 = {59 0d 2d 4f 48 0d 5f 58 43 0d 44 2d 43 0d 69 62 7e 0d 40 42 ad 49 48 03}  //weight: 1, accuracy: High
        $x_1_46 = {5a 0e 2e 4c 4b 0e 5c 5b 40 0e 47 2e 40 0e 6a 61 7d 0e 43 41 ae 4a 4b 00}  //weight: 1, accuracy: High
        $x_1_47 = {5b 0f 2f 4d 4a 0f 5d 5a 41 0f 46 2f 41 0f 6b 60 7c 0f 42 40 af 4b 4a 01}  //weight: 1, accuracy: High
        $x_1_48 = {44 10 30 52 55 10 42 45 5e 10 59 30 5e 10 74 7f 63 10 5d 5f b0 54 55 1e}  //weight: 1, accuracy: High
        $x_1_49 = {45 11 31 53 54 11 43 44 5f 11 58 31 5f 11 75 7e 62 11 5c 5e b1 55 54 1f}  //weight: 1, accuracy: High
        $x_1_50 = {46 12 32 50 57 12 40 47 5c 12 5b 32 5c 12 76 7d 61 12 5f 5d b2 56 57 1c}  //weight: 1, accuracy: High
        $x_1_51 = {47 13 33 51 56 13 41 46 5d 13 5a 33 5d 13 77 7c 60 13 5e 5c b3 57 56 1d}  //weight: 1, accuracy: High
        $x_1_52 = {40 14 34 56 51 14 46 41 5a 14 5d 34 5a 14 70 7b 67 14 59 5b b4 50 51 1a}  //weight: 1, accuracy: High
        $x_1_53 = {41 15 35 57 50 15 47 40 5b 15 5c 35 5b 15 71 7a 66 15 58 5a b5 51 50 1b}  //weight: 1, accuracy: High
        $x_1_54 = {42 16 36 54 53 16 44 43 58 16 5f 36 58 16 72 79 65 16 5b 59 b6 52 53 18}  //weight: 1, accuracy: High
        $x_1_55 = {43 17 37 55 52 17 45 42 59 17 5e 37 59 17 73 78 64 17 5a 58 b7 53 52 19}  //weight: 1, accuracy: High
        $x_1_56 = {4c 18 38 5a 5d 18 4a 4d 56 18 51 38 56 18 7c 77 6b 18 55 57 b8 5c 5d 16}  //weight: 1, accuracy: High
        $x_1_57 = {4d 19 39 5b 5c 19 4b 4c 57 19 50 39 57 19 7d 76 6a 19 54 56 b9 5d 5c 17}  //weight: 1, accuracy: High
        $x_1_58 = {4e 1a 3a 58 5f 1a 48 4f 54 1a 53 3a 54 1a 7e 75 69 1a 57 55 ba 5e 5f 14}  //weight: 1, accuracy: High
        $x_1_59 = {4f 1b 3b 59 5e 1b 49 4e 55 1b 52 3b 55 1b 7f 74 68 1b 56 54 bb 5f 5e 15}  //weight: 1, accuracy: High
        $x_1_60 = {48 1c 3c 5e 59 1c 4e 49 52 1c 55 3c 52 1c 78 73 6f 1c 51 53 bc 58 59 12}  //weight: 1, accuracy: High
        $x_1_61 = {49 1d 3d 5f 58 1d 4f 48 53 1d 54 3d 53 1d 79 72 6e 1d 50 52 bd 59 58 13}  //weight: 1, accuracy: High
        $x_1_62 = {4a 1e 3e 5c 5b 1e 4c 4b 50 1e 57 3e 50 1e 7a 71 6d 1e 53 51 be 5a 5b 10}  //weight: 1, accuracy: High
        $x_1_63 = {4b 1f 3f 5d 5a 1f 4d 4a 51 1f 56 3f 51 1f 7b 70 6c 1f 52 50 bf 5b 5a 11}  //weight: 1, accuracy: High
        $x_1_64 = {34 60 40 22 25 60 32 35 2e 60 29 40 2e 60 04 0f 13 60 2d 2f c0 24 25 6e}  //weight: 1, accuracy: High
        $x_1_65 = {35 61 41 23 24 61 33 34 2f 61 28 41 2f 61 05 0e 12 61 2c 2e c1 25 24 6f}  //weight: 1, accuracy: High
        $x_1_66 = {36 62 42 20 27 62 30 37 2c 62 2b 42 2c 62 06 0d 11 62 2f 2d c2 26 27 6c}  //weight: 1, accuracy: High
        $x_1_67 = {37 63 43 21 26 63 31 36 2d 63 2a 43 2d 63 07 0c 10 63 2e 2c c3 27 26 6d}  //weight: 1, accuracy: High
        $x_1_68 = {30 64 44 26 21 64 36 31 2a 64 2d 44 2a 64 00 0b 17 64 29 2b c4 20 21 6a}  //weight: 1, accuracy: High
        $x_1_69 = {31 65 45 27 20 65 37 30 2b 65 2c 45 2b 65 01 0a 16 65 28 2a c5 21 20 6b}  //weight: 1, accuracy: High
        $x_1_70 = {32 66 46 24 23 66 34 33 28 66 2f 46 28 66 02 09 15 66 2b 29 c6 22 23 68}  //weight: 1, accuracy: High
        $x_1_71 = {33 67 47 25 22 67 35 32 29 67 2e 47 29 67 03 08 14 67 2a 28 c7 23 22 69}  //weight: 1, accuracy: High
        $x_1_72 = {3c 68 48 2a 2d 68 3a 3d 26 68 21 48 26 68 0c 07 1b 68 25 27 c8 2c 2d 66}  //weight: 1, accuracy: High
        $x_1_73 = {3d 69 49 2b 2c 69 3b 3c 27 69 20 49 27 69 0d 06 1a 69 24 26 c9 2d 2c 67}  //weight: 1, accuracy: High
        $x_1_74 = {3e 6a 4a 28 2f 6a 38 3f 24 6a 23 4a 24 6a 0e 05 19 6a 27 25 ca 2e 2f 64}  //weight: 1, accuracy: High
        $x_1_75 = {3f 6b 4b 29 2e 6b 39 3e 25 6b 22 4b 25 6b 0f 04 18 6b 26 24 cb 2f 2e 65}  //weight: 1, accuracy: High
        $x_1_76 = {38 6c 4c 2e 29 6c 3e 39 22 6c 25 4c 22 6c 08 03 1f 6c 21 23 cc 28 29 62}  //weight: 1, accuracy: High
        $x_1_77 = {39 6d 4d 2f 28 6d 3f 38 23 6d 24 4d 23 6d 09 02 1e 6d 20 22 cd 29 28 63}  //weight: 1, accuracy: High
        $x_1_78 = {3a 6e 4e 2c 2b 6e 3c 3b 20 6e 27 4e 20 6e 0a 01 1d 6e 23 21 ce 2a 2b 60}  //weight: 1, accuracy: High
        $x_1_79 = {3b 6f 4f 2d 2a 6f 3d 3a 21 6f 26 4f 21 6f 0b 00 1c 6f 22 20 cf 2b 2a 61}  //weight: 1, accuracy: High
        $x_1_80 = {24 70 50 32 35 70 22 25 3e 70 39 50 3e 70 14 1f 03 70 3d 3f d0 34 35 7e}  //weight: 1, accuracy: High
        $x_1_81 = {25 71 51 33 34 71 23 24 3f 71 38 51 3f 71 15 1e 02 71 3c 3e d1 35 34 7f}  //weight: 1, accuracy: High
        $x_1_82 = {26 72 52 30 37 72 20 27 3c 72 3b 52 3c 72 16 1d 01 72 3f 3d d2 36 37 7c}  //weight: 1, accuracy: High
        $x_1_83 = {27 73 53 31 36 73 21 26 3d 73 3a 53 3d 73 17 1c 00 73 3e 3c d3 37 36 7d}  //weight: 1, accuracy: High
        $x_1_84 = {20 74 54 36 31 74 26 21 3a 74 3d 54 3a 74 10 1b 07 74 39 3b d4 30 31 7a}  //weight: 1, accuracy: High
        $x_1_85 = {21 75 55 37 30 75 27 20 3b 75 3c 55 3b 75 11 1a 06 75 38 3a d5 31 30 7b}  //weight: 1, accuracy: High
        $x_1_86 = {22 76 56 34 33 76 24 23 38 76 3f 56 38 76 12 19 05 76 3b 39 d6 32 33 78}  //weight: 1, accuracy: High
        $x_1_87 = {23 77 57 35 32 77 25 22 39 77 3e 57 39 77 13 18 04 77 3a 38 d7 33 32 79}  //weight: 1, accuracy: High
        $x_1_88 = {2c 78 58 3a 3d 78 2a 2d 36 78 31 58 36 78 1c 17 0b 78 35 37 d8 3c 3d 76}  //weight: 1, accuracy: High
        $x_1_89 = {2d 79 59 3b 3c 79 2b 2c 37 79 30 59 37 79 1d 16 0a 79 34 36 d9 3d 3c 77}  //weight: 1, accuracy: High
        $x_1_90 = {2e 7a 5a 38 3f 7a 28 2f 34 7a 33 5a 34 7a 1e 15 09 7a 37 35 da 3e 3f 74}  //weight: 1, accuracy: High
        $x_1_91 = {2f 7b 5b 39 3e 7b 29 2e 35 7b 32 5b 35 7b 1f 14 08 7b 36 34 db 3f 3e 75}  //weight: 1, accuracy: High
        $x_1_92 = {28 7c 5c 3e 39 7c 2e 29 32 7c 35 5c 32 7c 18 13 0f 7c 31 33 dc 38 39 72}  //weight: 1, accuracy: High
        $x_1_93 = {29 7d 5d 3f 38 7d 2f 28 33 7d 34 5d 33 7d 19 12 0e 7d 30 32 dd 39 38 73}  //weight: 1, accuracy: High
        $x_1_94 = {2a 7e 5e 3c 3b 7e 2c 2b 30 7e 37 5e 30 7e 1a 11 0d 7e 33 31 de 3a 3b 70}  //weight: 1, accuracy: High
        $x_1_95 = {2b 7f 5f 3d 3a 7f 2d 2a 31 7f 36 5f 31 7f 1b 10 0c 7f 32 30 df 3b 3a 71}  //weight: 1, accuracy: High
        $x_1_96 = {14 40 60 02 05 40 12 15 0e 40 09 60 0e 40 24 2f 33 40 0d 0f e0 04 05 4e}  //weight: 1, accuracy: High
        $x_1_97 = {15 41 61 03 04 41 13 14 0f 41 08 61 0f 41 25 2e 32 41 0c 0e e1 05 04 4f}  //weight: 1, accuracy: High
        $x_1_98 = {16 42 62 00 07 42 10 17 0c 42 0b 62 0c 42 26 2d 31 42 0f 0d e2 06 07 4c}  //weight: 1, accuracy: High
        $x_1_99 = {17 43 63 01 06 43 11 16 0d 43 0a 63 0d 43 27 2c 30 43 0e 0c e3 07 06 4d}  //weight: 1, accuracy: High
        $x_1_100 = {10 44 64 06 01 44 16 11 0a 44 0d 64 0a 44 20 2b 37 44 09 0b e4 00 01 4a}  //weight: 1, accuracy: High
        $x_1_101 = {11 45 65 07 00 45 17 10 0b 45 0c 65 0b 45 21 2a 36 45 08 0a e5 01 00 4b}  //weight: 1, accuracy: High
        $x_1_102 = {12 46 66 04 03 46 14 13 08 46 0f 66 08 46 22 29 35 46 0b 09 e6 02 03 48}  //weight: 1, accuracy: High
        $x_1_103 = {13 47 67 05 02 47 15 12 09 47 0e 67 09 47 23 28 34 47 0a 08 e7 03 02 49}  //weight: 1, accuracy: High
        $x_1_104 = {1c 48 68 0a 0d 48 1a 1d 06 48 01 68 06 48 2c 27 3b 48 05 07 e8 0c 0d 46}  //weight: 1, accuracy: High
        $x_1_105 = {1d 49 69 0b 0c 49 1b 1c 07 49 00 69 07 49 2d 26 3a 49 04 06 e9 0d 0c 47}  //weight: 1, accuracy: High
        $x_1_106 = {1e 4a 6a 08 0f 4a 18 1f 04 4a 03 6a 04 4a 2e 25 39 4a 07 05 ea 0e 0f 44}  //weight: 1, accuracy: High
        $x_1_107 = {1f 4b 6b 09 0e 4b 19 1e 05 4b 02 6b 05 4b 2f 24 38 4b 06 04 eb 0f 0e 45}  //weight: 1, accuracy: High
        $x_1_108 = {18 4c 6c 0e 09 4c 1e 19 02 4c 05 6c 02 4c 28 23 3f 4c 01 03 ec 08 09 42}  //weight: 1, accuracy: High
        $x_1_109 = {19 4d 6d 0f 08 4d 1f 18 03 4d 04 6d 03 4d 29 22 3e 4d 00 02 ed 09 08 43}  //weight: 1, accuracy: High
        $x_1_110 = {1a 4e 6e 0c 0b 4e 1c 1b 00 4e 07 6e 00 4e 2a 21 3d 4e 03 01 ee 0a 0b 40}  //weight: 1, accuracy: High
        $x_1_111 = {1b 4f 6f 0d 0a 4f 1d 1a 01 4f 06 6f 01 4f 2b 20 3c 4f 02 00 ef 0b 0a 41}  //weight: 1, accuracy: High
        $x_1_112 = {04 50 70 12 15 50 02 05 1e 50 19 70 1e 50 34 3f 23 50 1d 1f f0 14 15 5e}  //weight: 1, accuracy: High
        $x_1_113 = {05 51 71 13 14 51 03 04 1f 51 18 71 1f 51 35 3e 22 51 1c 1e f1 15 14 5f}  //weight: 1, accuracy: High
        $x_1_114 = {06 52 72 10 17 52 00 07 1c 52 1b 72 1c 52 36 3d 21 52 1f 1d f2 16 17 5c}  //weight: 1, accuracy: High
        $x_1_115 = {07 53 73 11 16 53 01 06 1d 53 1a 73 1d 53 37 3c 20 53 1e 1c f3 17 16 5d}  //weight: 1, accuracy: High
        $x_1_116 = {00 54 74 16 11 54 06 01 1a 54 1d 74 1a 54 30 3b 27 54 19 1b f4 10 11 5a}  //weight: 1, accuracy: High
        $x_1_117 = {01 55 75 17 10 55 07 00 1b 55 1c 75 1b 55 31 3a 26 55 18 1a f5 11 10 5b}  //weight: 1, accuracy: High
        $x_1_118 = {02 56 76 14 13 56 04 03 18 56 1f 76 18 56 32 39 25 56 1b 19 f6 12 13 58}  //weight: 1, accuracy: High
        $x_1_119 = {03 57 77 15 12 57 05 02 19 57 1e 77 19 57 33 38 24 57 1a 18 f7 13 12 59}  //weight: 1, accuracy: High
        $x_1_120 = {0c 58 78 1a 1d 58 0a 0d 16 58 11 78 16 58 3c 37 2b 58 15 17 f8 1c 1d 56}  //weight: 1, accuracy: High
        $x_1_121 = {0d 59 79 1b 1c 59 0b 0c 17 59 10 79 17 59 3d 36 2a 59 14 16 f9 1d 1c 57}  //weight: 1, accuracy: High
        $x_1_122 = {0e 5a 7a 18 1f 5a 08 0f 14 5a 13 7a 14 5a 3e 35 29 5a 17 15 fa 1e 1f 54}  //weight: 1, accuracy: High
        $x_1_123 = {0f 5b 7b 19 1e 5b 09 0e 15 5b 12 7b 15 5b 3f 34 28 5b 16 14 fb 1f 1e 55}  //weight: 1, accuracy: High
        $x_1_124 = {08 5c 7c 1e 19 5c 0e 09 12 5c 15 7c 12 5c 38 33 2f 5c 11 13 fc 18 19 52}  //weight: 1, accuracy: High
        $x_1_125 = {09 5d 7d 1f 18 5d 0f 08 13 5d 14 7d 13 5d 39 32 2e 5d 10 12 fd 19 18 53}  //weight: 1, accuracy: High
        $x_1_126 = {0a 5e 7e 1c 1b 5e 0c 0b 10 5e 17 7e 10 5e 3a 31 2d 5e 13 11 fe 1a 1b 50}  //weight: 1, accuracy: High
        $x_1_127 = {0b 5f 7f 1d 1a 5f 0d 0a 11 5f 16 7f 11 5f 3b 30 2c 5f 12 10 ff 1b 1a 51}  //weight: 1, accuracy: High
        $x_1_128 = {f4 a0 80 e2 e5 a0 f2 f5 ee a0 e9 80 ee a0 c4 cf d3 a0 ed ef 00 e4 e5 ae}  //weight: 1, accuracy: High
        $x_1_129 = {f5 a1 81 e3 e4 a1 f3 f4 ef a1 e8 81 ef a1 c5 ce d2 a1 ec ee 01 e5 e4 af}  //weight: 1, accuracy: High
        $x_1_130 = {f6 a2 82 e0 e7 a2 f0 f7 ec a2 eb 82 ec a2 c6 cd d1 a2 ef ed 02 e6 e7 ac}  //weight: 1, accuracy: High
        $x_1_131 = {f7 a3 83 e1 e6 a3 f1 f6 ed a3 ea 83 ed a3 c7 cc d0 a3 ee ec 03 e7 e6 ad}  //weight: 1, accuracy: High
        $x_1_132 = {f0 a4 84 e6 e1 a4 f6 f1 ea a4 ed 84 ea a4 c0 cb d7 a4 e9 eb 04 e0 e1 aa}  //weight: 1, accuracy: High
        $x_1_133 = {f1 a5 85 e7 e0 a5 f7 f0 eb a5 ec 85 eb a5 c1 ca d6 a5 e8 ea 05 e1 e0 ab}  //weight: 1, accuracy: High
        $x_1_134 = {f2 a6 86 e4 e3 a6 f4 f3 e8 a6 ef 86 e8 a6 c2 c9 d5 a6 eb e9 06 e2 e3 a8}  //weight: 1, accuracy: High
        $x_1_135 = {f3 a7 87 e5 e2 a7 f5 f2 e9 a7 ee 87 e9 a7 c3 c8 d4 a7 ea e8 07 e3 e2 a9}  //weight: 1, accuracy: High
        $x_1_136 = {fc a8 88 ea ed a8 fa fd e6 a8 e1 88 e6 a8 cc c7 db a8 e5 e7 08 ec ed a6}  //weight: 1, accuracy: High
        $x_1_137 = {fd a9 89 eb ec a9 fb fc e7 a9 e0 89 e7 a9 cd c6 da a9 e4 e6 09 ed ec a7}  //weight: 1, accuracy: High
        $x_1_138 = {fe aa 8a e8 ef aa f8 ff e4 aa e3 8a e4 aa ce c5 d9 aa e7 e5 0a ee ef a4}  //weight: 1, accuracy: High
        $x_1_139 = {ff ab 8b e9 ee ab f9 fe e5 ab e2 8b e5 ab cf c4 d8 ab e6 e4 0b ef ee a5}  //weight: 1, accuracy: High
        $x_1_140 = {f8 ac 8c ee e9 ac fe f9 e2 ac e5 8c e2 ac c8 c3 df ac e1 e3 0c e8 e9 a2}  //weight: 1, accuracy: High
        $x_1_141 = {f9 ad 8d ef e8 ad ff f8 e3 ad e4 8d e3 ad c9 c2 de ad e0 e2 0d e9 e8 a3}  //weight: 1, accuracy: High
        $x_1_142 = {fa ae 8e ec eb ae fc fb e0 ae e7 8e e0 ae ca c1 dd ae e3 e1 0e ea eb a0}  //weight: 1, accuracy: High
        $x_1_143 = {fb af 8f ed ea af fd fa e1 af e6 8f e1 af cb c0 dc af e2 e0 0f eb ea a1}  //weight: 1, accuracy: High
        $x_1_144 = {e4 b0 90 f2 f5 b0 e2 e5 fe b0 f9 90 fe b0 d4 df c3 b0 fd ff 10 f4 f5 be}  //weight: 1, accuracy: High
        $x_1_145 = {e5 b1 91 f3 f4 b1 e3 e4 ff b1 f8 91 ff b1 d5 de c2 b1 fc fe 11 f5 f4 bf}  //weight: 1, accuracy: High
        $x_1_146 = {e6 b2 92 f0 f7 b2 e0 e7 fc b2 fb 92 fc b2 d6 dd c1 b2 ff fd 12 f6 f7 bc}  //weight: 1, accuracy: High
        $x_1_147 = {e7 b3 93 f1 f6 b3 e1 e6 fd b3 fa 93 fd b3 d7 dc c0 b3 fe fc 13 f7 f6 bd}  //weight: 1, accuracy: High
        $x_1_148 = {e0 b4 94 f6 f1 b4 e6 e1 fa b4 fd 94 fa b4 d0 db c7 b4 f9 fb 14 f0 f1 ba}  //weight: 1, accuracy: High
        $x_1_149 = {e1 b5 95 f7 f0 b5 e7 e0 fb b5 fc 95 fb b5 d1 da c6 b5 f8 fa 15 f1 f0 bb}  //weight: 1, accuracy: High
        $x_1_150 = {e2 b6 96 f4 f3 b6 e4 e3 f8 b6 ff 96 f8 b6 d2 d9 c5 b6 fb f9 16 f2 f3 b8}  //weight: 1, accuracy: High
        $x_1_151 = {e3 b7 97 f5 f2 b7 e5 e2 f9 b7 fe 97 f9 b7 d3 d8 c4 b7 fa f8 17 f3 f2 b9}  //weight: 1, accuracy: High
        $x_1_152 = {ec b8 98 fa fd b8 ea ed f6 b8 f1 98 f6 b8 dc d7 cb b8 f5 f7 18 fc fd b6}  //weight: 1, accuracy: High
        $x_1_153 = {ed b9 99 fb fc b9 eb ec f7 b9 f0 99 f7 b9 dd d6 ca b9 f4 f6 19 fd fc b7}  //weight: 1, accuracy: High
        $x_1_154 = {ee ba 9a f8 ff ba e8 ef f4 ba f3 9a f4 ba de d5 c9 ba f7 f5 1a fe ff b4}  //weight: 1, accuracy: High
        $x_1_155 = {ef bb 9b f9 fe bb e9 ee f5 bb f2 9b f5 bb df d4 c8 bb f6 f4 1b ff fe b5}  //weight: 1, accuracy: High
        $x_1_156 = {e8 bc 9c fe f9 bc ee e9 f2 bc f5 9c f2 bc d8 d3 cf bc f1 f3 1c f8 f9 b2}  //weight: 1, accuracy: High
        $x_1_157 = {e9 bd 9d ff f8 bd ef e8 f3 bd f4 9d f3 bd d9 d2 ce bd f0 f2 1d f9 f8 b3}  //weight: 1, accuracy: High
        $x_1_158 = {ea be 9e fc fb be ec eb f0 be f7 9e f0 be da d1 cd be f3 f1 1e fa fb b0}  //weight: 1, accuracy: High
        $x_1_159 = {eb bf 9f fd fa bf ed ea f1 bf f6 9f f1 bf db d0 cc bf f2 f0 1f fb fa b1}  //weight: 1, accuracy: High
        $x_1_160 = {d4 80 a0 c2 c5 80 d2 d5 ce 80 c9 a0 ce 80 e4 ef f3 80 cd cf 20 c4 c5 8e}  //weight: 1, accuracy: High
        $x_1_161 = {d5 81 a1 c3 c4 81 d3 d4 cf 81 c8 a1 cf 81 e5 ee f2 81 cc ce 21 c5 c4 8f}  //weight: 1, accuracy: High
        $x_1_162 = {d6 82 a2 c0 c7 82 d0 d7 cc 82 cb a2 cc 82 e6 ed f1 82 cf cd 22 c6 c7 8c}  //weight: 1, accuracy: High
        $x_1_163 = {d7 83 a3 c1 c6 83 d1 d6 cd 83 ca a3 cd 83 e7 ec f0 83 ce cc 23 c7 c6 8d}  //weight: 1, accuracy: High
        $x_1_164 = {d0 84 a4 c6 c1 84 d6 d1 ca 84 cd a4 ca 84 e0 eb f7 84 c9 cb 24 c0 c1 8a}  //weight: 1, accuracy: High
        $x_1_165 = {d1 85 a5 c7 c0 85 d7 d0 cb 85 cc a5 cb 85 e1 ea f6 85 c8 ca 25 c1 c0 8b}  //weight: 1, accuracy: High
        $x_1_166 = {d2 86 a6 c4 c3 86 d4 d3 c8 86 cf a6 c8 86 e2 e9 f5 86 cb c9 26 c2 c3 88}  //weight: 1, accuracy: High
        $x_1_167 = {d3 87 a7 c5 c2 87 d5 d2 c9 87 ce a7 c9 87 e3 e8 f4 87 ca c8 27 c3 c2 89}  //weight: 1, accuracy: High
        $x_1_168 = {dc 88 a8 ca cd 88 da dd c6 88 c1 a8 c6 88 ec e7 fb 88 c5 c7 28 cc cd 86}  //weight: 1, accuracy: High
        $x_1_169 = {dd 89 a9 cb cc 89 db dc c7 89 c0 a9 c7 89 ed e6 fa 89 c4 c6 29 cd cc 87}  //weight: 1, accuracy: High
        $x_1_170 = {de 8a aa c8 cf 8a d8 df c4 8a c3 aa c4 8a ee e5 f9 8a c7 c5 2a ce cf 84}  //weight: 1, accuracy: High
        $x_1_171 = {df 8b ab c9 ce 8b d9 de c5 8b c2 ab c5 8b ef e4 f8 8b c6 c4 2b cf ce 85}  //weight: 1, accuracy: High
        $x_1_172 = {d8 8c ac ce c9 8c de d9 c2 8c c5 ac c2 8c e8 e3 ff 8c c1 c3 2c c8 c9 82}  //weight: 1, accuracy: High
        $x_1_173 = {d9 8d ad cf c8 8d df d8 c3 8d c4 ad c3 8d e9 e2 fe 8d c0 c2 2d c9 c8 83}  //weight: 1, accuracy: High
        $x_1_174 = {da 8e ae cc cb 8e dc db c0 8e c7 ae c0 8e ea e1 fd 8e c3 c1 2e ca cb 80}  //weight: 1, accuracy: High
        $x_1_175 = {db 8f af cd ca 8f dd da c1 8f c6 af c1 8f eb e0 fc 8f c2 c0 2f cb ca 81}  //weight: 1, accuracy: High
        $x_1_176 = {c4 90 b0 d2 d5 90 c2 c5 de 90 d9 b0 de 90 f4 ff e3 90 dd df 30 d4 d5 9e}  //weight: 1, accuracy: High
        $x_1_177 = {c5 91 b1 d3 d4 91 c3 c4 df 91 d8 b1 df 91 f5 fe e2 91 dc de 31 d5 d4 9f}  //weight: 1, accuracy: High
        $x_1_178 = {c6 92 b2 d0 d7 92 c0 c7 dc 92 db b2 dc 92 f6 fd e1 92 df dd 32 d6 d7 9c}  //weight: 1, accuracy: High
        $x_1_179 = {c7 93 b3 d1 d6 93 c1 c6 dd 93 da b3 dd 93 f7 fc e0 93 de dc 33 d7 d6 9d}  //weight: 1, accuracy: High
        $x_1_180 = {c0 94 b4 d6 d1 94 c6 c1 da 94 dd b4 da 94 f0 fb e7 94 d9 db 34 d0 d1 9a}  //weight: 1, accuracy: High
        $x_1_181 = {c1 95 b5 d7 d0 95 c7 c0 db 95 dc b5 db 95 f1 fa e6 95 d8 da 35 d1 d0 9b}  //weight: 1, accuracy: High
        $x_1_182 = {c2 96 b6 d4 d3 96 c4 c3 d8 96 df b6 d8 96 f2 f9 e5 96 db d9 36 d2 d3 98}  //weight: 1, accuracy: High
        $x_1_183 = {c3 97 b7 d5 d2 97 c5 c2 d9 97 de b7 d9 97 f3 f8 e4 97 da d8 37 d3 d2 99}  //weight: 1, accuracy: High
        $x_1_184 = {cc 98 b8 da dd 98 ca cd d6 98 d1 b8 d6 98 fc f7 eb 98 d5 d7 38 dc dd 96}  //weight: 1, accuracy: High
        $x_1_185 = {cd 99 b9 db dc 99 cb cc d7 99 d0 b9 d7 99 fd f6 ea 99 d4 d6 39 dd dc 97}  //weight: 1, accuracy: High
        $x_1_186 = {ce 9a ba d8 df 9a c8 cf d4 9a d3 ba d4 9a fe f5 e9 9a d7 d5 3a de df 94}  //weight: 1, accuracy: High
        $x_1_187 = {cf 9b bb d9 de 9b c9 ce d5 9b d2 bb d5 9b ff f4 e8 9b d6 d4 3b df de 95}  //weight: 1, accuracy: High
        $x_1_188 = {c8 9c bc de d9 9c ce c9 d2 9c d5 bc d2 9c f8 f3 ef 9c d1 d3 3c d8 d9 92}  //weight: 1, accuracy: High
        $x_1_189 = {c9 9d bd df d8 9d cf c8 d3 9d d4 bd d3 9d f9 f2 ee 9d d0 d2 3d d9 d8 93}  //weight: 1, accuracy: High
        $x_1_190 = {ca 9e be dc db 9e cc cb d0 9e d7 be d0 9e fa f1 ed 9e d3 d1 3e da db 90}  //weight: 1, accuracy: High
        $x_1_191 = {cb 9f bf dd da 9f cd ca d1 9f d6 bf d1 9f fb f0 ec 9f d2 d0 3f db da 91}  //weight: 1, accuracy: High
        $x_1_192 = {b4 e0 c0 a2 a5 e0 b2 b5 ae e0 a9 c0 ae e0 84 8f 93 e0 ad af 40 a4 a5 ee}  //weight: 1, accuracy: High
        $x_1_193 = {b5 e1 c1 a3 a4 e1 b3 b4 af e1 a8 c1 af e1 85 8e 92 e1 ac ae 41 a5 a4 ef}  //weight: 1, accuracy: High
        $x_1_194 = {b6 e2 c2 a0 a7 e2 b0 b7 ac e2 ab c2 ac e2 86 8d 91 e2 af ad 42 a6 a7 ec}  //weight: 1, accuracy: High
        $x_1_195 = {b7 e3 c3 a1 a6 e3 b1 b6 ad e3 aa c3 ad e3 87 8c 90 e3 ae ac 43 a7 a6 ed}  //weight: 1, accuracy: High
        $x_1_196 = {b0 e4 c4 a6 a1 e4 b6 b1 aa e4 ad c4 aa e4 80 8b 97 e4 a9 ab 44 a0 a1 ea}  //weight: 1, accuracy: High
        $x_1_197 = {b1 e5 c5 a7 a0 e5 b7 b0 ab e5 ac c5 ab e5 81 8a 96 e5 a8 aa 45 a1 a0 eb}  //weight: 1, accuracy: High
        $x_1_198 = {b2 e6 c6 a4 a3 e6 b4 b3 a8 e6 af c6 a8 e6 82 89 95 e6 ab a9 46 a2 a3 e8}  //weight: 1, accuracy: High
        $x_1_199 = {b3 e7 c7 a5 a2 e7 b5 b2 a9 e7 ae c7 a9 e7 83 88 94 e7 aa a8 47 a3 a2 e9}  //weight: 1, accuracy: High
        $x_1_200 = {bc e8 c8 aa ad e8 ba bd a6 e8 a1 c8 a6 e8 8c 87 9b e8 a5 a7 48 ac ad e6}  //weight: 1, accuracy: High
        $x_1_201 = {bd e9 c9 ab ac e9 bb bc a7 e9 a0 c9 a7 e9 8d 86 9a e9 a4 a6 49 ad ac e7}  //weight: 1, accuracy: High
        $x_1_202 = {be ea ca a8 af ea b8 bf a4 ea a3 ca a4 ea 8e 85 99 ea a7 a5 4a ae af e4}  //weight: 1, accuracy: High
        $x_1_203 = {bf eb cb a9 ae eb b9 be a5 eb a2 cb a5 eb 8f 84 98 eb a6 a4 4b af ae e5}  //weight: 1, accuracy: High
        $x_1_204 = {b8 ec cc ae a9 ec be b9 a2 ec a5 cc a2 ec 88 83 9f ec a1 a3 4c a8 a9 e2}  //weight: 1, accuracy: High
        $x_1_205 = {b9 ed cd af a8 ed bf b8 a3 ed a4 cd a3 ed 89 82 9e ed a0 a2 4d a9 a8 e3}  //weight: 1, accuracy: High
        $x_1_206 = {ba ee ce ac ab ee bc bb a0 ee a7 ce a0 ee 8a 81 9d ee a3 a1 4e aa ab e0}  //weight: 1, accuracy: High
        $x_1_207 = {bb ef cf ad aa ef bd ba a1 ef a6 cf a1 ef 8b 80 9c ef a2 a0 4f ab aa e1}  //weight: 1, accuracy: High
        $x_1_208 = {a4 f0 d0 b2 b5 f0 a2 a5 be f0 b9 d0 be f0 94 9f 83 f0 bd bf 50 b4 b5 fe}  //weight: 1, accuracy: High
        $x_1_209 = {a5 f1 d1 b3 b4 f1 a3 a4 bf f1 b8 d1 bf f1 95 9e 82 f1 bc be 51 b5 b4 ff}  //weight: 1, accuracy: High
        $x_1_210 = {a6 f2 d2 b0 b7 f2 a0 a7 bc f2 bb d2 bc f2 96 9d 81 f2 bf bd 52 b6 b7 fc}  //weight: 1, accuracy: High
        $x_1_211 = {a7 f3 d3 b1 b6 f3 a1 a6 bd f3 ba d3 bd f3 97 9c 80 f3 be bc 53 b7 b6 fd}  //weight: 1, accuracy: High
        $x_1_212 = {a0 f4 d4 b6 b1 f4 a6 a1 ba f4 bd d4 ba f4 90 9b 87 f4 b9 bb 54 b0 b1 fa}  //weight: 1, accuracy: High
        $x_1_213 = {a1 f5 d5 b7 b0 f5 a7 a0 bb f5 bc d5 bb f5 91 9a 86 f5 b8 ba 55 b1 b0 fb}  //weight: 1, accuracy: High
        $x_1_214 = {a2 f6 d6 b4 b3 f6 a4 a3 b8 f6 bf d6 b8 f6 92 99 85 f6 bb b9 56 b2 b3 f8}  //weight: 1, accuracy: High
        $x_1_215 = {a3 f7 d7 b5 b2 f7 a5 a2 b9 f7 be d7 b9 f7 93 98 84 f7 ba b8 57 b3 b2 f9}  //weight: 1, accuracy: High
        $x_1_216 = {ac f8 d8 ba bd f8 aa ad b6 f8 b1 d8 b6 f8 9c 97 8b f8 b5 b7 58 bc bd f6}  //weight: 1, accuracy: High
        $x_1_217 = {ad f9 d9 bb bc f9 ab ac b7 f9 b0 d9 b7 f9 9d 96 8a f9 b4 b6 59 bd bc f7}  //weight: 1, accuracy: High
        $x_1_218 = {ae fa da b8 bf fa a8 af b4 fa b3 da b4 fa 9e 95 89 fa b7 b5 5a be bf f4}  //weight: 1, accuracy: High
        $x_1_219 = {af fb db b9 be fb a9 ae b5 fb b2 db b5 fb 9f 94 88 fb b6 b4 5b bf be f5}  //weight: 1, accuracy: High
        $x_1_220 = {a8 fc dc be b9 fc ae a9 b2 fc b5 dc b2 fc 98 93 8f fc b1 b3 5c b8 b9 f2}  //weight: 1, accuracy: High
        $x_1_221 = {a9 fd dd bf b8 fd af a8 b3 fd b4 dd b3 fd 99 92 8e fd b0 b2 5d b9 b8 f3}  //weight: 1, accuracy: High
        $x_1_222 = {aa fe de bc bb fe ac ab b0 fe b7 de b0 fe 9a 91 8d fe b3 b1 5e ba bb f0}  //weight: 1, accuracy: High
        $x_1_223 = {ab ff df bd ba ff ad aa b1 ff b6 df b1 ff 9b 90 8c ff b2 b0 5f bb ba f1}  //weight: 1, accuracy: High
        $x_1_224 = {94 c0 e0 82 85 c0 92 95 8e c0 89 e0 8e c0 a4 af b3 c0 8d 8f 60 84 85 ce}  //weight: 1, accuracy: High
        $x_1_225 = {95 c1 e1 83 84 c1 93 94 8f c1 88 e1 8f c1 a5 ae b2 c1 8c 8e 61 85 84 cf}  //weight: 1, accuracy: High
        $x_1_226 = {96 c2 e2 80 87 c2 90 97 8c c2 8b e2 8c c2 a6 ad b1 c2 8f 8d 62 86 87 cc}  //weight: 1, accuracy: High
        $x_1_227 = {97 c3 e3 81 86 c3 91 96 8d c3 8a e3 8d c3 a7 ac b0 c3 8e 8c 63 87 86 cd}  //weight: 1, accuracy: High
        $x_1_228 = {90 c4 e4 86 81 c4 96 91 8a c4 8d e4 8a c4 a0 ab b7 c4 89 8b 64 80 81 ca}  //weight: 1, accuracy: High
        $x_1_229 = {91 c5 e5 87 80 c5 97 90 8b c5 8c e5 8b c5 a1 aa b6 c5 88 8a 65 81 80 cb}  //weight: 1, accuracy: High
        $x_1_230 = {92 c6 e6 84 83 c6 94 93 88 c6 8f e6 88 c6 a2 a9 b5 c6 8b 89 66 82 83 c8}  //weight: 1, accuracy: High
        $x_1_231 = {93 c7 e7 85 82 c7 95 92 89 c7 8e e7 89 c7 a3 a8 b4 c7 8a 88 67 83 82 c9}  //weight: 1, accuracy: High
        $x_1_232 = {9c c8 e8 8a 8d c8 9a 9d 86 c8 81 e8 86 c8 ac a7 bb c8 85 87 68 8c 8d c6}  //weight: 1, accuracy: High
        $x_1_233 = {9d c9 e9 8b 8c c9 9b 9c 87 c9 80 e9 87 c9 ad a6 ba c9 84 86 69 8d 8c c7}  //weight: 1, accuracy: High
        $x_1_234 = {9e ca ea 88 8f ca 98 9f 84 ca 83 ea 84 ca ae a5 b9 ca 87 85 6a 8e 8f c4}  //weight: 1, accuracy: High
        $x_1_235 = {9f cb eb 89 8e cb 99 9e 85 cb 82 eb 85 cb af a4 b8 cb 86 84 6b 8f 8e c5}  //weight: 1, accuracy: High
        $x_1_236 = {98 cc ec 8e 89 cc 9e 99 82 cc 85 ec 82 cc a8 a3 bf cc 81 83 6c 88 89 c2}  //weight: 1, accuracy: High
        $x_1_237 = {99 cd ed 8f 88 cd 9f 98 83 cd 84 ed 83 cd a9 a2 be cd 80 82 6d 89 88 c3}  //weight: 1, accuracy: High
        $x_1_238 = {9a ce ee 8c 8b ce 9c 9b 80 ce 87 ee 80 ce aa a1 bd ce 83 81 6e 8a 8b c0}  //weight: 1, accuracy: High
        $x_1_239 = {9b cf ef 8d 8a cf 9d 9a 81 cf 86 ef 81 cf ab a0 bc cf 82 80 6f 8b 8a c1}  //weight: 1, accuracy: High
        $x_1_240 = {84 d0 f0 92 95 d0 82 85 9e d0 99 f0 9e d0 b4 bf a3 d0 9d 9f 70 94 95 de}  //weight: 1, accuracy: High
        $x_1_241 = {85 d1 f1 93 94 d1 83 84 9f d1 98 f1 9f d1 b5 be a2 d1 9c 9e 71 95 94 df}  //weight: 1, accuracy: High
        $x_1_242 = {86 d2 f2 90 97 d2 80 87 9c d2 9b f2 9c d2 b6 bd a1 d2 9f 9d 72 96 97 dc}  //weight: 1, accuracy: High
        $x_1_243 = {87 d3 f3 91 96 d3 81 86 9d d3 9a f3 9d d3 b7 bc a0 d3 9e 9c 73 97 96 dd}  //weight: 1, accuracy: High
        $x_1_244 = {80 d4 f4 96 91 d4 86 81 9a d4 9d f4 9a d4 b0 bb a7 d4 99 9b 74 90 91 da}  //weight: 1, accuracy: High
        $x_1_245 = {81 d5 f5 97 90 d5 87 80 9b d5 9c f5 9b d5 b1 ba a6 d5 98 9a 75 91 90 db}  //weight: 1, accuracy: High
        $x_1_246 = {82 d6 f6 94 93 d6 84 83 98 d6 9f f6 98 d6 b2 b9 a5 d6 9b 99 76 92 93 d8}  //weight: 1, accuracy: High
        $x_1_247 = {83 d7 f7 95 92 d7 85 82 99 d7 9e f7 99 d7 b3 b8 a4 d7 9a 98 77 93 92 d9}  //weight: 1, accuracy: High
        $x_1_248 = {8c d8 f8 9a 9d d8 8a 8d 96 d8 91 f8 96 d8 bc b7 ab d8 95 97 78 9c 9d d6}  //weight: 1, accuracy: High
        $x_1_249 = {8d d9 f9 9b 9c d9 8b 8c 97 d9 90 f9 97 d9 bd b6 aa d9 94 96 79 9d 9c d7}  //weight: 1, accuracy: High
        $x_1_250 = {8e da fa 98 9f da 88 8f 94 da 93 fa 94 da be b5 a9 da 97 95 7a 9e 9f d4}  //weight: 1, accuracy: High
        $x_1_251 = {8f db fb 99 9e db 89 8e 95 db 92 fb 95 db bf b4 a8 db 96 94 7b 9f 9e d5}  //weight: 1, accuracy: High
        $x_1_252 = {88 dc fc 9e 99 dc 8e 89 92 dc 95 fc 92 dc b8 b3 af dc 91 93 7c 98 99 d2}  //weight: 1, accuracy: High
        $x_1_253 = {89 dd fd 9f 98 dd 8f 88 93 dd 94 fd 93 dd b9 b2 ae dd 90 92 7d 99 98 d3}  //weight: 1, accuracy: High
        $x_1_254 = {8a de fe 9c 9b de 8c 8b 90 de 97 fe 90 de ba b1 ad de 93 91 7e 9a 9b d0}  //weight: 1, accuracy: High
        $x_1_255 = {8b df ff 9d 9a df 8d 8a 91 df 96 ff 91 df bb b0 ac df 92 90 7f 9b 9a d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_ALX_2147711628_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ALX!!ObfuscatorAlx.gen!A"
        threat_id = "2147711628"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "ObfuscatorAlx: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 21 63 01 64 21 73 74 6f 21 68 6f 01 21 45 4e 52 21 6c 6e 65 41 64 2f}  //weight: 1, accuracy: High
        $x_1_2 = {76 22 60 02 67 22 70 77 6c 22 6b 6c 02 22 46 4d 51 22 6f 6d 66 42 67 2c}  //weight: 1, accuracy: High
        $x_1_3 = {77 23 61 03 66 23 71 76 6d 23 6a 6d 03 23 47 4c 50 23 6e 6c 67 43 66 2d}  //weight: 1, accuracy: High
        $x_1_4 = {70 24 66 04 61 24 76 71 6a 24 6d 6a 04 24 40 4b 57 24 69 6b 60 44 61 2a}  //weight: 1, accuracy: High
        $x_1_5 = {71 25 67 05 60 25 77 70 6b 25 6c 6b 05 25 41 4a 56 25 68 6a 61 45 60 2b}  //weight: 1, accuracy: High
        $x_1_6 = {72 26 64 06 63 26 74 73 68 26 6f 68 06 26 42 49 55 26 6b 69 62 46 63 28}  //weight: 1, accuracy: High
        $x_1_7 = {73 27 65 07 62 27 75 72 69 27 6e 69 07 27 43 48 54 27 6a 68 63 47 62 29}  //weight: 1, accuracy: High
        $x_1_8 = {7c 28 6a 08 6d 28 7a 7d 66 28 61 66 08 28 4c 47 5b 28 65 67 6c 48 6d 26}  //weight: 1, accuracy: High
        $x_1_9 = {7d 29 6b 09 6c 29 7b 7c 67 29 60 67 09 29 4d 46 5a 29 64 66 6d 49 6c 27}  //weight: 1, accuracy: High
        $x_1_10 = {7e 2a 68 0a 6f 2a 78 7f 64 2a 63 64 0a 2a 4e 45 59 2a 67 65 6e 4a 6f 24}  //weight: 1, accuracy: High
        $x_1_11 = {7f 2b 69 0b 6e 2b 79 7e 65 2b 62 65 0b 2b 4f 44 58 2b 66 64 6f 4b 6e 25}  //weight: 1, accuracy: High
        $x_1_12 = {78 2c 6e 0c 69 2c 7e 79 62 2c 65 62 0c 2c 48 43 5f 2c 61 63 68 4c 69 22}  //weight: 1, accuracy: High
        $x_1_13 = {79 2d 6f 0d 68 2d 7f 78 63 2d 64 63 0d 2d 49 42 5e 2d 60 62 69 4d 68 23}  //weight: 1, accuracy: High
        $x_1_14 = {7a 2e 6c 0e 6b 2e 7c 7b 60 2e 67 60 0e 2e 4a 41 5d 2e 63 61 6a 4e 6b 20}  //weight: 1, accuracy: High
        $x_1_15 = {7b 2f 6d 0f 6a 2f 7d 7a 61 2f 66 61 0f 2f 4b 40 5c 2f 62 60 6b 4f 6a 21}  //weight: 1, accuracy: High
        $x_1_16 = {64 30 72 10 75 30 62 65 7e 30 79 7e 10 30 54 5f 43 30 7d 7f 74 50 75 3e}  //weight: 1, accuracy: High
        $x_1_17 = {65 31 73 11 74 31 63 64 7f 31 78 7f 11 31 55 5e 42 31 7c 7e 75 51 74 3f}  //weight: 1, accuracy: High
        $x_1_18 = {66 32 70 12 77 32 60 67 7c 32 7b 7c 12 32 56 5d 41 32 7f 7d 76 52 77 3c}  //weight: 1, accuracy: High
        $x_1_19 = {67 33 71 13 76 33 61 66 7d 33 7a 7d 13 33 57 5c 40 33 7e 7c 77 53 76 3d}  //weight: 1, accuracy: High
        $x_1_20 = {60 34 76 14 71 34 66 61 7a 34 7d 7a 14 34 50 5b 47 34 79 7b 70 54 71 3a}  //weight: 1, accuracy: High
        $x_1_21 = {61 35 77 15 70 35 67 60 7b 35 7c 7b 15 35 51 5a 46 35 78 7a 71 55 70 3b}  //weight: 1, accuracy: High
        $x_1_22 = {62 36 74 16 73 36 64 63 78 36 7f 78 16 36 52 59 45 36 7b 79 72 56 73 38}  //weight: 1, accuracy: High
        $x_1_23 = {63 37 75 17 72 37 65 62 79 37 7e 79 17 37 53 58 44 37 7a 78 73 57 72 39}  //weight: 1, accuracy: High
        $x_1_24 = {6c 38 7a 18 7d 38 6a 6d 76 38 71 76 18 38 5c 57 4b 38 75 77 7c 58 7d 36}  //weight: 1, accuracy: High
        $x_1_25 = {6d 39 7b 19 7c 39 6b 6c 77 39 70 77 19 39 5d 56 4a 39 74 76 7d 59 7c 37}  //weight: 1, accuracy: High
        $x_1_26 = {6e 3a 78 1a 7f 3a 68 6f 74 3a 73 74 1a 3a 5e 55 49 3a 77 75 7e 5a 7f 34}  //weight: 1, accuracy: High
        $x_1_27 = {6f 3b 79 1b 7e 3b 69 6e 75 3b 72 75 1b 3b 5f 54 48 3b 76 74 7f 5b 7e 35}  //weight: 1, accuracy: High
        $x_1_28 = {68 3c 7e 1c 79 3c 6e 69 72 3c 75 72 1c 3c 58 53 4f 3c 71 73 78 5c 79 32}  //weight: 1, accuracy: High
        $x_1_29 = {69 3d 7f 1d 78 3d 6f 68 73 3d 74 73 1d 3d 59 52 4e 3d 70 72 79 5d 78 33}  //weight: 1, accuracy: High
        $x_1_30 = {6a 3e 7c 1e 7b 3e 6c 6b 70 3e 77 70 1e 3e 5a 51 4d 3e 73 71 7a 5e 7b 30}  //weight: 1, accuracy: High
        $x_1_31 = {6b 3f 7d 1f 7a 3f 6d 6a 71 3f 76 71 1f 3f 5b 50 4c 3f 72 70 7b 5f 7a 31}  //weight: 1, accuracy: High
        $x_1_32 = {54 00 42 20 45 00 52 55 4e 00 49 4e 20 00 64 6f 73 00 4d 4f 44 60 45 0e}  //weight: 1, accuracy: High
        $x_1_33 = {55 01 43 21 44 01 53 54 4f 01 48 4f 21 01 65 6e 72 01 4c 4e 45 61 44 0f}  //weight: 1, accuracy: High
        $x_1_34 = {56 02 40 22 47 02 50 57 4c 02 4b 4c 22 02 66 6d 71 02 4f 4d 46 62 47 0c}  //weight: 1, accuracy: High
        $x_1_35 = {57 03 41 23 46 03 51 56 4d 03 4a 4d 23 03 67 6c 70 03 4e 4c 47 63 46 0d}  //weight: 1, accuracy: High
        $x_1_36 = {50 04 46 24 41 04 56 51 4a 04 4d 4a 24 04 60 6b 77 04 49 4b 40 64 41 0a}  //weight: 1, accuracy: High
        $x_1_37 = {51 05 47 25 40 05 57 50 4b 05 4c 4b 25 05 61 6a 76 05 48 4a 41 65 40 0b}  //weight: 1, accuracy: High
        $x_1_38 = {52 06 44 26 43 06 54 53 48 06 4f 48 26 06 62 69 75 06 4b 49 42 66 43 08}  //weight: 1, accuracy: High
        $x_1_39 = {53 07 45 27 42 07 55 52 49 07 4e 49 27 07 63 68 74 07 4a 48 43 67 42 09}  //weight: 1, accuracy: High
        $x_1_40 = {5c 08 4a 28 4d 08 5a 5d 46 08 41 46 28 08 6c 67 7b 08 45 47 4c 68 4d 06}  //weight: 1, accuracy: High
        $x_1_41 = {5d 09 4b 29 4c 09 5b 5c 47 09 40 47 29 09 6d 66 7a 09 44 46 4d 69 4c 07}  //weight: 1, accuracy: High
        $x_1_42 = {5e 0a 48 2a 4f 0a 58 5f 44 0a 43 44 2a 0a 6e 65 79 0a 47 45 4e 6a 4f 04}  //weight: 1, accuracy: High
        $x_1_43 = {5f 0b 49 2b 4e 0b 59 5e 45 0b 42 45 2b 0b 6f 64 78 0b 46 44 4f 6b 4e 05}  //weight: 1, accuracy: High
        $x_1_44 = {58 0c 4e 2c 49 0c 5e 59 42 0c 45 42 2c 0c 68 63 7f 0c 41 43 48 6c 49 02}  //weight: 1, accuracy: High
        $x_1_45 = {59 0d 4f 2d 48 0d 5f 58 43 0d 44 43 2d 0d 69 62 7e 0d 40 42 49 6d 48 03}  //weight: 1, accuracy: High
        $x_1_46 = {5a 0e 4c 2e 4b 0e 5c 5b 40 0e 47 40 2e 0e 6a 61 7d 0e 43 41 4a 6e 4b 00}  //weight: 1, accuracy: High
        $x_1_47 = {5b 0f 4d 2f 4a 0f 5d 5a 41 0f 46 41 2f 0f 6b 60 7c 0f 42 40 4b 6f 4a 01}  //weight: 1, accuracy: High
        $x_1_48 = {44 10 52 30 55 10 42 45 5e 10 59 5e 30 10 74 7f 63 10 5d 5f 54 70 55 1e}  //weight: 1, accuracy: High
        $x_1_49 = {45 11 53 31 54 11 43 44 5f 11 58 5f 31 11 75 7e 62 11 5c 5e 55 71 54 1f}  //weight: 1, accuracy: High
        $x_1_50 = {46 12 50 32 57 12 40 47 5c 12 5b 5c 32 12 76 7d 61 12 5f 5d 56 72 57 1c}  //weight: 1, accuracy: High
        $x_1_51 = {47 13 51 33 56 13 41 46 5d 13 5a 5d 33 13 77 7c 60 13 5e 5c 57 73 56 1d}  //weight: 1, accuracy: High
        $x_1_52 = {40 14 56 34 51 14 46 41 5a 14 5d 5a 34 14 70 7b 67 14 59 5b 50 74 51 1a}  //weight: 1, accuracy: High
        $x_1_53 = {41 15 57 35 50 15 47 40 5b 15 5c 5b 35 15 71 7a 66 15 58 5a 51 75 50 1b}  //weight: 1, accuracy: High
        $x_1_54 = {42 16 54 36 53 16 44 43 58 16 5f 58 36 16 72 79 65 16 5b 59 52 76 53 18}  //weight: 1, accuracy: High
        $x_1_55 = {43 17 55 37 52 17 45 42 59 17 5e 59 37 17 73 78 64 17 5a 58 53 77 52 19}  //weight: 1, accuracy: High
        $x_1_56 = {4c 18 5a 38 5d 18 4a 4d 56 18 51 56 38 18 7c 77 6b 18 55 57 5c 78 5d 16}  //weight: 1, accuracy: High
        $x_1_57 = {4d 19 5b 39 5c 19 4b 4c 57 19 50 57 39 19 7d 76 6a 19 54 56 5d 79 5c 17}  //weight: 1, accuracy: High
        $x_1_58 = {4e 1a 58 3a 5f 1a 48 4f 54 1a 53 54 3a 1a 7e 75 69 1a 57 55 5e 7a 5f 14}  //weight: 1, accuracy: High
        $x_1_59 = {4f 1b 59 3b 5e 1b 49 4e 55 1b 52 55 3b 1b 7f 74 68 1b 56 54 5f 7b 5e 15}  //weight: 1, accuracy: High
        $x_1_60 = {48 1c 5e 3c 59 1c 4e 49 52 1c 55 52 3c 1c 78 73 6f 1c 51 53 58 7c 59 12}  //weight: 1, accuracy: High
        $x_1_61 = {49 1d 5f 3d 58 1d 4f 48 53 1d 54 53 3d 1d 79 72 6e 1d 50 52 59 7d 58 13}  //weight: 1, accuracy: High
        $x_1_62 = {4a 1e 5c 3e 5b 1e 4c 4b 50 1e 57 50 3e 1e 7a 71 6d 1e 53 51 5a 7e 5b 10}  //weight: 1, accuracy: High
        $x_1_63 = {4b 1f 5d 3f 5a 1f 4d 4a 51 1f 56 51 3f 1f 7b 70 6c 1f 52 50 5b 7f 5a 11}  //weight: 1, accuracy: High
        $x_1_64 = {34 60 22 40 25 60 32 35 2e 60 29 2e 40 60 04 0f 13 60 2d 2f 24 00 25 6e}  //weight: 1, accuracy: High
        $x_1_65 = {35 61 23 41 24 61 33 34 2f 61 28 2f 41 61 05 0e 12 61 2c 2e 25 01 24 6f}  //weight: 1, accuracy: High
        $x_1_66 = {36 62 20 42 27 62 30 37 2c 62 2b 2c 42 62 06 0d 11 62 2f 2d 26 02 27 6c}  //weight: 1, accuracy: High
        $x_1_67 = {37 63 21 43 26 63 31 36 2d 63 2a 2d 43 63 07 0c 10 63 2e 2c 27 03 26 6d}  //weight: 1, accuracy: High
        $x_1_68 = {30 64 26 44 21 64 36 31 2a 64 2d 2a 44 64 00 0b 17 64 29 2b 20 04 21 6a}  //weight: 1, accuracy: High
        $x_1_69 = {31 65 27 45 20 65 37 30 2b 65 2c 2b 45 65 01 0a 16 65 28 2a 21 05 20 6b}  //weight: 1, accuracy: High
        $x_1_70 = {32 66 24 46 23 66 34 33 28 66 2f 28 46 66 02 09 15 66 2b 29 22 06 23 68}  //weight: 1, accuracy: High
        $x_1_71 = {33 67 25 47 22 67 35 32 29 67 2e 29 47 67 03 08 14 67 2a 28 23 07 22 69}  //weight: 1, accuracy: High
        $x_1_72 = {3c 68 2a 48 2d 68 3a 3d 26 68 21 26 48 68 0c 07 1b 68 25 27 2c 08 2d 66}  //weight: 1, accuracy: High
        $x_1_73 = {3d 69 2b 49 2c 69 3b 3c 27 69 20 27 49 69 0d 06 1a 69 24 26 2d 09 2c 67}  //weight: 1, accuracy: High
        $x_1_74 = {3e 6a 28 4a 2f 6a 38 3f 24 6a 23 24 4a 6a 0e 05 19 6a 27 25 2e 0a 2f 64}  //weight: 1, accuracy: High
        $x_1_75 = {3f 6b 29 4b 2e 6b 39 3e 25 6b 22 25 4b 6b 0f 04 18 6b 26 24 2f 0b 2e 65}  //weight: 1, accuracy: High
        $x_1_76 = {38 6c 2e 4c 29 6c 3e 39 22 6c 25 22 4c 6c 08 03 1f 6c 21 23 28 0c 29 62}  //weight: 1, accuracy: High
        $x_1_77 = {39 6d 2f 4d 28 6d 3f 38 23 6d 24 23 4d 6d 09 02 1e 6d 20 22 29 0d 28 63}  //weight: 1, accuracy: High
        $x_1_78 = {3a 6e 2c 4e 2b 6e 3c 3b 20 6e 27 20 4e 6e 0a 01 1d 6e 23 21 2a 0e 2b 60}  //weight: 1, accuracy: High
        $x_1_79 = {3b 6f 2d 4f 2a 6f 3d 3a 21 6f 26 21 4f 6f 0b 00 1c 6f 22 20 2b 0f 2a 61}  //weight: 1, accuracy: High
        $x_1_80 = {24 70 32 50 35 70 22 25 3e 70 39 3e 50 70 14 1f 03 70 3d 3f 34 10 35 7e}  //weight: 1, accuracy: High
        $x_1_81 = {25 71 33 51 34 71 23 24 3f 71 38 3f 51 71 15 1e 02 71 3c 3e 35 11 34 7f}  //weight: 1, accuracy: High
        $x_1_82 = {26 72 30 52 37 72 20 27 3c 72 3b 3c 52 72 16 1d 01 72 3f 3d 36 12 37 7c}  //weight: 1, accuracy: High
        $x_1_83 = {27 73 31 53 36 73 21 26 3d 73 3a 3d 53 73 17 1c 00 73 3e 3c 37 13 36 7d}  //weight: 1, accuracy: High
        $x_1_84 = {20 74 36 54 31 74 26 21 3a 74 3d 3a 54 74 10 1b 07 74 39 3b 30 14 31 7a}  //weight: 1, accuracy: High
        $x_1_85 = {21 75 37 55 30 75 27 20 3b 75 3c 3b 55 75 11 1a 06 75 38 3a 31 15 30 7b}  //weight: 1, accuracy: High
        $x_1_86 = {22 76 34 56 33 76 24 23 38 76 3f 38 56 76 12 19 05 76 3b 39 32 16 33 78}  //weight: 1, accuracy: High
        $x_1_87 = {23 77 35 57 32 77 25 22 39 77 3e 39 57 77 13 18 04 77 3a 38 33 17 32 79}  //weight: 1, accuracy: High
        $x_1_88 = {2c 78 3a 58 3d 78 2a 2d 36 78 31 36 58 78 1c 17 0b 78 35 37 3c 18 3d 76}  //weight: 1, accuracy: High
        $x_1_89 = {2d 79 3b 59 3c 79 2b 2c 37 79 30 37 59 79 1d 16 0a 79 34 36 3d 19 3c 77}  //weight: 1, accuracy: High
        $x_1_90 = {2e 7a 38 5a 3f 7a 28 2f 34 7a 33 34 5a 7a 1e 15 09 7a 37 35 3e 1a 3f 74}  //weight: 1, accuracy: High
        $x_1_91 = {2f 7b 39 5b 3e 7b 29 2e 35 7b 32 35 5b 7b 1f 14 08 7b 36 34 3f 1b 3e 75}  //weight: 1, accuracy: High
        $x_1_92 = {28 7c 3e 5c 39 7c 2e 29 32 7c 35 32 5c 7c 18 13 0f 7c 31 33 38 1c 39 72}  //weight: 1, accuracy: High
        $x_1_93 = {29 7d 3f 5d 38 7d 2f 28 33 7d 34 33 5d 7d 19 12 0e 7d 30 32 39 1d 38 73}  //weight: 1, accuracy: High
        $x_1_94 = {2a 7e 3c 5e 3b 7e 2c 2b 30 7e 37 30 5e 7e 1a 11 0d 7e 33 31 3a 1e 3b 70}  //weight: 1, accuracy: High
        $x_1_95 = {2b 7f 3d 5f 3a 7f 2d 2a 31 7f 36 31 5f 7f 1b 10 0c 7f 32 30 3b 1f 3a 71}  //weight: 1, accuracy: High
        $x_1_96 = {14 40 02 60 05 40 12 15 0e 40 09 0e 60 40 24 2f 33 40 0d 0f 04 20 05 4e}  //weight: 1, accuracy: High
        $x_1_97 = {15 41 03 61 04 41 13 14 0f 41 08 0f 61 41 25 2e 32 41 0c 0e 05 21 04 4f}  //weight: 1, accuracy: High
        $x_1_98 = {16 42 00 62 07 42 10 17 0c 42 0b 0c 62 42 26 2d 31 42 0f 0d 06 22 07 4c}  //weight: 1, accuracy: High
        $x_1_99 = {17 43 01 63 06 43 11 16 0d 43 0a 0d 63 43 27 2c 30 43 0e 0c 07 23 06 4d}  //weight: 1, accuracy: High
        $x_1_100 = {10 44 06 64 01 44 16 11 0a 44 0d 0a 64 44 20 2b 37 44 09 0b 00 24 01 4a}  //weight: 1, accuracy: High
        $x_1_101 = {11 45 07 65 00 45 17 10 0b 45 0c 0b 65 45 21 2a 36 45 08 0a 01 25 00 4b}  //weight: 1, accuracy: High
        $x_1_102 = {12 46 04 66 03 46 14 13 08 46 0f 08 66 46 22 29 35 46 0b 09 02 26 03 48}  //weight: 1, accuracy: High
        $x_1_103 = {13 47 05 67 02 47 15 12 09 47 0e 09 67 47 23 28 34 47 0a 08 03 27 02 49}  //weight: 1, accuracy: High
        $x_1_104 = {1c 48 0a 68 0d 48 1a 1d 06 48 01 06 68 48 2c 27 3b 48 05 07 0c 28 0d 46}  //weight: 1, accuracy: High
        $x_1_105 = {1d 49 0b 69 0c 49 1b 1c 07 49 00 07 69 49 2d 26 3a 49 04 06 0d 29 0c 47}  //weight: 1, accuracy: High
        $x_1_106 = {1e 4a 08 6a 0f 4a 18 1f 04 4a 03 04 6a 4a 2e 25 39 4a 07 05 0e 2a 0f 44}  //weight: 1, accuracy: High
        $x_1_107 = {1f 4b 09 6b 0e 4b 19 1e 05 4b 02 05 6b 4b 2f 24 38 4b 06 04 0f 2b 0e 45}  //weight: 1, accuracy: High
        $x_1_108 = {18 4c 0e 6c 09 4c 1e 19 02 4c 05 02 6c 4c 28 23 3f 4c 01 03 08 2c 09 42}  //weight: 1, accuracy: High
        $x_1_109 = {19 4d 0f 6d 08 4d 1f 18 03 4d 04 03 6d 4d 29 22 3e 4d 00 02 09 2d 08 43}  //weight: 1, accuracy: High
        $x_1_110 = {1a 4e 0c 6e 0b 4e 1c 1b 00 4e 07 00 6e 4e 2a 21 3d 4e 03 01 0a 2e 0b 40}  //weight: 1, accuracy: High
        $x_1_111 = {1b 4f 0d 6f 0a 4f 1d 1a 01 4f 06 01 6f 4f 2b 20 3c 4f 02 00 0b 2f 0a 41}  //weight: 1, accuracy: High
        $x_1_112 = {04 50 12 70 15 50 02 05 1e 50 19 1e 70 50 34 3f 23 50 1d 1f 14 30 15 5e}  //weight: 1, accuracy: High
        $x_1_113 = {05 51 13 71 14 51 03 04 1f 51 18 1f 71 51 35 3e 22 51 1c 1e 15 31 14 5f}  //weight: 1, accuracy: High
        $x_1_114 = {06 52 10 72 17 52 00 07 1c 52 1b 1c 72 52 36 3d 21 52 1f 1d 16 32 17 5c}  //weight: 1, accuracy: High
        $x_1_115 = {07 53 11 73 16 53 01 06 1d 53 1a 1d 73 53 37 3c 20 53 1e 1c 17 33 16 5d}  //weight: 1, accuracy: High
        $x_1_116 = {00 54 16 74 11 54 06 01 1a 54 1d 1a 74 54 30 3b 27 54 19 1b 10 34 11 5a}  //weight: 1, accuracy: High
        $x_1_117 = {01 55 17 75 10 55 07 00 1b 55 1c 1b 75 55 31 3a 26 55 18 1a 11 35 10 5b}  //weight: 1, accuracy: High
        $x_1_118 = {02 56 14 76 13 56 04 03 18 56 1f 18 76 56 32 39 25 56 1b 19 12 36 13 58}  //weight: 1, accuracy: High
        $x_1_119 = {03 57 15 77 12 57 05 02 19 57 1e 19 77 57 33 38 24 57 1a 18 13 37 12 59}  //weight: 1, accuracy: High
        $x_1_120 = {0c 58 1a 78 1d 58 0a 0d 16 58 11 16 78 58 3c 37 2b 58 15 17 1c 38 1d 56}  //weight: 1, accuracy: High
        $x_1_121 = {0d 59 1b 79 1c 59 0b 0c 17 59 10 17 79 59 3d 36 2a 59 14 16 1d 39 1c 57}  //weight: 1, accuracy: High
        $x_1_122 = {0e 5a 18 7a 1f 5a 08 0f 14 5a 13 14 7a 5a 3e 35 29 5a 17 15 1e 3a 1f 54}  //weight: 1, accuracy: High
        $x_1_123 = {0f 5b 19 7b 1e 5b 09 0e 15 5b 12 15 7b 5b 3f 34 28 5b 16 14 1f 3b 1e 55}  //weight: 1, accuracy: High
        $x_1_124 = {08 5c 1e 7c 19 5c 0e 09 12 5c 15 12 7c 5c 38 33 2f 5c 11 13 18 3c 19 52}  //weight: 1, accuracy: High
        $x_1_125 = {09 5d 1f 7d 18 5d 0f 08 13 5d 14 13 7d 5d 39 32 2e 5d 10 12 19 3d 18 53}  //weight: 1, accuracy: High
        $x_1_126 = {0a 5e 1c 7e 1b 5e 0c 0b 10 5e 17 10 7e 5e 3a 31 2d 5e 13 11 1a 3e 1b 50}  //weight: 1, accuracy: High
        $x_1_127 = {0b 5f 1d 7f 1a 5f 0d 0a 11 5f 16 11 7f 5f 3b 30 2c 5f 12 10 1b 3f 1a 51}  //weight: 1, accuracy: High
        $x_1_128 = {f4 a0 e2 80 e5 a0 f2 f5 ee a0 e9 ee 80 a0 c4 cf d3 a0 ed ef e4 c0 e5 ae}  //weight: 1, accuracy: High
        $x_1_129 = {f5 a1 e3 81 e4 a1 f3 f4 ef a1 e8 ef 81 a1 c5 ce d2 a1 ec ee e5 c1 e4 af}  //weight: 1, accuracy: High
        $x_1_130 = {f6 a2 e0 82 e7 a2 f0 f7 ec a2 eb ec 82 a2 c6 cd d1 a2 ef ed e6 c2 e7 ac}  //weight: 1, accuracy: High
        $x_1_131 = {f7 a3 e1 83 e6 a3 f1 f6 ed a3 ea ed 83 a3 c7 cc d0 a3 ee ec e7 c3 e6 ad}  //weight: 1, accuracy: High
        $x_1_132 = {f0 a4 e6 84 e1 a4 f6 f1 ea a4 ed ea 84 a4 c0 cb d7 a4 e9 eb e0 c4 e1 aa}  //weight: 1, accuracy: High
        $x_1_133 = {f1 a5 e7 85 e0 a5 f7 f0 eb a5 ec eb 85 a5 c1 ca d6 a5 e8 ea e1 c5 e0 ab}  //weight: 1, accuracy: High
        $x_1_134 = {f2 a6 e4 86 e3 a6 f4 f3 e8 a6 ef e8 86 a6 c2 c9 d5 a6 eb e9 e2 c6 e3 a8}  //weight: 1, accuracy: High
        $x_1_135 = {f3 a7 e5 87 e2 a7 f5 f2 e9 a7 ee e9 87 a7 c3 c8 d4 a7 ea e8 e3 c7 e2 a9}  //weight: 1, accuracy: High
        $x_1_136 = {fc a8 ea 88 ed a8 fa fd e6 a8 e1 e6 88 a8 cc c7 db a8 e5 e7 ec c8 ed a6}  //weight: 1, accuracy: High
        $x_1_137 = {fd a9 eb 89 ec a9 fb fc e7 a9 e0 e7 89 a9 cd c6 da a9 e4 e6 ed c9 ec a7}  //weight: 1, accuracy: High
        $x_1_138 = {fe aa e8 8a ef aa f8 ff e4 aa e3 e4 8a aa ce c5 d9 aa e7 e5 ee ca ef a4}  //weight: 1, accuracy: High
        $x_1_139 = {ff ab e9 8b ee ab f9 fe e5 ab e2 e5 8b ab cf c4 d8 ab e6 e4 ef cb ee a5}  //weight: 1, accuracy: High
        $x_1_140 = {f8 ac ee 8c e9 ac fe f9 e2 ac e5 e2 8c ac c8 c3 df ac e1 e3 e8 cc e9 a2}  //weight: 1, accuracy: High
        $x_1_141 = {f9 ad ef 8d e8 ad ff f8 e3 ad e4 e3 8d ad c9 c2 de ad e0 e2 e9 cd e8 a3}  //weight: 1, accuracy: High
        $x_1_142 = {fa ae ec 8e eb ae fc fb e0 ae e7 e0 8e ae ca c1 dd ae e3 e1 ea ce eb a0}  //weight: 1, accuracy: High
        $x_1_143 = {fb af ed 8f ea af fd fa e1 af e6 e1 8f af cb c0 dc af e2 e0 eb cf ea a1}  //weight: 1, accuracy: High
        $x_1_144 = {e4 b0 f2 90 f5 b0 e2 e5 fe b0 f9 fe 90 b0 d4 df c3 b0 fd ff f4 d0 f5 be}  //weight: 1, accuracy: High
        $x_1_145 = {e5 b1 f3 91 f4 b1 e3 e4 ff b1 f8 ff 91 b1 d5 de c2 b1 fc fe f5 d1 f4 bf}  //weight: 1, accuracy: High
        $x_1_146 = {e6 b2 f0 92 f7 b2 e0 e7 fc b2 fb fc 92 b2 d6 dd c1 b2 ff fd f6 d2 f7 bc}  //weight: 1, accuracy: High
        $x_1_147 = {e7 b3 f1 93 f6 b3 e1 e6 fd b3 fa fd 93 b3 d7 dc c0 b3 fe fc f7 d3 f6 bd}  //weight: 1, accuracy: High
        $x_1_148 = {e0 b4 f6 94 f1 b4 e6 e1 fa b4 fd fa 94 b4 d0 db c7 b4 f9 fb f0 d4 f1 ba}  //weight: 1, accuracy: High
        $x_1_149 = {e1 b5 f7 95 f0 b5 e7 e0 fb b5 fc fb 95 b5 d1 da c6 b5 f8 fa f1 d5 f0 bb}  //weight: 1, accuracy: High
        $x_1_150 = {e2 b6 f4 96 f3 b6 e4 e3 f8 b6 ff f8 96 b6 d2 d9 c5 b6 fb f9 f2 d6 f3 b8}  //weight: 1, accuracy: High
        $x_1_151 = {e3 b7 f5 97 f2 b7 e5 e2 f9 b7 fe f9 97 b7 d3 d8 c4 b7 fa f8 f3 d7 f2 b9}  //weight: 1, accuracy: High
        $x_1_152 = {ec b8 fa 98 fd b8 ea ed f6 b8 f1 f6 98 b8 dc d7 cb b8 f5 f7 fc d8 fd b6}  //weight: 1, accuracy: High
        $x_1_153 = {ed b9 fb 99 fc b9 eb ec f7 b9 f0 f7 99 b9 dd d6 ca b9 f4 f6 fd d9 fc b7}  //weight: 1, accuracy: High
        $x_1_154 = {ee ba f8 9a ff ba e8 ef f4 ba f3 f4 9a ba de d5 c9 ba f7 f5 fe da ff b4}  //weight: 1, accuracy: High
        $x_1_155 = {ef bb f9 9b fe bb e9 ee f5 bb f2 f5 9b bb df d4 c8 bb f6 f4 ff db fe b5}  //weight: 1, accuracy: High
        $x_1_156 = {e8 bc fe 9c f9 bc ee e9 f2 bc f5 f2 9c bc d8 d3 cf bc f1 f3 f8 dc f9 b2}  //weight: 1, accuracy: High
        $x_1_157 = {e9 bd ff 9d f8 bd ef e8 f3 bd f4 f3 9d bd d9 d2 ce bd f0 f2 f9 dd f8 b3}  //weight: 1, accuracy: High
        $x_1_158 = {ea be fc 9e fb be ec eb f0 be f7 f0 9e be da d1 cd be f3 f1 fa de fb b0}  //weight: 1, accuracy: High
        $x_1_159 = {eb bf fd 9f fa bf ed ea f1 bf f6 f1 9f bf db d0 cc bf f2 f0 fb df fa b1}  //weight: 1, accuracy: High
        $x_1_160 = {d4 80 c2 a0 c5 80 d2 d5 ce 80 c9 ce a0 80 e4 ef f3 80 cd cf c4 e0 c5 8e}  //weight: 1, accuracy: High
        $x_1_161 = {d5 81 c3 a1 c4 81 d3 d4 cf 81 c8 cf a1 81 e5 ee f2 81 cc ce c5 e1 c4 8f}  //weight: 1, accuracy: High
        $x_1_162 = {d6 82 c0 a2 c7 82 d0 d7 cc 82 cb cc a2 82 e6 ed f1 82 cf cd c6 e2 c7 8c}  //weight: 1, accuracy: High
        $x_1_163 = {d7 83 c1 a3 c6 83 d1 d6 cd 83 ca cd a3 83 e7 ec f0 83 ce cc c7 e3 c6 8d}  //weight: 1, accuracy: High
        $x_1_164 = {d0 84 c6 a4 c1 84 d6 d1 ca 84 cd ca a4 84 e0 eb f7 84 c9 cb c0 e4 c1 8a}  //weight: 1, accuracy: High
        $x_1_165 = {d1 85 c7 a5 c0 85 d7 d0 cb 85 cc cb a5 85 e1 ea f6 85 c8 ca c1 e5 c0 8b}  //weight: 1, accuracy: High
        $x_1_166 = {d2 86 c4 a6 c3 86 d4 d3 c8 86 cf c8 a6 86 e2 e9 f5 86 cb c9 c2 e6 c3 88}  //weight: 1, accuracy: High
        $x_1_167 = {d3 87 c5 a7 c2 87 d5 d2 c9 87 ce c9 a7 87 e3 e8 f4 87 ca c8 c3 e7 c2 89}  //weight: 1, accuracy: High
        $x_1_168 = {dc 88 ca a8 cd 88 da dd c6 88 c1 c6 a8 88 ec e7 fb 88 c5 c7 cc e8 cd 86}  //weight: 1, accuracy: High
        $x_1_169 = {dd 89 cb a9 cc 89 db dc c7 89 c0 c7 a9 89 ed e6 fa 89 c4 c6 cd e9 cc 87}  //weight: 1, accuracy: High
        $x_1_170 = {de 8a c8 aa cf 8a d8 df c4 8a c3 c4 aa 8a ee e5 f9 8a c7 c5 ce ea cf 84}  //weight: 1, accuracy: High
        $x_1_171 = {df 8b c9 ab ce 8b d9 de c5 8b c2 c5 ab 8b ef e4 f8 8b c6 c4 cf eb ce 85}  //weight: 1, accuracy: High
        $x_1_172 = {d8 8c ce ac c9 8c de d9 c2 8c c5 c2 ac 8c e8 e3 ff 8c c1 c3 c8 ec c9 82}  //weight: 1, accuracy: High
        $x_1_173 = {d9 8d cf ad c8 8d df d8 c3 8d c4 c3 ad 8d e9 e2 fe 8d c0 c2 c9 ed c8 83}  //weight: 1, accuracy: High
        $x_1_174 = {da 8e cc ae cb 8e dc db c0 8e c7 c0 ae 8e ea e1 fd 8e c3 c1 ca ee cb 80}  //weight: 1, accuracy: High
        $x_1_175 = {db 8f cd af ca 8f dd da c1 8f c6 c1 af 8f eb e0 fc 8f c2 c0 cb ef ca 81}  //weight: 1, accuracy: High
        $x_1_176 = {c4 90 d2 b0 d5 90 c2 c5 de 90 d9 de b0 90 f4 ff e3 90 dd df d4 f0 d5 9e}  //weight: 1, accuracy: High
        $x_1_177 = {c5 91 d3 b1 d4 91 c3 c4 df 91 d8 df b1 91 f5 fe e2 91 dc de d5 f1 d4 9f}  //weight: 1, accuracy: High
        $x_1_178 = {c6 92 d0 b2 d7 92 c0 c7 dc 92 db dc b2 92 f6 fd e1 92 df dd d6 f2 d7 9c}  //weight: 1, accuracy: High
        $x_1_179 = {c7 93 d1 b3 d6 93 c1 c6 dd 93 da dd b3 93 f7 fc e0 93 de dc d7 f3 d6 9d}  //weight: 1, accuracy: High
        $x_1_180 = {c0 94 d6 b4 d1 94 c6 c1 da 94 dd da b4 94 f0 fb e7 94 d9 db d0 f4 d1 9a}  //weight: 1, accuracy: High
        $x_1_181 = {c1 95 d7 b5 d0 95 c7 c0 db 95 dc db b5 95 f1 fa e6 95 d8 da d1 f5 d0 9b}  //weight: 1, accuracy: High
        $x_1_182 = {c2 96 d4 b6 d3 96 c4 c3 d8 96 df d8 b6 96 f2 f9 e5 96 db d9 d2 f6 d3 98}  //weight: 1, accuracy: High
        $x_1_183 = {c3 97 d5 b7 d2 97 c5 c2 d9 97 de d9 b7 97 f3 f8 e4 97 da d8 d3 f7 d2 99}  //weight: 1, accuracy: High
        $x_1_184 = {cc 98 da b8 dd 98 ca cd d6 98 d1 d6 b8 98 fc f7 eb 98 d5 d7 dc f8 dd 96}  //weight: 1, accuracy: High
        $x_1_185 = {cd 99 db b9 dc 99 cb cc d7 99 d0 d7 b9 99 fd f6 ea 99 d4 d6 dd f9 dc 97}  //weight: 1, accuracy: High
        $x_1_186 = {ce 9a d8 ba df 9a c8 cf d4 9a d3 d4 ba 9a fe f5 e9 9a d7 d5 de fa df 94}  //weight: 1, accuracy: High
        $x_1_187 = {cf 9b d9 bb de 9b c9 ce d5 9b d2 d5 bb 9b ff f4 e8 9b d6 d4 df fb de 95}  //weight: 1, accuracy: High
        $x_1_188 = {c8 9c de bc d9 9c ce c9 d2 9c d5 d2 bc 9c f8 f3 ef 9c d1 d3 d8 fc d9 92}  //weight: 1, accuracy: High
        $x_1_189 = {c9 9d df bd d8 9d cf c8 d3 9d d4 d3 bd 9d f9 f2 ee 9d d0 d2 d9 fd d8 93}  //weight: 1, accuracy: High
        $x_1_190 = {ca 9e dc be db 9e cc cb d0 9e d7 d0 be 9e fa f1 ed 9e d3 d1 da fe db 90}  //weight: 1, accuracy: High
        $x_1_191 = {cb 9f dd bf da 9f cd ca d1 9f d6 d1 bf 9f fb f0 ec 9f d2 d0 db ff da 91}  //weight: 1, accuracy: High
        $x_1_192 = {b4 e0 a2 c0 a5 e0 b2 b5 ae e0 a9 ae c0 e0 84 8f 93 e0 ad af a4 80 a5 ee}  //weight: 1, accuracy: High
        $x_1_193 = {b5 e1 a3 c1 a4 e1 b3 b4 af e1 a8 af c1 e1 85 8e 92 e1 ac ae a5 81 a4 ef}  //weight: 1, accuracy: High
        $x_1_194 = {b6 e2 a0 c2 a7 e2 b0 b7 ac e2 ab ac c2 e2 86 8d 91 e2 af ad a6 82 a7 ec}  //weight: 1, accuracy: High
        $x_1_195 = {b7 e3 a1 c3 a6 e3 b1 b6 ad e3 aa ad c3 e3 87 8c 90 e3 ae ac a7 83 a6 ed}  //weight: 1, accuracy: High
        $x_1_196 = {b0 e4 a6 c4 a1 e4 b6 b1 aa e4 ad aa c4 e4 80 8b 97 e4 a9 ab a0 84 a1 ea}  //weight: 1, accuracy: High
        $x_1_197 = {b1 e5 a7 c5 a0 e5 b7 b0 ab e5 ac ab c5 e5 81 8a 96 e5 a8 aa a1 85 a0 eb}  //weight: 1, accuracy: High
        $x_1_198 = {b2 e6 a4 c6 a3 e6 b4 b3 a8 e6 af a8 c6 e6 82 89 95 e6 ab a9 a2 86 a3 e8}  //weight: 1, accuracy: High
        $x_1_199 = {b3 e7 a5 c7 a2 e7 b5 b2 a9 e7 ae a9 c7 e7 83 88 94 e7 aa a8 a3 87 a2 e9}  //weight: 1, accuracy: High
        $x_1_200 = {bc e8 aa c8 ad e8 ba bd a6 e8 a1 a6 c8 e8 8c 87 9b e8 a5 a7 ac 88 ad e6}  //weight: 1, accuracy: High
        $x_1_201 = {bd e9 ab c9 ac e9 bb bc a7 e9 a0 a7 c9 e9 8d 86 9a e9 a4 a6 ad 89 ac e7}  //weight: 1, accuracy: High
        $x_1_202 = {be ea a8 ca af ea b8 bf a4 ea a3 a4 ca ea 8e 85 99 ea a7 a5 ae 8a af e4}  //weight: 1, accuracy: High
        $x_1_203 = {bf eb a9 cb ae eb b9 be a5 eb a2 a5 cb eb 8f 84 98 eb a6 a4 af 8b ae e5}  //weight: 1, accuracy: High
        $x_1_204 = {b8 ec ae cc a9 ec be b9 a2 ec a5 a2 cc ec 88 83 9f ec a1 a3 a8 8c a9 e2}  //weight: 1, accuracy: High
        $x_1_205 = {b9 ed af cd a8 ed bf b8 a3 ed a4 a3 cd ed 89 82 9e ed a0 a2 a9 8d a8 e3}  //weight: 1, accuracy: High
        $x_1_206 = {ba ee ac ce ab ee bc bb a0 ee a7 a0 ce ee 8a 81 9d ee a3 a1 aa 8e ab e0}  //weight: 1, accuracy: High
        $x_1_207 = {bb ef ad cf aa ef bd ba a1 ef a6 a1 cf ef 8b 80 9c ef a2 a0 ab 8f aa e1}  //weight: 1, accuracy: High
        $x_1_208 = {a4 f0 b2 d0 b5 f0 a2 a5 be f0 b9 be d0 f0 94 9f 83 f0 bd bf b4 90 b5 fe}  //weight: 1, accuracy: High
        $x_1_209 = {a5 f1 b3 d1 b4 f1 a3 a4 bf f1 b8 bf d1 f1 95 9e 82 f1 bc be b5 91 b4 ff}  //weight: 1, accuracy: High
        $x_1_210 = {a6 f2 b0 d2 b7 f2 a0 a7 bc f2 bb bc d2 f2 96 9d 81 f2 bf bd b6 92 b7 fc}  //weight: 1, accuracy: High
        $x_1_211 = {a7 f3 b1 d3 b6 f3 a1 a6 bd f3 ba bd d3 f3 97 9c 80 f3 be bc b7 93 b6 fd}  //weight: 1, accuracy: High
        $x_1_212 = {a0 f4 b6 d4 b1 f4 a6 a1 ba f4 bd ba d4 f4 90 9b 87 f4 b9 bb b0 94 b1 fa}  //weight: 1, accuracy: High
        $x_1_213 = {a1 f5 b7 d5 b0 f5 a7 a0 bb f5 bc bb d5 f5 91 9a 86 f5 b8 ba b1 95 b0 fb}  //weight: 1, accuracy: High
        $x_1_214 = {a2 f6 b4 d6 b3 f6 a4 a3 b8 f6 bf b8 d6 f6 92 99 85 f6 bb b9 b2 96 b3 f8}  //weight: 1, accuracy: High
        $x_1_215 = {a3 f7 b5 d7 b2 f7 a5 a2 b9 f7 be b9 d7 f7 93 98 84 f7 ba b8 b3 97 b2 f9}  //weight: 1, accuracy: High
        $x_1_216 = {ac f8 ba d8 bd f8 aa ad b6 f8 b1 b6 d8 f8 9c 97 8b f8 b5 b7 bc 98 bd f6}  //weight: 1, accuracy: High
        $x_1_217 = {ad f9 bb d9 bc f9 ab ac b7 f9 b0 b7 d9 f9 9d 96 8a f9 b4 b6 bd 99 bc f7}  //weight: 1, accuracy: High
        $x_1_218 = {ae fa b8 da bf fa a8 af b4 fa b3 b4 da fa 9e 95 89 fa b7 b5 be 9a bf f4}  //weight: 1, accuracy: High
        $x_1_219 = {af fb b9 db be fb a9 ae b5 fb b2 b5 db fb 9f 94 88 fb b6 b4 bf 9b be f5}  //weight: 1, accuracy: High
        $x_1_220 = {a8 fc be dc b9 fc ae a9 b2 fc b5 b2 dc fc 98 93 8f fc b1 b3 b8 9c b9 f2}  //weight: 1, accuracy: High
        $x_1_221 = {a9 fd bf dd b8 fd af a8 b3 fd b4 b3 dd fd 99 92 8e fd b0 b2 b9 9d b8 f3}  //weight: 1, accuracy: High
        $x_1_222 = {aa fe bc de bb fe ac ab b0 fe b7 b0 de fe 9a 91 8d fe b3 b1 ba 9e bb f0}  //weight: 1, accuracy: High
        $x_1_223 = {ab ff bd df ba ff ad aa b1 ff b6 b1 df ff 9b 90 8c ff b2 b0 bb 9f ba f1}  //weight: 1, accuracy: High
        $x_1_224 = {94 c0 82 e0 85 c0 92 95 8e c0 89 8e e0 c0 a4 af b3 c0 8d 8f 84 a0 85 ce}  //weight: 1, accuracy: High
        $x_1_225 = {95 c1 83 e1 84 c1 93 94 8f c1 88 8f e1 c1 a5 ae b2 c1 8c 8e 85 a1 84 cf}  //weight: 1, accuracy: High
        $x_1_226 = {96 c2 80 e2 87 c2 90 97 8c c2 8b 8c e2 c2 a6 ad b1 c2 8f 8d 86 a2 87 cc}  //weight: 1, accuracy: High
        $x_1_227 = {97 c3 81 e3 86 c3 91 96 8d c3 8a 8d e3 c3 a7 ac b0 c3 8e 8c 87 a3 86 cd}  //weight: 1, accuracy: High
        $x_1_228 = {90 c4 86 e4 81 c4 96 91 8a c4 8d 8a e4 c4 a0 ab b7 c4 89 8b 80 a4 81 ca}  //weight: 1, accuracy: High
        $x_1_229 = {91 c5 87 e5 80 c5 97 90 8b c5 8c 8b e5 c5 a1 aa b6 c5 88 8a 81 a5 80 cb}  //weight: 1, accuracy: High
        $x_1_230 = {92 c6 84 e6 83 c6 94 93 88 c6 8f 88 e6 c6 a2 a9 b5 c6 8b 89 82 a6 83 c8}  //weight: 1, accuracy: High
        $x_1_231 = {93 c7 85 e7 82 c7 95 92 89 c7 8e 89 e7 c7 a3 a8 b4 c7 8a 88 83 a7 82 c9}  //weight: 1, accuracy: High
        $x_1_232 = {9c c8 8a e8 8d c8 9a 9d 86 c8 81 86 e8 c8 ac a7 bb c8 85 87 8c a8 8d c6}  //weight: 1, accuracy: High
        $x_1_233 = {9d c9 8b e9 8c c9 9b 9c 87 c9 80 87 e9 c9 ad a6 ba c9 84 86 8d a9 8c c7}  //weight: 1, accuracy: High
        $x_1_234 = {9e ca 88 ea 8f ca 98 9f 84 ca 83 84 ea ca ae a5 b9 ca 87 85 8e aa 8f c4}  //weight: 1, accuracy: High
        $x_1_235 = {9f cb 89 eb 8e cb 99 9e 85 cb 82 85 eb cb af a4 b8 cb 86 84 8f ab 8e c5}  //weight: 1, accuracy: High
        $x_1_236 = {98 cc 8e ec 89 cc 9e 99 82 cc 85 82 ec cc a8 a3 bf cc 81 83 88 ac 89 c2}  //weight: 1, accuracy: High
        $x_1_237 = {99 cd 8f ed 88 cd 9f 98 83 cd 84 83 ed cd a9 a2 be cd 80 82 89 ad 88 c3}  //weight: 1, accuracy: High
        $x_1_238 = {9a ce 8c ee 8b ce 9c 9b 80 ce 87 80 ee ce aa a1 bd ce 83 81 8a ae 8b c0}  //weight: 1, accuracy: High
        $x_1_239 = {9b cf 8d ef 8a cf 9d 9a 81 cf 86 81 ef cf ab a0 bc cf 82 80 8b af 8a c1}  //weight: 1, accuracy: High
        $x_1_240 = {84 d0 92 f0 95 d0 82 85 9e d0 99 9e f0 d0 b4 bf a3 d0 9d 9f 94 b0 95 de}  //weight: 1, accuracy: High
        $x_1_241 = {85 d1 93 f1 94 d1 83 84 9f d1 98 9f f1 d1 b5 be a2 d1 9c 9e 95 b1 94 df}  //weight: 1, accuracy: High
        $x_1_242 = {86 d2 90 f2 97 d2 80 87 9c d2 9b 9c f2 d2 b6 bd a1 d2 9f 9d 96 b2 97 dc}  //weight: 1, accuracy: High
        $x_1_243 = {87 d3 91 f3 96 d3 81 86 9d d3 9a 9d f3 d3 b7 bc a0 d3 9e 9c 97 b3 96 dd}  //weight: 1, accuracy: High
        $x_1_244 = {80 d4 96 f4 91 d4 86 81 9a d4 9d 9a f4 d4 b0 bb a7 d4 99 9b 90 b4 91 da}  //weight: 1, accuracy: High
        $x_1_245 = {81 d5 97 f5 90 d5 87 80 9b d5 9c 9b f5 d5 b1 ba a6 d5 98 9a 91 b5 90 db}  //weight: 1, accuracy: High
        $x_1_246 = {82 d6 94 f6 93 d6 84 83 98 d6 9f 98 f6 d6 b2 b9 a5 d6 9b 99 92 b6 93 d8}  //weight: 1, accuracy: High
        $x_1_247 = {83 d7 95 f7 92 d7 85 82 99 d7 9e 99 f7 d7 b3 b8 a4 d7 9a 98 93 b7 92 d9}  //weight: 1, accuracy: High
        $x_1_248 = {8c d8 9a f8 9d d8 8a 8d 96 d8 91 96 f8 d8 bc b7 ab d8 95 97 9c b8 9d d6}  //weight: 1, accuracy: High
        $x_1_249 = {8d d9 9b f9 9c d9 8b 8c 97 d9 90 97 f9 d9 bd b6 aa d9 94 96 9d b9 9c d7}  //weight: 1, accuracy: High
        $x_1_250 = {8e da 98 fa 9f da 88 8f 94 da 93 94 fa da be b5 a9 da 97 95 9e ba 9f d4}  //weight: 1, accuracy: High
        $x_1_251 = {8f db 99 fb 9e db 89 8e 95 db 92 95 fb db bf b4 a8 db 96 94 9f bb 9e d5}  //weight: 1, accuracy: High
        $x_1_252 = {88 dc 9e fc 99 dc 8e 89 92 dc 95 92 fc dc b8 b3 af dc 91 93 98 bc 99 d2}  //weight: 1, accuracy: High
        $x_1_253 = {89 dd 9f fd 98 dd 8f 88 93 dd 94 93 fd dd b9 b2 ae dd 90 92 99 bd 98 d3}  //weight: 1, accuracy: High
        $x_1_254 = {8a de 9c fe 9b de 8c 8b 90 de 97 90 fe de ba b1 ad de 93 91 9a be 9b d0}  //weight: 1, accuracy: High
        $x_1_255 = {8b df 9d ff 9a df 8d 8a 91 df 96 91 ff df bb b0 ac df 92 90 9b bf 9a d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win32_Obfuscator_Pouletcrypt_2147711676_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.Pouletcrypt"
        threat_id = "2147711676"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 80 00 00 29 ?? ?? 6a 00 03 b3 ?? ?? ?? 00 56 2b b3 ?? ?? ?? 00 29 ?? ?? e8 ?? 00 00 00 5b 5e 5f 5a ff e3}  //weight: 1, accuracy: Low
        $x_1_2 = {59 d3 c0 8a dc b4 00 d3 cb 59 49 75 ea c1 cb 18 52 29 d2 31 da 89 d0 5a 5b 59 c9 c2 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_QQ_2147711751_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QQ"
        threat_id = "2147711751"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 81 c4 5c ff ff ff 64 8b 3d 30 00 00 00 (03|0f|2b|3b|6b|83|8b|b8|b9|ba|be) [0-4] (03|0f|2b|3b|6b|83|8b|b8|b9|ba|be) [0-4] (03|0f|2b|3b|6b|83|8b|b8|b9|ba|be) [0-4] (03|0f|2b|3b|6b|83|8b|b8|b9|ba|be) [0-4] (03|0f|2b|3b|6b|83|8b|b8|b9|ba|be)}  //weight: 10, accuracy: Low
        $x_1_2 = {89 bd 5c ff ff ff 8b 5d e4 83 eb ?? c7 07 ?? ?? ?? ?? 03 fb c7 07 ?? ?? ?? ?? 03 fb c7 07 ?? ?? ?? ?? 03 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CAL_2147711990_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAL"
        threat_id = "2147711990"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 24 30 6b c6 44 24 35 6c c6 44 24 36 33 c6 44 24 37 32 88 5c 24 38}  //weight: 1, accuracy: High
        $x_1_2 = {b8 cd cc cc cc f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 8a 82 ?? ?? ?? ?? 30 04 39 41 3b ce 72 df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZAH_2147714348_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZAH!bit"
        threat_id = "2147714348"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f4 8a 4c 37 04 8a 14 02 8a c3 f6 d0 88 0e a8 01 74 04 02 ca eb 02 2a ca 88 0e 43 8b 4d ?? 46 3b 5d fc 72 d4}  //weight: 2, accuracy: Low
        $x_1_2 = {b8 4d 5a 00 00 89 7d fc 8b 5f ?? 89 5d f4 66 39 03 74 07 32 c0 e9 ?? ?? 00 00 56 8b 73 3c 03 f3 81 3e 50 45 00 00 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 30 00 00 52 6a 00 ff 17 8b f8 85 ff 0f 84 ?? ?? 00 00 0f b7 46 06 6b c8 28 0f b7 46 14 03 c8 8b 43 3c 83 c1 18 03 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ZAI_2147716261_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZAI!bit"
        threat_id = "2147716261"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 03 c3 8a 0c 1a 88 0c 30 60 8b 4d 08 8a 45 ff d3 e3 33 db 0b 1d ?? ?? ?? ?? 03 d9 8a 33 90 c1 ea 08 90 33 c2 88 03 90 61 8b 45 08 40 3d ?? ?? ?? ?? 89 45 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 24 46 88 5c 24 48 88 5c 24 4b 88 5c 24 4c c6 44 24 49 2e 88 44 24 4a c6 44 24 4d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_ZAK_2147716536_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZAK!bit"
        threat_id = "2147716536"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c8 03 c3 68 ?? ?? ?? 00 8a 14 19 88 14 30 ff 15 ?? ?? ?? 00 60 8b 4d 08 8a 45 ff d3 e3 33 db 0b 1d ?? ?? ?? 00 03 d9 8a 33 90 c1 ea 08 90 33 c2 88 03}  //weight: 2, accuracy: Low
        $x_1_2 = {b1 64 b0 6c 68 ?? ?? ?? ?? 88 4c ?? ?? 88 44 ?? ?? 88 44 ?? ?? c6 44 ?? ?? 2e 88 4c ?? ?? 88 44 ?? ?? 88 44 ?? ?? c6 44 ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c9 8a 0c 10 81 e9 8b 00 00 00 75 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_QV_2147716824_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QV"
        threat_id = "2147716824"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {eb 09 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1}  //weight: 10, accuracy: High
        $x_10_2 = {8a 01 3c 61 7c 15 3c 7a 7f 11 0f be c0 83 e8 54 6a 1a 99 5f f7 ff 80 c2 61 eb 17 3c 41 7c 15 3c 5a 7f 11 0f be c0 83 e8 34 6a 1a 99 5f f7 ff 80 c2 41 88 11 41 80 39 00 75 c6}  //weight: 10, accuracy: High
        $x_1_3 = "hfre32.qyy" ascii //weight: 1
        $x_1_4 = "jf2_32.qyy" ascii //weight: 1
        $x_1_5 = "jvavarg.qyy" ascii //weight: 1
        $x_1_6 = "nqincv32.qyy" ascii //weight: 1
        $x_1_7 = "furyy32.qyy" ascii //weight: 1
        $x_1_8 = "agqyy.qyy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_QV_2147716824_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.QV"
        threat_id = "2147716824"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8e fe 1f 4b 74}  //weight: 5, accuracy: High
        $x_5_2 = {3d 03 40 00 80 74 14 68 19 2b 90 95}  //weight: 5, accuracy: High
        $x_1_3 = {68 01 3d 1e d2}  //weight: 1, accuracy: High
        $x_1_4 = {68 02 f1 f8 08}  //weight: 1, accuracy: High
        $x_1_5 = {68 05 ad 89 0d}  //weight: 1, accuracy: High
        $x_1_6 = {68 07 be db 80}  //weight: 1, accuracy: High
        $x_1_7 = {68 09 dc 1b 1e}  //weight: 1, accuracy: High
        $x_1_8 = {68 0c fb 14 73}  //weight: 1, accuracy: High
        $x_1_9 = {68 13 11 74 02}  //weight: 1, accuracy: High
        $x_1_10 = {68 19 2b 90 95}  //weight: 1, accuracy: High
        $x_1_11 = {68 25 f5 10 5e}  //weight: 1, accuracy: High
        $x_1_12 = {68 26 ef 02 98}  //weight: 1, accuracy: High
        $x_1_13 = {68 28 de 73 75}  //weight: 1, accuracy: High
        $x_1_14 = {68 2c 01 95 12}  //weight: 1, accuracy: High
        $x_1_15 = {68 2f 00 10 15}  //weight: 1, accuracy: High
        $x_1_16 = {68 32 0e 48 9c}  //weight: 1, accuracy: High
        $x_1_17 = {68 34 55 35 db}  //weight: 1, accuracy: High
        $x_1_18 = {68 3a e0 48 ef}  //weight: 1, accuracy: High
        $x_1_19 = {68 3e 8d 61 be}  //weight: 1, accuracy: High
        $x_1_20 = {68 42 a8 6f 9e}  //weight: 1, accuracy: High
        $x_1_21 = {68 46 85 5d c9}  //weight: 1, accuracy: High
        $x_1_22 = {68 49 7d 99 28}  //weight: 1, accuracy: High
        $x_1_23 = "hR$C2" ascii //weight: 1
        $x_1_24 = {68 57 95 aa de}  //weight: 1, accuracy: High
        $x_1_25 = {68 59 c7 ec d4}  //weight: 1, accuracy: High
        $x_1_26 = {68 60 a2 8a 76}  //weight: 1, accuracy: High
        $x_1_27 = {68 62 29 21 1a}  //weight: 1, accuracy: High
        $x_1_28 = {68 6a 85 13 9f}  //weight: 1, accuracy: High
        $x_1_29 = {68 6b e1 7f 48}  //weight: 1, accuracy: High
        $x_1_30 = {68 6d d1 b2 4c}  //weight: 1, accuracy: High
        $x_1_31 = {68 71 a1 5e 72}  //weight: 1, accuracy: High
        $x_1_32 = {68 78 9c d0 1a}  //weight: 1, accuracy: High
        $x_1_33 = {68 7c 01 f0 5a}  //weight: 1, accuracy: High
        $x_1_34 = {68 81 de ec 67}  //weight: 1, accuracy: High
        $x_1_35 = {68 86 67 41 6b}  //weight: 1, accuracy: High
        $x_1_36 = {68 8a 96 78 bf}  //weight: 1, accuracy: High
        $x_1_37 = {68 8f c8 0b 57}  //weight: 1, accuracy: High
        $x_1_38 = {68 95 23 26 bc}  //weight: 1, accuracy: High
        $x_1_39 = {68 95 69 27 f2}  //weight: 1, accuracy: High
        $x_1_40 = {68 9b 90 c4 8a}  //weight: 1, accuracy: High
        $x_1_41 = {68 9d 29 a4 99}  //weight: 1, accuracy: High
        $x_1_42 = {68 a1 87 55 4d}  //weight: 1, accuracy: High
        $x_1_43 = {68 a1 b0 5c 72}  //weight: 1, accuracy: High
        $x_1_44 = {68 af 12 3d 1b}  //weight: 1, accuracy: High
        $x_1_45 = {68 c0 0f 40 3e}  //weight: 1, accuracy: High
        $x_1_46 = {68 c1 ea 9d 27}  //weight: 1, accuracy: High
        $x_1_47 = {68 c3 d1 3f 0f}  //weight: 1, accuracy: High
        $x_1_48 = {68 c8 39 03 24}  //weight: 1, accuracy: High
        $x_1_49 = {68 c9 f0 f0 81}  //weight: 1, accuracy: High
        $x_1_50 = {68 d1 8a 31 46}  //weight: 1, accuracy: High
        $x_1_51 = {68 d5 70 34 6b}  //weight: 1, accuracy: High
        $x_1_52 = {68 d5 b0 3e 72}  //weight: 1, accuracy: High
        $x_1_53 = {68 d7 3d 59 08}  //weight: 1, accuracy: High
        $x_1_54 = {68 d9 38 45 17}  //weight: 1, accuracy: High
        $x_1_55 = {68 dc 67 21 7a}  //weight: 1, accuracy: High
        $x_1_56 = {68 e4 55 9f da}  //weight: 1, accuracy: High
        $x_1_57 = {68 eb 3d 03 84}  //weight: 1, accuracy: High
        $x_1_58 = {68 ee ea c0 1f}  //weight: 1, accuracy: High
        $x_1_59 = {68 f0 97 a0 90}  //weight: 1, accuracy: High
        $x_1_60 = {68 f0 9a b8 6f}  //weight: 1, accuracy: High
        $x_1_61 = {68 f3 74 43 c5}  //weight: 1, accuracy: High
        $x_1_62 = {68 f5 72 99 3d}  //weight: 1, accuracy: High
        $x_1_63 = {68 f6 35 3d d6}  //weight: 1, accuracy: High
        $x_1_64 = {68 fb 96 32 22}  //weight: 1, accuracy: High
        $x_1_65 = {68 fc 7e b8 48}  //weight: 1, accuracy: High
        $x_1_66 = {68 fc da 94 48}  //weight: 1, accuracy: High
        $x_1_67 = {68 fe 93 43 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_5_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ZAL_2147718635_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZAL!bit"
        threat_id = "2147718635"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 24 14 8b 0d ?? ?? ?? 00 02 c3 5b 32 c2 88 04 31 8b 44 24 0c 83 f8 10 75 02}  //weight: 2, accuracy: Low
        $x_1_2 = {64 8b 1d 18 00 00 00 [0-32] 8b 51 30 [0-32] 8b 48 0c [0-32] 8b 42 1c [0-32] 8b 51 08}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 8a 51 01 83 ea 4c 85 d2 74 04 ff e3 eb ?? b8}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 10 88 11 a0 ?? ?? ?? 00 50 8b 4d ?? 51 8b 55 ?? 52 e8 ?? ?? ?? 00 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_ZAM_2147718758_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ZAM!bit"
        threat_id = "2147718758"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c8 89 4d ?? eb d6 8b 15 ?? ?? ?? 00 03 55 ?? 8a 45 ?? 88 02 83 7d ?? 00 74 0e 8b 0d ?? ?? ?? 00 03 4d ?? 8a 55 ?? 88 11 eb 81}  //weight: 2, accuracy: Low
        $x_2_2 = {03 45 98 8a 4d cc 88 08 83 7d d8 00 74 0e 8b 15 ?? ?? ?? 00 03 55 98 8a 45 cc 88 02 e9 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = {74 25 6a 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 85 c0 74 0a}  //weight: 1, accuracy: Low
        $x_1_4 = "//::++**s3///f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CAN_2147719216_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAN"
        threat_id = "2147719216"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 00 8b 45 f4 50 ff 95 ?? ?? ff ff 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff ff 75 05 e9 ?? ?? 00 00 6a 04 68 00 30 00 00 8b 8d ?? ?? ff ff 51 6a 00 ff 95}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 55 f4 52 ff 95 ?? ?? ff ff 85 c0 75 05 e9 ?? ?? 00 00 8b 85 ?? ?? ff ff 89 85 ?? ?? ff ff 8b 8d ?? ?? ff ff 8b 51 3c}  //weight: 3, accuracy: Low
        $x_3_3 = {8d 44 0a 18 89 85 ?? ?? ff ff 6a 04 68 00 30 00 00 8b 8d ?? ?? ff ff 8b 51 ?? 52 6a 00 ff 95 ?? ?? ff ff 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff 00 75 05 e9}  //weight: 3, accuracy: Low
        $x_4_4 = {0f b6 02 3d b8 00 00 00 75 02 eb ?? 8b 4d fc 0f b6 11 81 fa e9 00 00 00 75}  //weight: 4, accuracy: Low
        $x_4_5 = {8d 44 0a 05 89 45 fc eb ?? 8b 4d fc 0f b6 11 81 fa ea 00 00 00 75 ?? 8b 45 fc 8b 48 01 89 4d fc eb}  //weight: 4, accuracy: Low
        $x_4_6 = {c2 04 00 8d 24 24 8d 24 24 8d 54 24 08 cd 2e c3}  //weight: 4, accuracy: High
        $x_3_7 = {68 02 01 00 00 ff 95 ?? ?? 00 00 68 00 80 00 00 6a 00 8b 55 ?? 52 ff 55 ?? 68 00 80 00 00 6a 00 8b 45 ?? 50 ff 55}  //weight: 3, accuracy: Low
        $x_3_8 = {68 00 80 00 00 6a 00 8b 4d ?? 51 ff 55 ?? 8b 45 ?? eb 02 33 c0 8b e5 5d c2 f0 00}  //weight: 3, accuracy: Low
        $x_3_9 = {b8 25 00 00 00 66 89 45 ?? b9 54 00 00 00 66 89 4d ?? ba 45 00 00 00 66 89 55 ?? b8 4d 00 00 00 66 89 45 ?? b9 50 00 00 00 66 89 4d ?? ba 25 00 00 00 66 89 55 ?? 33 c0 66 89 45 ?? c7 45 c8 00 00 00 00 6a 04 68 00 30 00 00 68 04 01 00 00}  //weight: 3, accuracy: Low
        $x_1_10 = {68 0b 6f d6 4a}  //weight: 1, accuracy: High
        $x_1_11 = {68 24 63 8d e9}  //weight: 1, accuracy: High
        $x_1_12 = {68 2c 0d 45 97}  //weight: 1, accuracy: High
        $x_1_13 = {68 5b ef 98 ee}  //weight: 1, accuracy: High
        $x_1_14 = {68 91 6c fd 88}  //weight: 1, accuracy: High
        $x_1_15 = {68 c8 cc e1 16}  //weight: 1, accuracy: High
        $x_1_16 = {68 cf 48 26 df}  //weight: 1, accuracy: High
        $x_1_17 = {68 f6 23 bb 49}  //weight: 1, accuracy: High
        $x_3_18 = {8a 0a 42 80 f9 ae 75 f8 84 c0 75 04 fe c0 eb f0}  //weight: 3, accuracy: High
        $x_2_19 = {8d 72 08 8b cb 8b 3e 89 4d f8 3b 7a 04 74 0d 41 8b c7 33 c1 3b 42 04 75 f6}  //weight: 2, accuracy: High
        $x_3_20 = {8a 44 0d f8 30 04 33 41 33 c0 83 f9 04 0f 44 c8 43 3b 1a 72 eb}  //weight: 3, accuracy: High
        $x_3_21 = {6a 10 6a 00 8d 45 ?? 50 e8 ?? ?? 00 00 6a 44 6a 00 8d 8d ?? ?? ff ff 51 e8 ?? ?? 00 00 6a 08 6a 00 8d 95 ?? ?? ff ff 52 e8}  //weight: 3, accuracy: Low
        $x_3_22 = {3d 4d 5a 00 00 74 07 33 c0 e9 ?? ?? 00 00 8b 4d ?? 8b 95 ?? ?? 00 00 03 51 3c 89 55 ?? 8b 45 ?? 81 38 50 45 00 00 75 0f 8b 4d ?? 0f b7 51 04 81 fa 4c 01 00 00}  //weight: 3, accuracy: Low
        $x_3_23 = {57 56 89 65 ?? 83 e4 f0 6a 33 e8 00 00 00 00 83 04 24 05 cb}  //weight: 3, accuracy: Low
        $x_3_24 = {5a 8b 45 08 0f 05 89 45 d4 03 65 ec e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb}  //weight: 3, accuracy: High
        $x_2_25 = {0f b7 4d f8 0f b7 55 f4 3b ca 74 07 b8 01 00 00 00 eb 07 e9 ?? ?? ff ff 33 c0 5e 8b e5 5d c2 08 00}  //weight: 2, accuracy: Low
        $x_2_26 = {0f be 4d fb 0f be 55 fa 3b ca 74 07 b8 01 00 00 00 eb 07 e9 ?? ?? ff ff 33 c0 5e 8b e5 5d c2 08 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CAP_2147732927_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAP"
        threat_id = "2147732927"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {39 4d 08 7e 0e e8 ?? ?? ?? ?? 30 04 11 41 3b 4d 08 7c f2 5d c2 04 00}  //weight: 20, accuracy: Low
        $x_20_2 = {6a 40 ff b5 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 9d ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 20 00 00 00 8b 85 ?? ?? ?? ?? 03 c0 89 85 ?? ?? ?? ?? 46 3b b5 ?? ?? ?? ?? 72 ?? ff b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_CAP_2147732927_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAP"
        threat_id = "2147732927"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 31 30 31 39 00 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e}  //weight: 1, accuracy: High
        $x_1_2 = {21 31 30 31 36 00 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e}  //weight: 1, accuracy: High
        $x_2_3 = {33 f6 89 7d ?? 89 45 ?? 39 5d ?? 76 ?? 53 ff 15 ?? ?? 40 00 56 ff 75 ?? e8 ?? ?? ?? ?? 88 04 3e 46 59 59 3b 75 ?? 72}  //weight: 2, accuracy: Low
        $x_2_4 = {57 ff 75 f0 e8 ?? ?? ?? ?? 59 59 8b 0d ?? ?? ?? ?? 88 04 39 83 ff ?? 75}  //weight: 2, accuracy: Low
        $x_2_5 = {56 ff 75 fc e8 ?? ?? ?? ?? 59 59 8b 0d ?? ?? ?? ?? 88 04 31 83 fe ?? 75}  //weight: 2, accuracy: Low
        $x_2_6 = {8b 4d 94 8b c6 e8 ?? ?? ?? ?? 88 04 3e 46 3b 75 ?? 72}  //weight: 2, accuracy: Low
        $x_10_7 = {55 8b ec 8b 45 ?? 8b 4d ?? 8a 04 01 5d c3}  //weight: 10, accuracy: Low
        $x_10_8 = {c3 cc ff 25 ?? ?? ?? ?? 8a 04 01 c3}  //weight: 10, accuracy: Low
        $x_30_9 = {8b c7 c1 e8 05 03 45 ?? 8b cf c1 e1 04 03 4d ?? 33 c1 8b 4d ?? 81 45 ?? ?? ?? ?? ?? 03 cf 33 c1 2b d8 ff 4d ?? 75 ?? 8b 45 ?? 89 78 04 5f 5e 89 18 5b c9 c3}  //weight: 30, accuracy: Low
        $x_30_10 = {8b c7 c1 e8 05 03 45 ?? 8b cf c1 e1 04 03 4d ?? 33 c1 8d 0c 3b 33 c1 2b f0 8b c6 c1 e8 05 03 45 ?? 8b ce c1 e1 04 03 4d ?? 33 c1 8d 0c 33 33 c1 2b f8 81 c3 ?? ?? ?? ?? ff 4d ?? 75 ?? 8b 45 ?? 89 38 5f 89 70 04 5e 5b c9 c3}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_30_*) and 1 of ($x_10_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CAP_2147732927_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAP"
        threat_id = "2147732927"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {4c 36 18 00 ?? ?? 81 ?? ?? 31 46 34 00 ?? ?? 81 ?? ?? 80 65 0f 02 ?? ?? 81 ?? ?? 0e 54 b8 02 ?? ?? 81 ?? ?? a9 cc 52 00}  //weight: 9, accuracy: Low
        $x_9_2 = {01 1f f2 00 7e 12 81 ?? ?? 7c 7f 00 00 74 09 81 ?? ?? a9 cc 52 00}  //weight: 9, accuracy: Low
        $x_5_3 = {9b 54 0f 00 ?? ?? 81 ?? ?? 24 6f 63 24}  //weight: 5, accuracy: Low
        $x_5_4 = {7d 3e 65 01}  //weight: 5, accuracy: High
        $x_9_5 = {79 b3 07 00 ?? ?? 81 ?? ?? 4f b7 23 00 ?? ?? 81 ?? ?? 11 d0 ec 1c}  //weight: 9, accuracy: Low
        $x_5_6 = {33 32 2e 64 66 c7 [0-5] 00 6c 6c}  //weight: 5, accuracy: Low
        $x_5_7 = {52 68 ad c0 03 00 6a 01}  //weight: 5, accuracy: High
        $x_5_8 = {bd 76 f0 00 7e ?? 81 ?? ?? bf 73 15 41 74}  //weight: 5, accuracy: Low
        $x_4_9 = {3d 71 75 0b 00 75}  //weight: 4, accuracy: High
        $x_4_10 = {81 7d e4 96 7c 5e 37 7d}  //weight: 4, accuracy: High
        $x_4_11 = {81 7d e4 cf 26 00 00 7d}  //weight: 4, accuracy: High
        $x_3_12 = "viziyehuyipajanedele manujihakomivucoyozehilixiyeji miyabifopogebite" ascii //weight: 3
        $x_3_13 = "huhujipibunulenivibufu tekokubemavifexirumitatimipi wuyokahatoceseyu" ascii //weight: 3
        $x_3_14 = "yugifadate memitolazurojakimususinamiwu kexawegusecucasefanizosoyopa" ascii //weight: 3
        $x_3_15 = "dojasupabaxo misawibobuwoniyu toyoliyesulibi" ascii //weight: 3
        $x_3_16 = "loyatalotubifomapi ticisekore dawiruwudonuje" ascii //weight: 3
        $x_3_17 = "wabukehebu zopobuyowa gakikobumawirupetirudo" ascii //weight: 3
        $x_3_18 = "tonomoxadarerajo micuzasutenuboba mupotukemo" ascii //weight: 3
        $x_3_19 = "piwovagitetekamihabitedo" ascii //weight: 3
        $x_3_20 = "duwavisecositesafuyatetoti" ascii //weight: 3
        $x_3_21 = "fibiboluhisuci" ascii //weight: 3
        $x_3_22 = "xehokaguzodikacasehama risamokekuru" ascii //weight: 3
        $x_3_23 = "leminowayiyobopahosudojipukocome cerexica malekunutupufid" ascii //weight: 3
        $x_3_24 = "nivokerakugisaza nikilibexuru bopegejor" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*))) or
            ((1 of ($x_9_*) and 1 of ($x_3_*))) or
            ((1 of ($x_9_*) and 1 of ($x_4_*))) or
            ((1 of ($x_9_*) and 1 of ($x_5_*))) or
            ((2 of ($x_9_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CAP_2147732927_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAP"
        threat_id = "2147732927"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 39 05 ?? ?? ?? ?? 76 ?? 8b 0d ?? ?? ?? ?? 8a 94 01 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 01 40 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {50 56 56 56 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8a 84 38 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 04 39 47 3b 3d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {41 00 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 8a 88 ?? ?? ?? ?? 88 0a 81 bd ?? ?? ?? ?? ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c0 01 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 3b 0d ?? ?? ?? ?? 73 ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 8a 88 ?? ?? ?? ?? 88 0a eb}  //weight: 1, accuracy: Low
        $x_1_5 = {33 f6 39 5d ?? 76 ?? 3b f3 75 ?? ff 75 ?? 53 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 84 37 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 04 0e 83 fe ?? 75}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 75 dc 53 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 84 37 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 04 0e 83 fe ?? 75}  //weight: 1, accuracy: Low
        $x_1_7 = {6a 00 ff d7 6a 00 6a 00 ff d3 8b 0d ?? ?? ?? ?? 8a 94 31 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 14 30 46 3b 35 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_8 = {6a 00 ff d7 6a 00 6a 00 ff d3 a1 ?? ?? ?? ?? 8a 8c 30 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 0c 32 46 3b 35 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_9 = {33 c0 89 0d ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 76 ?? 8b 15 ?? ?? ?? ?? 8a 8c 02 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 0c 02 40 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_10 = {33 c0 89 15 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 76 ?? 8b 0d ?? ?? ?? ?? 8a 94 01 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 01 40 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_11 = {6a 00 ff d7 8b 0d ?? ?? ?? ?? 8a 94 31 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 14 30 46 3b 35 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_12 = {41 00 ff 15 ?? ?? ?? ?? 8b d6 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 04 0e 46 3b b4 24 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_13 = {6a 00 ff 15 ?? ?? ?? ?? ff d3 8b d6 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 04 0e 46 3b 74 24 ?? 72}  //weight: 1, accuracy: Low
        $x_1_14 = {6a 00 8d 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 8a 89 ?? ?? ?? ?? 88 08 eb}  //weight: 1, accuracy: Low
        $x_2_15 = {50 57 57 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 4e 79}  //weight: 2, accuracy: Low
        $x_2_16 = {6a 00 6a 00 ff d5 e8 ?? ?? ?? ?? 30 04 3e 46 3b f3 7c}  //weight: 2, accuracy: Low
        $x_2_17 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 3e 46 3b f3 7c}  //weight: 2, accuracy: Low
        $x_2_18 = {6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 3e 6a 00 ff 15 ?? ?? ?? ?? 46 3b 75 ?? 7c}  //weight: 2, accuracy: Low
        $x_2_19 = {33 c1 8b 55 ?? c1 ea ?? 03 55 ?? 33 c2 8b 4d ?? 2b c8 89 4d ?? 81 7d ?? ?? ?? ?? ?? 73}  //weight: 2, accuracy: Low
        $x_2_20 = {33 d0 33 d1 2b f2 8b d6 c1 ea 05 03 54 24 ?? 8b c6 c1 e0 04 03 44 24 ?? 8d 0c 33 33 d0 33 d1 2b fa 81 fd ?? ?? ?? ?? 73}  //weight: 2, accuracy: Low
        $x_2_21 = {33 c8 2b d9 8b cb 8b c3 c1 e9 05 03 4d ?? c1 e0 04 03 45 ?? 33 c8 8d 04 1e 33 c8 8d b6 ?? ?? ?? ?? 2b f9 83 6d ?? ?? 75}  //weight: 2, accuracy: Low
        $x_2_22 = {8d 49 00 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 8b d1 c1 ea ?? 30 14 30 40 3b c7 7c}  //weight: 2, accuracy: Low
        $x_2_23 = {0f b6 c0 8b 4d ?? 03 4d ?? 0f be 09 33 c8 8b 45 ?? 03 45 ?? 88 08 8b 45 ?? 48 89 45 ?? eb}  //weight: 2, accuracy: Low
        $x_4_24 = {33 ff 81 ff ?? ?? ?? ?? 75 ?? ff 15 ?? ?? ?? ?? 8b c7 99 83 fa ?? 7c}  //weight: 4, accuracy: Low
        $x_4_25 = {33 f6 81 fe ?? ?? ?? ?? 7d ?? ff d7 81 fe ?? ?? ?? ?? 75 ?? ff 15 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 7c}  //weight: 4, accuracy: Low
        $x_4_26 = {41 00 52 a1 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 83 c4 ?? ff 15 ?? ?? ?? ?? 64 8b 15 ?? ?? ?? ?? 8b 02 c7 40 04 01 00 00 00 33 c0}  //weight: 4, accuracy: Low
        $x_4_27 = {8d 55 fc 52 6a 40 a1 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 52 8b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 15}  //weight: 4, accuracy: Low
        $x_4_28 = {46 3b 75 dc 72 ?? ff 75 ?? e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 64 a1 ?? ?? ?? ?? 8b 00 8b 4d ?? 5f 5e c7 40 04 01 00 00 00 33 cd 33 c0}  //weight: 4, accuracy: Low
        $x_4_29 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 7c ?? e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 64 8b 0d 2c 00 00 00 8b 11}  //weight: 4, accuracy: Low
        $x_4_30 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 7c ?? e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 64 a1 2c 00 00 00 8b 08}  //weight: 4, accuracy: Low
        $x_4_31 = {41 00 ff 15 ?? ?? ?? ?? 64 a1 2c 00 00 00 8b 08 5f 5e c7 41 ?? ?? ?? ?? ?? 33 c0}  //weight: 4, accuracy: Low
        $x_4_32 = {5f 5e c3 ff 15 ?? ?? ?? ?? c3 8a 84 11 ?? ?? 00 00 c3}  //weight: 4, accuracy: Low
        $x_4_33 = {6a 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 81 bd ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? ff 15 ?? ?? ?? ?? 81 bd}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
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

rule VirTool_Win32_Obfuscator_ARL_2147732940_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.ARL"
        threat_id = "2147732940"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e2 f5 8b 45 ?? 80 38 8b 75 01 c3 e8 ?? ?? ?? ?? 5f 83 c7 0d 57 53 ff 55 08}  //weight: 2, accuracy: Low
        $x_1_2 = {41 2b c2 78 04 74 02 eb f7 33 c0 03 c2 e2 fc}  //weight: 1, accuracy: High
        $x_1_3 = {58 81 78 64 00 02 00 00 75 0f 8b 04 24 c7 04 24 00 00 00 00 ff 74 24 04 50 ff e6}  //weight: 1, accuracy: High
        $x_1_4 = {8b 09 33 c0 39 41 ?? 74 f7 ff 71 ?? 8f 45 ?? e8 ?? ?? ?? ?? 8f 41 1c 61 c3 58 ff d0 83 7c 24 08 02}  //weight: 1, accuracy: Low
        $x_2_5 = {3b 75 64 75 0d 03 75 68 03 7d 68 2b 4d 68 85 c9 74 13 ad 50 83 e8 0a 35}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Obfuscator_CAQ_2147733142_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAQ"
        threat_id = "2147733142"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {3b fb 75 0f ff 74 ?? ?? 53 ff 15 ?? ?? ?? ?? 89 44 ?? ?? 8b 44 ?? ?? 89 44 ?? ?? 81 44 ?? ?? ?? ?? ?? ?? 8b 44 ?? ?? 8a 0c 38 8b 44 ?? ?? 88 0c 38 83 ff ?? 75 ?? 56 6a 40 ff 74 ?? ?? 50 ff 15 ?? ?? ?? ?? 89 ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? 8b 44 ?? ?? 03 c0 89 44 ?? ?? 47 3b 7c 24 ?? 72}  //weight: 4, accuracy: Low
        $x_4_2 = {8a 44 0f 03 8a d0 80 e2 ?? c0 e2 ?? 0a 54 0f ?? 88 55 ?? 8a d0 24 ?? c0 e0 ?? 0a 04 0f c0 e2 ?? 0a 54 0f ?? 88 04 1e 8a 45 ?? 46 88 04 1e 8b 45 ?? 46 88 14 1e 83 c1 ?? 46 3b 08 72}  //weight: 4, accuracy: Low
        $x_4_3 = {8a 44 0f 03 8a d0 80 e2 ?? c0 e2 ?? 0a 54 0f ?? 88 55 ?? 8a d0 24 ?? c0 e0 ?? 0a 04 0f c0 e2 ?? 0a 54 0f ?? 88 04 1e 8a 45 ?? 88 44 1e ?? 8b 45 ?? 88 54 1e ?? 83 c1 ?? 83 c6 ?? 3b 08 72}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win32_Obfuscator_CAP_2147733157_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CAP!!ObfuscatorCap.gen!A"
        threat_id = "2147733157"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "ObfuscatorCap: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc ad 85 c0 74 ?? 40 74 ?? 48 03 45 04 8b d0 ad 56 8b c8 8b f2 f3 a4 5e eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 f8 03 f1 4e c1 e9 03 8b d1 8b 5d c0 56 51 b9 08 00 00 00 8a 07 32 c3 88 06 47 2b f2 49 75 f4}  //weight: 1, accuracy: High
        $x_1_3 = {8b 75 f8 49 03 f1 03 f8 41 2b f9 8a 07 32 c3 88 06 47 4e 49 75 f5}  //weight: 1, accuracy: High
        $x_1_4 = {75 f7 6a 00 8d 45 ec 50 ff 75 f8 ff 75 c4 ff 75 fc ff 55 cc}  //weight: 1, accuracy: High
        $x_1_5 = {72 04 51 ff 55 0c 6a 01 68 00 20 00 00 ff 75 e8 ff 75 e4 ff 55 10 85 c0 75 0e}  //weight: 1, accuracy: High
        $x_1_6 = {03 45 d8 50 ff 55 28 8b d8 8b 47 10 85 c0 75 0a 8b 07 85 c0}  //weight: 1, accuracy: High
        $x_1_7 = {8b 06 85 c0 74 33 a9 00 00 00 f0 74 07 25 ff ff 00 00 eb 05 03 45 d8 40 40 50 53 ff 55 24}  //weight: 1, accuracy: High
        $x_1_8 = {8b 74 24 28 8b 7c 24 30 bd 03 00 00 00 31 c0 31 db ac 3c 11 76 ?? 2c 11 3c 04 73 ?? 89 c1 eb ?? 05 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_9 = {73 73 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 00 56 69 72 74 75 61 6c 46 72 65 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule VirTool_Win32_Obfuscator_CA_2147745164_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.CA!MTB"
        threat_id = "2147745164"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 e8 68 ?? ?? ?? 00 50 c7 45 fc 00 00 00 00 c7 45 e8 44 00 00 00 e8 1a 09 00 00 8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 40 89 45 08 b8 ?? ?? ?? 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "StartAsFrameProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KO_2147754552_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KO!MTB"
        threat_id = "2147754552"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0b cf c0 e5 ?? 13 cc 8f 06 81 ef 04 00 00 00 d3 e9 66 1b ce 8b 0f 66 81 fe ?? ?? f5 66 85 f8 33 cb 66 f7 c3 ?? ?? e9 65 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OA_2147754654_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OA!MTB"
        threat_id = "2147754654"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 30 fe ff ff 81 45 88 ?? ?? ?? ?? 81 6d ac ?? ?? ?? ?? 81 85 34 ff ff ff ?? ?? ?? ?? 8b 4d 08 03 4d 0c 0f be 11 0f b6 85 63 ff ff ff 33 d0 8b 4d 08 03 4d 0c 88 11 8b 55 0c 83 ea 01 89 55 0c e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_OS_2147754655_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.OS!MTB"
        threat_id = "2147754655"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 84 bd e4 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 [0-5] 8a 84 85 e4 fb ff ff 32 45 ef 8b 4d f0 88 01 [0-4] 42 ff 4d e4 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_KK_2147754833_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.KK!MTB"
        threat_id = "2147754833"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 84 24 60 01 00 00 81 84 24 bc 01 00 00 ?? ?? ?? ?? 81 44 24 20 39 2d 8e 45 81 84 24 14 02 00 00 ?? ?? ?? ?? 81 ac 24 88 00 00 00 ?? ?? ?? ?? 81 ac 24 e0 01 00 00 ?? ?? ?? ?? b8 ?? ?? ?? ?? f7 a4 24 e0 00 00 00 8b 84 24 e0 00 00 00 81 84 24 9c 02 00 00 ?? ?? ?? ?? 81 6c 24 5c ?? ?? ?? ?? 81 84 24 44 02 00 00 ?? ?? ?? ?? 30 0c 37 83 ee 01 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_AYA_2147782880_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.AYA"
        threat_id = "2147782880"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c0 83 c2 01 8b c0 a1 ?? ?? ?? ?? 8b c0 8b ca 8b c0 8b d0 33 d1 8b c2 c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Obfuscator_LBF_2147954990_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Obfuscator.LBF"
        threat_id = "2147954990"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 43 f7 31 ?? 8d ?? ?? ?? 00 00 0f af d6 01 ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

