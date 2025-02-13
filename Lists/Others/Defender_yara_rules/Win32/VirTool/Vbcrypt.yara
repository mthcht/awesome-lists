rule VirTool_Win32_Vbcrypt_A_2147606767_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.A"
        threat_id = "2147606767"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Select * from Win32_BaseBoard" wide //weight: 1
        $x_1_2 = {55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 00 00 00 00 24 00 00 00 53 00 59 00 4e 00 54 00 48 00 45 00 54 00 49 00 43 00 55 00 53 00 45 00 52 00 2e 00 46 00 47 00 56 00 53 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 4c 69 51 75 69 64 56 61 70 6f 75 72 53 74 75 62 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 72 79 70 74 6f 4d 61 69 6e 00 00 43 72 79 70 74 6f 52 43 34}  //weight: 1, accuracy: High
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule VirTool_Win32_Vbcrypt_B_2147606869_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.B"
        threat_id = "2147606869"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loadme\\m.vbp" wide //weight: 1
        $x_1_2 = "windir" wide //weight: 1
        $x_1_3 = {21 f9 71 02 78 b2 36 45 be 7c f0 47 d1 c6 37 25 00 00 00 00 00 00 01 00 00 00 30 32 30 34 33 30 50 72 6f 6a 65 63 74 31 00 30 2d 43 30 30 30}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 61 6c 6c 65 72 79 00 a0 00 00 50 72 6f 6a 65 63 74 31 00}  //weight: 1, accuracy: High
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_C_2147608082_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.C"
        threat_id = "2147608082"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 69 00 6e 00 64 00 69 00 72 00 00 00 00 00 1c 00 00 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 6d 00 65 00 6c 00 74 00 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "MZ signature not found!" wide //weight: 1
        $x_1_3 = "File load error" wide //weight: 1
        $x_1_4 = {6d 52 75 6e 50 45 00 00 6d 52 65 61 64 57 72 69 74 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_K_2147623540_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.K"
        threat_id = "2147623540"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Billar Crypter" wide //weight: 1
        $x_1_2 = {45 6e 63 72 69 70 74 61 41 50 49 00 72 75 6e 00 53 74 75 62 64 6f 73}  //weight: 1, accuracy: High
        $x_1_3 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_P_2147624590_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.P"
        threat_id = "2147624590"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c 2e 64 6c 6c [0-8] 53 68 65 6c 6c 45 78 65 63 75 74 65 [0-96] 2e 00 65 00 78 00 65 00 00 00 [0-8] 64 00 66 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\AY:\\code\\prog\\my\\myprog.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_Q_2147624594_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.Q"
        threat_id = "2147624594"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 [0-32] 5c 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 20 00 50 00 61 00 63 00 6b 00 61 00 67 00 65 00 5c 00 [0-48] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "This is by TrD and D4rkDays so bow to us biatch" wide //weight: 1
        $x_1_3 = "Hello anti virus companys, this is backdoor.win32.D4rkDays, Thank you for your attention" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_AD_2147628328_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.AD"
        threat_id = "2147628328"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60" ascii //weight: 1
        $x_1_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_3 = ":\\Documents and Settings\\Logan\\Desktop\\Crypter's\\Source's\\Novo Projeto\\Stub\\stub.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_D_2147636162_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.gen!D"
        threat_id = "2147636162"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 0e 5a 01 90}  //weight: 1, accuracy: High
        $x_1_2 = {0e 65 00 74 b4 6e 09 49 cd}  //weight: 1, accuracy: High
        $x_1_3 = {cd 46 21 74 54 65 68 53 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_CO_2147645147_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.CO"
        threat_id = "2147645147"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 4d 00 61 00 73 00 74 00 65 00 72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 53 00 6c 00 69 00 70 00 6e 00 6f 00 72 00 62 00 5c 00 53 00 6c 00 69 00 70 00 6e 00 6f 00 72 00 62 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 00 6c 00 69 00 70 00 6e 00 6f 00 72 00 62 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 4c 00 54 00 44 00 41 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {46 53 6c 69 70 6e 6f 72 62 00 00 00 4d 53 6c 69 70 6e 6f 72 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_CT_2147645926_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.CT"
        threat_id = "2147645926"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 95 70 ff ff ff 8d 45 dc 52 50 89 bd 78 ff ff ff 89 bd 70 ff ff ff ff d3 8b 4d 0c 50 8b 11 52}  //weight: 1, accuracy: High
        $x_1_2 = {c7 85 c0 fe ff ff ?? ?? 40 00 eb 0a c7 85 c0 fe ff ff ?? ?? 40 00 8b 95 c0 fe ff ff 8b 02 89 85 08 ff ff ff 8d 4d c0 51 8b 95 08 ff ff ff 8b 02 8b 8d 08 ff ff ff 51}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 14 0f bf 95 bc fe ff ff 85 d2 0f 84 55 1d 00 00 c7 45 fc 04 00 00 00 e8 ?? ?? ff ff c7 45 fc 05 00 00 00 83 3d ?? ?? 40 00 00 75 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_DG_2147647292_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.DG"
        threat_id = "2147647292"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 b8 8d 55 d0 52 50 8b 08 8b f0 ff 51 58 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {ff d3 8b d0 8d 4d cc ff d7 8b 55 d0 50 52 ff d3 8b d0 8d 4d c8 ff d7 50 68}  //weight: 1, accuracy: High
        $x_1_3 = {8d 55 dc 52 ff d6 8d 45 d8 50 ff d6 8d 4d c0 8d 55 c4 51 8d 45 c8 52 8d 4d cc 50 8d 55 d0 51 8d 45 d4 52 50 6a 06 ff}  //weight: 1, accuracy: High
        $x_1_4 = {8b d0 8d 4d cc ff d7 8b 4d d0 50 51 ff d3 8b d0 8d 4d c8 ff d7 50 68 68 1b 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_DM_2147647769_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.DM"
        threat_id = "2147647769"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 95 88 fe ff ff 52 8d 85 a8 fe ff ff 50 c7 85 c0 fe ff ff 01 00 00 00 c7 85 b8 fe ff ff 02 00 00 00 c7 85 88 fe ff ff 08 40 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8d 8d d0 f9 ff ff ff d6 8d 8d cc f9 ff ff ff d6 8d 8d c8 f9 ff ff ff d6 8d 8d c4 f9 ff ff ff d6 8d 8d c0 f9 ff ff ff d6 c3}  //weight: 1, accuracy: High
        $x_1_3 = {8b 85 8c f7 ff ff c7 85 7c f7 ff ff 03 40 00 00 8b 48 14 c1 e1 04}  //weight: 1, accuracy: High
        $x_1_4 = {50 6a 10 68 80 08 00 00 ff d3 83 c4 1c b8 02 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Vbcrypt_H_2147647876_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.gen!H"
        threat_id = "2147647876"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\DarkEye\\Darkeye\\VB6.OLB" ascii //weight: 1
        $x_1_2 = {e9 e9 e9 e9 cc cc cc cc cc cc cc cc cc cc cc cc 9e 9e 9e 9e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_DN_2147647898_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.DN"
        threat_id = "2147647898"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 85 64 ff ff ff 89 45 ?? 8b 45 ?? 3b 85 60 ff ff ff 7f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 0c ff 30 f7 db 1b db f7 db e8 ?? ?? ff ff f7 d8 1b c0 f7 d8 85 d8}  //weight: 1, accuracy: Low
        $x_1_3 = {56 8d 45 e4 89 45 c8 6a 40 8d 45 c0 50 8d 45 d4 50 c7 45 c0 11 60 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {89 45 e4 56 8d 45 d8 89 45 bc 68 80 00 00 00 8d 45 b4 50 8d 45 c8 50}  //weight: 1, accuracy: High
        $x_1_5 = {57 6a 09 6a 01 57 8d 85 54 ff ff ff 50 6a 10 68 80 08 00 00 e8}  //weight: 1, accuracy: High
        $x_1_6 = {53 68 aa 00 00 00 6a 01 53 8d 45 b0 50 6a 10 68 80 08 00 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_7 = {83 c4 14 eb 52 b8 ?? ?? ?? ?? f7 d8 b9 ?? ?? ?? ?? 83 d1 00 f7 d9 89 ?? ?? ff ff ff 89 ?? ?? ff ff ff 6a 00 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Vbcrypt_DP_2147648385_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.DP"
        threat_id = "2147648385"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8b 00 ff 75 08 ff 50 04 66 c7 45 e0 ?? 00 66 c7 45 e4 01 00 66 c7 45 e8 01 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc 32 00 00 00 c7 85 ?? ff ff ff 16 00 00 00 c7 85 ?? ff ff ff 02 00 00 00 c7 85 ?? ff ff ff 2c 00 00 00 c7 85 ?? ff ff ff 02 00 00 00 8d 45 b0 50}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 d8 fe ff ff 89 85 ?? ff ff ff c7 85 ?? ff ff ff 08 20 00 00 8d 95 ?? ff ff ff b9}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 fc 3f 00 00 00 c7 85 ?? ff ff ff 05 00 00 00 c7 85 ?? ff ff ff 02 00 00 00 c7 85 ?? ff ff ff 5f 00 00 00 c7 85 ?? ff ff ff 02 00 00 00 8d 45 b0 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Vbcrypt_DS_2147648807_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.DS"
        threat_id = "2147648807"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 85 b4 fe ff ff c7 85 ac fe ff ff 03 00 00 00 8b 45 c8 89 85 e8 fd ff ff 83 65 c8 00 8b 85 e8 fd ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {83 a5 e4 fe ff ff 00 8b 85 e0 fe ff ff 89 85 b0 fd ff ff 83 a5 e0 fe ff ff 00 8b 85 dc fe ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {83 a5 94 fe ff ff 00 c7 85 8c fe ff ff 02 00 00 00 83 a5 a4 fe ff ff 00 c7 85 9c fe ff ff 02 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {83 65 c8 00 8b 85 ec fd ff ff 89 85 c4 fe ff ff c7 85 bc fe ff ff 08 00 00 00 6a 04}  //weight: 1, accuracy: High
        $x_1_5 = {8b 7d 08 8d 4d 94 8b 07 51 8d 4d e8 51 68 c2 8c 10 c5 ff 35 ?? ?? ?? 00 57 ff 50 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_Vbcrypt_EA_2147650907_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.EA"
        threat_id = "2147650907"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Devek" ascii //weight: 1
        $x_1_2 = "xwUnmapViewOfSection" ascii //weight: 1
        $x_1_3 = "fileX" ascii //weight: 1
        $x_1_4 = "zreateProcessA" ascii //weight: 1
        $x_1_5 = "ztWriteVirtualMemory" ascii //weight: 1
        $x_1_6 = "__vbazopyBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_EB_2147651280_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.EB"
        threat_id = "2147651280"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff d6 8d 4d 80 6a 6c 51 ff d6 8d 95 60 ff ff ff 6a 58 52 ff d6 8d 85 40 ff ff ff 6a 78 50 ff d6 8d 8d 20 ff ff ff 6a 5a 51 ff d6 6a 71 8d 95 00 ff ff ff 52 ff d6 8d 85 e0 fe ff ff 6a 33 50 ff d6 8d 8d c0 fe ff ff 6a 69 51 ff d6 8d 95 a0 fe ff ff 6a 53 52 ff d6 8d 85 80 fe ff ff 6a 42 50 ff d6 8d 8d 60 fe ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_EC_2147651310_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.EC"
        threat_id = "2147651310"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 ec 54 53 56 57 89 65 f4 c7 45 f8 ?? ?? ?? ?? 8b 55 10 33 c0 8d 4d cc 89 45 e4 89 45 d0 89 45 cc 89 45 c8 89 45 b8 89 45 a8 e8 ?? ?? ?? ?? ff 75 cc e8 ?? ?? ?? ?? 85 c0 8b 45 0c 0f 84 f8 00 00 00 ff 30 e8 ?? ?? ?? ?? 8b c8 e8 ?? ?? ?? ?? 6a 01 89 45 a0 5f 6a 02 89 7d e8 5b 8b 45 e8 66 3b 45 a0}  //weight: 4, accuracy: Low
        $x_4_2 = {c7 45 fc 03 00 00 00 ba ?? ?? ?? ?? 8d 4d cc e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 cc 50 8d 45 b4 50 e8 d4 16 00 00}  //weight: 4, accuracy: Low
        $x_2_3 = "yy31396" wide //weight: 2
        $x_2_4 = "ab2k56" wide //weight: 2
        $x_1_5 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {52 65 67 57 72 69 74 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {77 69 6e 69 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Vbcrypt_EF_2147652918_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.EF"
        threat_id = "2147652918"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 51 c7 85 60 ff ff ff 03 80 00 00 ff 15 ?? ?? ?? ?? 66 85 c0 [0-16] 52 50 89 bd ?? ?? ?? ?? 89 bd ?? ?? ?? ?? ff d3 8b 4d 0c 50 8b 11 52 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 8b 4d ?? 8d 55 ?? 66 89 8d ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 52 8d 8d ?? ?? ?? ?? 50 51 89 bd ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 52 50 ff 15 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_EG_2147652963_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.EG"
        threat_id = "2147652963"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 15 04 10 40 00 50 ff 15 18 11 40 00 50 8d [0-96] c7 85 ?? ?? ff ff ?? 00 00 00 c7 85 ?? ?? ff ff 02 00 00 00 c7 85 [0-255] ff ?? 00 00 00 c7 85 [0-255] ff 02 00 00 00 6a 00 8d ?? ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {40 db e2 89 85 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? 00 7d 23 6a 40 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8d [0-32] ff 15 ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Vbcrypt_EH_2147652968_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vbcrypt.EH"
        threat_id = "2147652968"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 58 ff ff ff 08 00 00 00 c7 45 c0 01 00 00 00 89 75 b8 c7 85 78 ff ff ff 08 40 00 00 ff 15 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 6a 01 8d ?? ?? ?? ?? 8d ?? ?? ?? ?? c7 85 ?? ?? ff ff 01 00 00 00 89 b5 ?? ff ff ff ff 15 ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c4 10 66 3b f3 0f 8c ?? ?? ?? ?? 66 6b ff 40 66 8b 45 dc 0f 80 ?? ?? ?? ?? 66 03 fe 0f 80 ?? ?? ?? ?? 66 05 06 00 0f 80 ?? ?? ?? ?? 66 3d 08 00 89 45 dc 0f 8c ?? ?? ?? ?? 0f bf f7 8d 55 dc 66 2d 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

