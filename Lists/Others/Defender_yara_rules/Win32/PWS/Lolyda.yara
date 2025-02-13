rule PWS_Win32_Lolyda_C_2147599187_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.C"
        threat_id = "2147599187"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "73"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 4c 4f 41 44 45 52 00 4c 59 4c 4f 41 44 45 52 2e 45 58 45 00 4d 42 45 52 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 22 25 73 22 00 30 34 33 30}  //weight: 10, accuracy: High
        $x_10_3 = "MZKERNEL32.DLL" ascii //weight: 10
        $x_10_4 = "SizeofResource" ascii //weight: 10
        $x_10_5 = "FindResourceA" ascii //weight: 10
        $x_10_6 = "RtlZeroMemory" ascii //weight: 10
        $x_10_7 = "WriteFile" ascii //weight: 10
        $x_1_8 = "LYMANGR.DLL" ascii //weight: 1
        $x_1_9 = {00 4d 48 4c 59 00}  //weight: 1, accuracy: High
        $x_1_10 = "MSDEG32.DLL" ascii //weight: 1
        $x_1_11 = "REGKEY.HIV" ascii //weight: 1
        $x_3_12 = {55 8b ec 81 c4 a4 fb ff ff eb 21 6a 00 6a 00 6a 00 6a 00 e8 0e 01 00 00 6a 00 6a 00 6a 00 6a 00 e8 01 01 00 00 56 57 e8 72 01 00 00 e8 bd fe ff ff 68 04 01 00 00 8d 85 b8 fc ff ff 50 6a 00 e8 18 01 00 00 68 00 02 00 00 8d 85 bc fd ff ff 50 e8 2b 01 00 00 68 00 30 40 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_D_2147599188_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.D"
        threat_id = "2147599188"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetOpenUrl" ascii //weight: 1
        $x_1_2 = "post2007" ascii //weight: 1
        $x_1_3 = "%s?server=%s&gameid=%s&pass=%s&pin=%s&wupin=%s&role=%s&equ=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_E_2147599190_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.E"
        threat_id = "2147599190"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 8d 85 fc fe ff ff 50 e8 ?? ?? 00 00 0b c0 0f 85 ?? 01 00 00 ff b5 e0 fe ff ff 6a 08 e8 ?? ?? 00 00 89 85 a4 fc ff ff 0b c0 0f 84 04 00 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_F_2147599191_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.F"
        threat_id = "2147599191"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 74 27 33 ff 81 3c 37 23 fe 4e f7 75 11 83 7c 37 08 00 74 0a 81 7c 37 0c 84 14 1a af 74 2c 06 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_H_2147605342_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.H"
        threat_id = "2147605342"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 e8 fe ff ff 50 68 ?? ?? ?? ?? e8 ?? ?? 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 75 fc e8 ?? ?? 00 00 0b c0 74 73 89 45 f8 50 ff 75 fc e8 ?? ?? 00 00 89 45 f0 ff 75 f8 ff 75 fc e8 ?? ?? 00 00 0b c0 74 55 50 e8 ?? ?? 00 00 0b c0 74 4b 89 45 ec 6a 00 6a 20 6a 02 6a 00 6a 00 68 00 00 00 40 68 ?? ?? ?? ?? e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_I_2147607583_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.I"
        threat_id = "2147607583"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0b c0 74 4c 33 d2 eb 40 8b 7d f4 03 fa 81 3f 23 fe 4e f7 75 30 83 7f 08 00 74 2a 81 7f 0c 84 14 1a af}  //weight: 5, accuracy: High
        $x_1_2 = "?server=%s&gameid=%s&pass=%s&pin=%s&wupin=%s&role=%s&equ=" ascii //weight: 1
        $x_1_3 = "Forthgoner" ascii //weight: 1
        $x_1_4 = "\\Device\\devHBKernel" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_J_2147607777_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.J"
        threat_id = "2147607777"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c6 45 ff e9 ff 15 ?? ?? 00 10 8b 75 0c 8b d8 8d 45 d0}  //weight: 4, accuracy: Low
        $x_4_2 = {74 71 83 7d f8 01 75 6b 8d 45 f8 50 8d 46 08 6a 04 50 8b 06 40 50 53 ff d7 85 c0 74 56 83 7d f8 04 75 50 8d 45 f4 8b 3d ?? ?? 00 10 50 8d 45 ff 6a 01}  //weight: 4, accuracy: Low
        $x_1_3 = "?server=%s&gameid=%s&pass=%s&pin=%s&wupin=%s&role=%s&equ=" ascii //weight: 1
        $x_1_4 = "Forthgoner" ascii //weight: 1
        $x_1_5 = ".cn/verify/postly.asp" ascii //weight: 1
        $x_1_6 = "\\userdata\\currentserver.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_K_2147611395_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.K"
        threat_id = "2147611395"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d 20 0b e0 22 00 75 ?? 83 7d 14 04 72 06 83 7d 1c 04 73 08}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Device\\devHBKernel32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_N_2147611823_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.N"
        threat_id = "2147611823"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 90 01 00 00 68 58 02 00 00 6a 64 6a 64 68 00 00 cf 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 0b e0 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 42 49 6e 6a 65 63 74 33 32 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 42 4b 65 72 6e 65 6c 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Lolyda_O_2147611829_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.O"
        threat_id = "2147611829"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 9c ff b6 24 1a 00 00 8f 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 01 00 00 00 9d 61 90}  //weight: 1, accuracy: Low
        $x_1_2 = {80 7e 01 31 72 06 80 7e 01 38 76 02 eb 58 80 7e 02 41 72 06 80 7e 02 4a 76 02 eb 4a}  //weight: 1, accuracy: High
        $x_1_3 = "account=%s&server=%s&pswimagecount=%d&pswimageindex=%d&pswimageda" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_P_2147611830_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.P"
        threat_id = "2147611830"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7c 4c 8b 0d ?? ?? ?? ?? 83 f9 01 7c 41 81 f9 96 00 00 00 7f 39 56 8b 35 ?? ?? ?? ?? 6a 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "server=%s&account=%s&password1=%s&password2=%s&levels=%s&cash=%s&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_S_2147612701_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.S"
        threat_id = "2147612701"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 72 76 69 63 65 52 6f 75 74 65 45 78 80 00 [0-128] 48 42 [0-8] 2e 64 6c 6c [0-128] 53 74 61 72 74 53 65 72 76 69 63 65 45 78 00 53 74 6f 70 53 65 72 76 69 63 65 45 78}  //weight: 1, accuracy: Low
        $x_1_2 = "account=%s&password" ascii //weight: 1
        $x_1_3 = {00 25 73 25 73 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_X_2147616914_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.X"
        threat_id = "2147616914"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 83 e3 05 83 fb 05 75 ?? 83 c0 03 89 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 83 e3 09 83 fb 09 75 ?? 83 c0 25 89 45 f0 8b 45 f0}  //weight: 1, accuracy: Low
        $x_2_3 = {83 fb 47 72 30 83 fb 49 76 22 83 fb 4a 76 26 83 fb 4d 76 15 83 fb 4e 76 1c 83 fb 51 76 08 83 fb 52 75 12}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_T_2147617421_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.T"
        threat_id = "2147617421"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 48 42 53 65 72 76 69 63 65 33 32 00 53 79 73 74 65 6d 2e 65 78 65}  //weight: 10, accuracy: High
        $x_4_2 = {53 74 6f 70 53 65 72 76 69 63 65 45 78 00 5c 00 53 74 61 72 74 53 65 72 76 69 63 65 45 78}  //weight: 4, accuracy: High
        $x_4_3 = "HBInject32" ascii //weight: 4
        $x_4_4 = "AppInit_DLLs" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_Y_2147618162_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.Y"
        threat_id = "2147618162"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc b0 e9 aa 8b 45 08 2b 45 fc 83 e8 05 ab}  //weight: 1, accuracy: High
        $x_1_2 = {50 6a 0b 8d 85 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 58 0b c0 74 4e}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 4a ff 75 fc e8 ?? ?? ?? ?? 6a 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_V_2147618420_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.V"
        threat_id = "2147618420"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 72 76 69 63 65 52 6f 75 74 65 45 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 74 61 72 74 53 65 72 76 69 63 65 45 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 74 6f 70 53 65 72 76 69 63 65 45 78 00}  //weight: 1, accuracy: High
        $x_1_4 = "levels=%s&cash=%s" ascii //weight: 1
        $x_1_5 = {66 ad b9 03 00 00 00 ba 3d 00 00 00 83 6d fc 02 86 c4 c1 c0 10 86 c4 50 25 00 00 00 fc c1 c0 06 8a 80 ?? ?? ?? ?? aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_W_2147618488_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.W"
        threat_id = "2147618488"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 fc 50 6a 04 6a 05 ff 75 08 6a ff e8 ?? ?? ?? 00 6a 05 ff 75 0c ff 75 08 e8 ?? ?? ?? 00 83 c4 0c 6a 00 ff 75 fc 6a 05 ff 75 08 6a ff e8 ?? ?? ?? 00 b8 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {86 c4 c1 c0 10 86 c4 50 25 00 00 00 fc c1 c0 06 8a 80 ?? ?? ?? 10 aa 58 c1 e0 06}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 0c 8b 45 10 03 45 e8 c6 00 e9 8b 45 0c 03 45 e8 8b 55 10 03 55 e8 2b c2 8b d0 83 ea 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Lolyda_A_2147618896_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.gen!A"
        threat_id = "2147618896"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {86 c4 c1 c0 10 86 c4 50 25 00 00 00 fc c1 c0 06 8a 80 ?? ?? ?? 10 aa 58 c1 e0 06}  //weight: 6, accuracy: Low
        $x_1_2 = "&account=%s" ascii //weight: 1
        $x_1_3 = "&password" ascii //weight: 1
        $x_1_4 = "post.asp" ascii //weight: 1
        $x_1_5 = "&cash=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_Z_2147618912_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.Z"
        threat_id = "2147618912"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InternetOpenA" ascii //weight: 1
        $x_1_2 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 52 6f 75 74 65 45 78}  //weight: 1, accuracy: High
        $x_1_3 = {61 63 63 6f 75 6e 74 3d 25 73 26 70 61 73 73 77 6f 72 64 ?? 3d 25 73 26 70 61 73 73 77 6f 72 64 ?? 3d 25 73 26 70 61 73 73 65 64}  //weight: 1, accuracy: Low
        $x_1_4 = "&server=%s&inputsource=%s&levels=%d" ascii //weight: 1
        $x_1_5 = {25 73 3f 25 73 00 46 6f 72 74 68 67 6f 6e 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Lolyda_AJ_2147620096_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AJ"
        threat_id = "2147620096"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 4a ff ff ff ?? e8 ?? ?? ff ff 8d 45 ?? e8 ?? ?? ff ff 6a 00 68 ?? ?? ?? ?? 68 b6 00 00 00}  //weight: 3, accuracy: Low
        $x_3_2 = {c6 43 04 6f c6 43 05 72 c6 43 06 65 c6 43 07 72 c6 43 08 2e c6 43 09 65 c6 43 0a 78 c6 43 0b 65}  //weight: 3, accuracy: High
        $x_1_3 = {44 6f 50 61 63 74 68 2e 44 6f 4d 61 6b 65 53 68 65 6c 6c 43 6f 64 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 6f 50 61 63 74 68 2e 61 73 6d 63 6f 64 65 5b 30 5d 3c 3e 30 00}  //weight: 1, accuracy: High
        $x_1_5 = {07 00 00 00 77 61 69 74 6d 62 68 00}  //weight: 1, accuracy: High
        $x_1_6 = {07 00 00 00 73 75 63 63 6d 62 68 00}  //weight: 1, accuracy: High
        $x_1_7 = {09 00 00 00 6f 66 66 6c 69 6e 65 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_AA_2147621468_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AA"
        threat_id = "2147621468"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 57 56 8b 7d 08 8b 75 0c ac 0a c0 74 03 32 45 10 aa 80 3e 00 75 06 80 7e 01 00 74 02 eb ea 5e 5f c9 c2 0c 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 57 56 51 8b 7d 08 8b 75 0c 8b 4d 10 0b c9 74 07 ac 32 45 14 aa e2 f9 59 5e 5f c9 c2 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_AB_2147622136_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AB"
        threat_id = "2147622136"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 08 80 f2 9a 88 11 41 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {8a 8c 05 00 ff ff ff 80 c1 0a 88 8c 05 00 fe ff ff 40 3b c7 7c ea}  //weight: 1, accuracy: High
        $x_1_3 = "&zone=%s&server=%s&name=%s&pass=%s&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_AC_2147622353_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AC"
        threat_id = "2147622353"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 f2 9a 88 10 40 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 08 80 f2 9a 88 11 41 4e 75 f4}  //weight: 1, accuracy: High
        $x_1_3 = {8b 48 fc 8b 30 2b ce 83 e9 05 89 48 f8}  //weight: 1, accuracy: High
        $x_1_4 = {8b 48 fc 2b 08 83 e9 05 89 48 f8}  //weight: 1, accuracy: High
        $x_1_5 = {74 04 2c 05 eb 02 2c 0a 88 84 0d}  //weight: 1, accuracy: High
        $x_1_6 = {66 6f 6e 74 73 5c 67 (74 68|62 6d)}  //weight: 1, accuracy: Low
        $x_5_7 = "&zone=%s&server=%s&name=%s&pass" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_AE_2147624115_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AE"
        threat_id = "2147624115"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zone=%s&" ascii //weight: 1
        $x_1_2 = "name=%s&" ascii //weight: 1
        $x_1_3 = "server=%s&" ascii //weight: 1
        $x_1_4 = "fonts\\gth" ascii //weight: 1
        $x_1_5 = {c6 06 e9 2b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Lolyda_AF_2147624189_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AF"
        threat_id = "2147624189"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 06 e9 2b c6 6a 01 83 e8 05 89 46 01 58}  //weight: 1, accuracy: High
        $x_1_2 = {4e 75 f4 5e 09 00 8a 14 ?? 80 ea ?? 88}  //weight: 1, accuracy: Low
        $x_1_3 = {66 6f 6e 74 73 5c 67 74 68 05 00 2e (66|74)}  //weight: 1, accuracy: Low
        $x_1_4 = "Acc@&#ep@&#t:@&#*/*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Lolyda_AG_2147624234_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AG"
        threat_id = "2147624234"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 6f 6e 74 73 5c 67 74 68 05 00 2e 66 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "sysgth.dll" ascii //weight: 1
        $x_1_3 = "mmsfc1.dll" ascii //weight: 1
        $x_2_4 = {85 f6 74 34 2b c3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb c6}  //weight: 2, accuracy: Low
        $x_2_5 = {b9 89 02 00 00 33 c0 8d bd ?? ?? ff ff f3 ab}  //weight: 2, accuracy: Low
        $x_2_6 = {8a 14 08 80 ea ?? 88 11 41 4e 75 f4 5e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_AK_2147624365_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AK"
        threat_id = "2147624365"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6e 66 72 6d 62 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_2 = "succmb" ascii //weight: 1
        $x_1_3 = {26 6d 62 68 3d c3 dc 00}  //weight: 1, accuracy: High
        $x_2_4 = {8a 04 33 55 04 ?? 34 ?? 2c ?? 47 88 06 46 ff 15 ?? ?? ?? ?? 3b f8 7c e8}  //weight: 2, accuracy: Low
        $x_1_5 = {2b de c6 06 e9 [0-2] 8d 83 ?? ?? ?? ?? [0-1] 8b c8 8b d0 c1 e9 08 88 46 01 88 4e 02}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 06 e9 2b c6 [0-2] 83 e8 05 89 46 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_AL_2147624457_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AL"
        threat_id = "2147624457"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dxcyyshaha" ascii //weight: 1
        $x_1_2 = {53 79 73 44 69 72 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 4c 50 4b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 04 c0 00 08 56 89 5d fc ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_AM_2147624588_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AM"
        threat_id = "2147624588"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InstallService" ascii //weight: 1
        $x_1_2 = "InternetConnectA" ascii //weight: 1
        $x_1_3 = {00 2f 66 6c 61 73 68 2e 61 73 70}  //weight: 1, accuracy: High
        $x_1_4 = {00 2f 47 65 74 67 69 66 2e 61 73 70}  //weight: 1, accuracy: High
        $x_1_5 = {00 69 73 6f 6e 6c 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 41 63 63 65 70 74 3a 20 2a 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_7 = "n=up&" ascii //weight: 1
        $x_1_8 = "&zt=" ascii //weight: 1
        $x_1_9 = "&js=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule PWS_Win32_Lolyda_AM_2147624588_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AM"
        threat_id = "2147624588"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 33 55 2c 05 47 88 06 46 ff 15 ?? ?? ?? ?? 3b f8 7c (e7|ec)}  //weight: 2, accuracy: Low
        $x_2_2 = {74 41 81 bd ?? ?? ff ff 40 4b 4c 00 0f 82 ?? ?? 00 00 66 8b 85 ?? ?? ff ff 66 3d 1e 00 0f 86 ?? ?? 00 00 66 3d 3c 00 0f 83}  //weight: 2, accuracy: Low
        $x_2_3 = {b8 e9 a2 8b 2e 8a 0c 3e 57 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 8d 0c 52 c1 e1 03 2b ca 03 d9 46 ff d5 3b f0 7c d9}  //weight: 2, accuracy: High
        $x_2_4 = {2b de c6 06 e9 [0-2] 8d 83 ?? ?? ?? ?? [0-1] 8b c8 8b d0 c1 e9 08 88 46 01 88 4e 02}  //weight: 2, accuracy: Low
        $x_1_5 = {61 63 74 69 6f 6e 3d (75 70|6f 6b) 26 75 3d 00}  //weight: 1, accuracy: Low
        $x_1_6 = "action=update&u=" ascii //weight: 1
        $x_1_7 = {26 7a 74 3d 6f 66 66 6c 69 6e 65 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_8 = {26 7a 74 3d 77 61 69 74 6d 62 68 00}  //weight: 1, accuracy: High
        $x_1_9 = {63 6a 78 73 6a 61 73 64 66 67 68 00}  //weight: 1, accuracy: High
        $x_1_10 = {6a 78 73 6a 71 77 65 72 74 79 00}  //weight: 1, accuracy: High
        $x_1_11 = "norespond" ascii //weight: 1
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

rule PWS_Win32_Lolyda_AN_2147624834_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AN"
        threat_id = "2147624834"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 33 55 04 ?? 34 ?? 2c ?? 47 88 06 46 ff 15 ?? ?? ?? ?? 3b f8 7c e8}  //weight: 1, accuracy: Low
        $x_2_2 = {2b de c6 06 e9 [0-2] 8d 83 ?? ?? ?? ?? [0-1] 8b c8 8b d0 c1 e9 08 88 46 01 88 4e 02}  //weight: 2, accuracy: Low
        $x_1_3 = {68 d0 07 00 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 85 c0 74 ec a0 ?? ?? ?? ?? 84 c0 74 e3 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_AO_2147625843_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AO"
        threat_id = "2147625843"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4b c6 44 24 ?? 56 c6 44 24 ?? 4d c6 44 24 ?? 6f c6 44 24 ?? 6e c6 44 24 ?? 58 c6 44 24 ?? 50 c6 44 24 ?? 2e}  //weight: 2, accuracy: Low
        $x_2_2 = {68 ec fe ff ff 56 ff d7 8d 54 24 ?? 6a 00 52 8d 84 24 ?? ?? 00 00 68 14 01 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 04 33 04 ?? 34 ?? 2c ?? 88 06 [0-5] 47 55 46 ff 15 ?? ?? ?? ?? 3b f8 7c}  //weight: 2, accuracy: Low
        $x_1_4 = {61 76 70 2e 65 78 65 00 65 6c 65 6d 65 6e 74 5c}  //weight: 1, accuracy: High
        $x_1_5 = "ZPWUpdatePack\\DefaultIcon" ascii //weight: 1
        $x_1_6 = {26 7a 74 3d 73 75 63 63 6d 62 68 00 61 63 74 69 6f 6e 3d 75 70 26 75 3d}  //weight: 1, accuracy: High
        $x_1_7 = "/wmrmb.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_AP_2147625849_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AP"
        threat_id = "2147625849"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TenQQAccount.dll" ascii //weight: 1
        $x_1_2 = "Content-Type: image/pjpeg" ascii //weight: 1
        $x_1_3 = "name=\"submitted\"" ascii //weight: 1
        $x_1_4 = "\\DNF\\Release\\RSDFL.pdb" ascii //weight: 1
        $x_1_5 = "MiniSniffer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_AQ_2147625882_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AQ"
        threat_id = "2147625882"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 07 a3 ?? ?? ?? ?? 61 36}  //weight: 2, accuracy: Low
        $x_2_2 = {61 3e 8b 89 c4 03 00 00 ff 25}  //weight: 2, accuracy: High
        $x_1_3 = {2b c6 83 e8 05 c6 06 e9 89 46 01}  //weight: 1, accuracy: High
        $x_1_4 = {83 c0 09 89 45 0c eb 03 8b 45 0c 8b 48 fc 2b 08 83 e9 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_AS_2147626921_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AS"
        threat_id = "2147626921"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b de 8d 83 ?? ?? ?? ?? 8b c8 c6 06 e9 88 46 01 8b d0 c1 e9 08 88 4e 02}  //weight: 2, accuracy: Low
        $x_1_2 = {26 6d 62 6d 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 7a 74 3d 77 61 69 74 6d 62 68 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 63 74 69 6f 6e 3d 75 70 26 7a 74 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_AT_2147627867_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AT"
        threat_id = "2147627867"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ff 8b 44 24 10 8a 04 02 32 01 34 ?? 46 3b 74 24 14 88 01 7c dd}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 f8 e9 03 50 14 8d 45 f8 50 51 2b d1}  //weight: 1, accuracy: High
        $x_1_3 = {3f 41 3d 25 73 26 75 3d 25 73 26 63 3d 25 73 26 6d 62 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "&P=%s&PIN=%s&" ascii //weight: 1
        $x_1_5 = {20 5a c7 1a 9f 43 72 ca 37 33 77 c7 e0 c5 43 fb ff fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Lolyda_AU_2147629105_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AU"
        threat_id = "2147629105"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 da 32 1e 80 f3}  //weight: 2, accuracy: High
        $x_2_2 = {68 14 05 00 00 8d}  //weight: 2, accuracy: High
        $x_2_3 = {2b c6 c6 86 ?? ?? 00 00 e8 2d ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {33 c8 8b 06 81 f1 ?? ?? 00 00 89 (4d|8d)}  //weight: 2, accuracy: Low
        $x_2_5 = {25 73 3f 61 63 74 3d 26 64 31 30 3d 25 73 26 64 38 30 3d 25 64 00}  //weight: 2, accuracy: High
        $x_1_6 = {63 6d 64 20 2f 63 20 25 73 20 25 73 20 49 6e 73 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 73 7e 25 30 36 78 2e 7e 7e 7e 00}  //weight: 1, accuracy: High
        $x_1_8 = {25 73 7e 7e 25 30 36 78 2e 7e 7e 7e 00}  //weight: 1, accuracy: High
        $x_1_9 = "?d10=%s&d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_AW_2147629677_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AW"
        threat_id = "2147629677"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {78 38 42 ec 00 53 65 74 57 69 6e 64 6f 77 00}  //weight: 2, accuracy: High
        $x_1_2 = "ss12D000dll.dll" ascii //weight: 1
        $x_1_3 = {75 1f 8b 7d fc 8b 55 08 8b df 2b d3 83 ea 05 89 55 f8 b0 e9 aa 8d 75 f8 b9 04 00 00 00 f3 a4}  //weight: 1, accuracy: High
        $x_1_4 = {eb 08 eb 06 aa e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_AX_2147631774_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AX"
        threat_id = "2147631774"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 2c 50 ff 15 ?? ?? ?? ?? 83 c4 08 40 6a 00 50 6a 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 00 20 00 00 2b c3 6a 00 8d 0c 2b 50 51 52 ff 15 ?? ?? ?? ?? 85 c0 7e 45}  //weight: 1, accuracy: Low
        $x_1_3 = {42 4e 50 53 44 6c 6c 2e 64 6c 6c 00 43 6f 47 65 74 43 6f 6d 43 61 74 61 6c 6f 67 00 73 72 70 63 73 73 2e 43 6f 47 65 74 43 6f 6d 43 61 74 61 6c 6f 67 00 47 65 74 52 50 43 53 53 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s~%06x.~~~" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Lolyda_AY_2147632060_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AY"
        threat_id = "2147632060"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e6 19 c1 e8 07 0b f0 0f be c1 8a 4a 01 03 c6 42 84 c9 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = "mibao.php?action=put&u=%s" ascii //weight: 1
        $x_1_3 = "?s=%s&u=%s&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_AZ_2147632512_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.AZ"
        threat_id = "2147632512"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {be 5a 00 00 00 6a 01 ff ?? 8d 54 24 ?? 66 89 74 24 ?? 52 [0-8] 85 c0 74 47 8d 44 24 ?? 50 [0-6] 83 f8 02 75}  //weight: 2, accuracy: Low
        $x_2_2 = {81 c6 ff ff 00 00 66 83 fe 44 73 ?? a1 ?? ?? ?? ?? 85 c0 74}  //weight: 2, accuracy: Low
        $x_1_3 = "UR.$LD.$ow.$nloa.$dToFileA" ascii //weight: 1
        $x_1_4 = {64 6f 6d 61 69 6e 5c 75 73 65 72 6e 61 6d 65 00 70 61 73 73 77 6f 72 64}  //weight: 1, accuracy: High
        $x_1_5 = "%08x.~tp" ascii //weight: 1
        $x_1_6 = {78 78 78 00 6d 61 72 6b}  //weight: 1, accuracy: High
        $x_1_7 = "regs.$vr32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_BA_2147633533_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.BA"
        threat_id = "2147633533"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 11 7c 0f 8a 14 01 80 f2 ?? 80 c2 ?? 88 14 01 48 79 f1}  //weight: 1, accuracy: Low
        $x_1_2 = {25 00 6c 00 73 00 25 00 68 00 73 00 5f 00 2e 00 62 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c6 00 e8 2b 4c 24 0c 83 e9 05 89 48 01}  //weight: 1, accuracy: High
        $x_1_4 = {25 68 73 3f 61 63 74 3d 26 64 31 30 3d 25 68 73 26 64 38 30 3d 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Lolyda_BB_2147636400_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.BB"
        threat_id = "2147636400"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 02 00 17 00 ?? c7 45 fc 0e 01 01 00 89 ?? 08 89 ?? f8 ff 15 ?? ?? ?? ?? 85 c0 74 09 f6 45 08 20 74 03 6a 01}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 89 02 00 00 33 c0 8d bd}  //weight: 1, accuracy: High
        $x_1_3 = "%s~~%06x.~~~" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_BC_2147636766_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.BC"
        threat_id = "2147636766"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 26 85 d9 ed 93 e1 33 6e be 01 b6 03 14 d8 f8}  //weight: 1, accuracy: High
        $x_1_2 = {32 d0 88 14 31 8a c2 8a 14 1f 2a c2 47 83 ff 04 88 04 31 72 02 33 ff 41 3b cd 72 de}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 83 ea 05 ?? ?? 89 56 01}  //weight: 1, accuracy: Low
        $x_1_4 = "mibao.asp?act=&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Lolyda_BD_2147638821_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.BD"
        threat_id = "2147638821"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 65 6c 2e 73 70 72 [0-5] 42 74 6e 4b 65 79 [0-5] 25 73 3f 75 3d 25 73 26 73 6c 3d 25 73 26 73 68 61 3d 25 73}  //weight: 2, accuracy: Low
        $x_1_2 = "%s/mibao.php?action=getpos&u=%s&st=%s" ascii //weight: 1
        $x_1_3 = "%08X_gmh_mutex" ascii //weight: 1
        $x_1_4 = "%s?u=%s&sl=%s&sha=%s" ascii //weight: 1
        $x_1_5 = "user\\uicommon.ini" ascii //weight: 1
        $x_3_6 = {56 50 c6 45 ?? 3d c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 26 c6 45 ?? 70 c6 45 ?? 3d c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 26 c6 45 ?? 72 c6 45 ?? 3d}  //weight: 3, accuracy: Low
        $x_2_7 = {be 80 00 00 00 8d 85 ?? ?? ?? ?? 56 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? c6 45 ?? 2e c6 45 ?? 5c c6 45 ?? 75 c6 45 ?? 73 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 5c c6 45 ?? 75 c6 45 ?? 69 c6 45 ?? 63 c6 45 ?? 6f c6 45 ?? 6d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_BE_2147640964_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.BE"
        threat_id = "2147640964"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 01 80 c2 07 80 f2 05 80 ea 07 88 10 40 4e 75 ee}  //weight: 2, accuracy: High
        $x_1_2 = "ac=up&zzz=exk&dd2=" ascii //weight: 1
        $x_1_3 = "ac=up&zzz=ol&dd2=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_BF_2147643712_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.BF"
        threat_id = "2147643712"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {79 75 63 6f 6d 72 65 73 2e 64 6c 6c 00 00 00 00 79 75 6d 69 64 69 6d 61 70 2e 64 6c 6c 00 00 00 79 75 6b 73 75 73 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 50 8d 45 cc 6a 15 50 ff 75 e8 ff d7 6a 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Lolyda_BF_2147643712_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.BF"
        threat_id = "2147643712"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 43 01 9c c6 43 02 e8 c6 43 07 9d c6 43 08 61}  //weight: 2, accuracy: High
        $x_1_2 = {73 20 80 b9 ?? ?? ?? ?? 5f 74 10 41 56 89 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 eb dd c6 81 ?? ?? ?? ?? 40}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 0e 83 c3 36 51 50 66 c7 45 ?? 42 4d 89 5d ?? 66 89 7d ?? 66 89 7d ?? c7 45 ?? 36 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_BI_2147651460_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.BI"
        threat_id = "2147651460"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\secivreS\\teSlortnoCtnerruC\\METSYS" ascii //weight: 10
        $x_10_2 = "Fuck You By QQ:123**321" ascii //weight: 10
        $x_1_3 = "DragonNest.exe" ascii //weight: 1
        $x_1_4 = "tw2.exe" ascii //weight: 1
        $x_1_5 = "wow.exe" ascii //weight: 1
        $x_1_6 = "QQhxgame.exe" ascii //weight: 1
        $x_1_7 = "xy3.exe" ascii //weight: 1
        $x_1_8 = "xy2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_BJ_2147656168_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.BJ"
        threat_id = "2147656168"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 73 3f 61 63 74 3d 67 65 74 70 6f 73 26 64 ?? ?? 3d 25 73 26 70 6f 73 3d 26 64 ?? ?? 3d 25 64}  //weight: 10, accuracy: Low
        $x_1_2 = "AeliFypoC" ascii //weight: 1
        $x_1_3 = "swodniWmunE" ascii //weight: 1
        $x_1_4 = "MAC:%02X-%02X-" ascii //weight: 1
        $x_1_5 = "%s%d.dll" ascii //weight: 1
        $x_1_6 = {25 73 5c 25 73 5f 25 64 2e 62 6d 70 [0-5] 53 48 45 4c 4c 48 4f 4f 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Lolyda_BK_2147672516_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lolyda.BK"
        threat_id = "2147672516"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolyda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PropertyProtectWnd" ascii //weight: 2
        $x_3_2 = "..\\LastConfig.ini" ascii //weight: 3
        $x_3_3 = "Content-Disposition: form-data; name=\"file1\"; filename=\"%s\"" ascii //weight: 3
        $x_4_4 = "d00=%s&d01=%s&d30=%s&d32=%d&d40=%d&d10=%s&d11=%s&d12=%s&d21=%s&d50=%s" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

