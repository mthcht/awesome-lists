rule Backdoor_Win32_Lotok_RT_2147782058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.RT!MTB"
        threat_id = "2147782058"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3F0DShellex" ascii //weight: 1
        $x_1_2 = "http://47.103.219.77/svchost.exe" ascii //weight: 1
        $x_1_3 = "MFC42.DLL" ascii //weight: 1
        $x_1_4 = "GetModuleHandleA" ascii //weight: 1
        $x_1_5 = "GetStartupInfoA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_DG_2147827614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.DG!MTB"
        threat_id = "2147827614"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 d8 53 c6 45 d9 4f c6 45 da 46 c6 45 db 54 c6 45 dc 57 c6 45 dd 41 c6 45 de 52 c6 45 df 45 c6 45 e0 5c c6 45 e1 43 c6 45 e2 6c c6 45 e3 61 c6 45 e4 73 c6 45 e5 73 c6 45 e6 65 c6 45 e7 73 c6 45 e8 5c c6 45 e9 2e c6 45 ea 33 c6 45 eb 38 c6 45 ec 36 c6 45 ed 5c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_BT_2147832934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.BT!MTB"
        threat_id = "2147832934"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff 45 ec 8b 75 e8 8b 45 08 8b 4d 10 8b 55 ec 03 c6 6a 00 8a 0c 0a 30 08 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GHG_2147843941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GHG!MTB"
        threat_id = "2147843941"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 45 e4 55 c6 45 e5 52 c6 45 e6 4c c6 45 e7 44 c6 45 e8 6f c6 45 e9 77 c6 45 ea 6e c6 45 eb 6c c6 45 ec 6f c6 45 ed 61 c6 45 ee 64 c6 45 ef 54 c6 45 f0 6f c6 45 f1 46 c6 45 f2 69 c6 45 f3 6c c6 45 f4 65 c6 45 f5 41 c6 45 f6 00 8d 45 e4 50 8b 4d d8 51 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GHJ_2147847949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GHJ!MTB"
        threat_id = "2147847949"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b0 65 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 8d 44 24 ?? 50 51 c6 44 24 ?? 43 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 74 c6 44 24 ?? 45 c6 44 24 ?? 76 c6 44 24 ?? 6e c6 44 24 ?? 74 c6 44 24 ?? 41 88 5c 24 ?? ff d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GKH_2147849760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GKH!MTB"
        threat_id = "2147849760"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b0 65 b1 74 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 88 4c 24 ?? 88 4c 24 ?? 8b 0d ?? ?? ?? ?? 8d 44 24 ?? c6 44 24 ?? 43 50 51 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 45 c6 44 24 ?? 76 c6 44 24 ?? 6e c6 44 24 ?? 41 c6 44 24 ?? 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNL_2147851375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNL!MTB"
        threat_id = "2147851375"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b1 61 b2 72 88 4c 24 ?? 88 4c 24 ?? 8d 4c 24 ?? b0 65 51 68 ?? ?? ?? ?? c6 44 24 ?? 43 88 54 24 ?? 88 44 24 ?? c6 44 24 ?? 74 88 44 24 ?? c6 44 24 ?? 54 c6 44 24 ?? 68 88 54 24 ?? 88 44 24 ?? c6 44 24 ?? 64 c6 44 ?? 24 00 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNO_2147851478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNO!MTB"
        threat_id = "2147851478"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b0 65 b2 72 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 8d 44 24 ?? b1 61 50 68 ?? ?? ?? ?? c6 44 24 ?? 43 88 54 24 ?? 88 4c 24 ?? c6 44 24 ?? 74 c6 44 24 ?? 54 c6 44 24 ?? 68 88 54 24 20 88 4c 24 ?? c6 44 24 ?? 64 c6 44 ?? 24 00 ff d5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNP_2147851496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNP!MTB"
        threat_id = "2147851496"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 c0 8a 4c 07 01 32 0c 07 89 c2 d1 ea 51 b9 ?? ?? ?? ?? 49 59 83 c0 02 60 89 f9 89 c8 61 88 0c 17 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNP_2147851496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNP!MTB"
        threat_id = "2147851496"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {23 c2 83 c4 ?? a3 ?? ?? ?? ?? 8a 44 24 1c 32 c3 2a c3 32 c3 02 c3 88 04 2f 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 47 03 d1 84 c0 89 15 ?? ?? ?? ?? ?? ?? 8b 54 24 10 8b 44 24 14 83 c6 02 03 d6 3b d0}  //weight: 10, accuracy: Low
        $x_1_2 = "Ch7Demddo6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNP_2147851496_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNP!MTB"
        threat_id = "2147851496"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 b2 72 f2 ae f7 d1 49 88 54 24 ?? 88 54 24 ?? 8b d1 bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 49 c6 44 24 ?? 43 c6 44 24 ?? 74 c6 44 24 ?? 54 8d 44 0a ?? c6 44 24 ?? 68 50 c6 44 24 ?? 64 c6 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNQ_2147851656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNQ!MTB"
        threat_id = "2147851656"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 c3 2a c3 32 c3 89 2d ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 02 c3 88 04 17 03 e9 83 c4 ?? 47 89 0d ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 84 c0 ?? ?? 8b 44 24 ?? 83 c6 ?? 03 c6 3b 44 24 ?? 0f 8c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNQ_2147851656_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNQ!MTB"
        threat_id = "2147851656"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b1 72 50 53 c6 44 24 ?? 56 c6 44 24 ?? 69 88 4c 24 ?? c6 44 24 ?? 75 c6 44 24 ?? 61 c6 44 24 ?? 6c c6 44 24 ?? 50 88 4c 24 ?? c6 44 24 ?? 6f c6 44 24 ?? 65 c6 44 24 ?? 63 c6 44 24 ?? 00 ff d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNR_2147851668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNR!MTB"
        threat_id = "2147851668"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ca 0f af c8 8a 44 24 ?? 23 d1 32 c3 89 15 ?? ?? ?? ?? 8b 54 24 ?? 2a c3 32 c3 89 0d ?? ?? ?? ?? 02 c3 83 c4 ?? 88 04 2a 45 84 c0 ?? ?? 8b 44 24 ?? 8b 4c 24 ?? 83 c6 ?? 03 c6 3b c1 0f 8c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNT_2147852192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNT!MTB"
        threat_id = "2147852192"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c1 8a 4c 24 2c a3 ?? ?? ?? ?? 8a 44 24 10 2a c1 89 35 ?? ?? ?? ?? 32 c1 02 c1 8b 0d ?? ?? ?? ?? 0f af ca 89 0d ?? ?? ?? ?? 8b 4c 24 14 8b 54 24 1c 88 04 11}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_CJ_2147852923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.CJ!MTB"
        threat_id = "2147852923"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 99 f7 fb 8b 45 10 57 6a 01 6a 01 8a 0c 02 30 4d 0b 8d 55 0b 52 e8 [0-4] 83 c4 10 ff 45 fc 56 e8 [0-4] 83 c4 04 85 c0 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GMF_2147888490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GMF!MTB"
        threat_id = "2147888490"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b0 6c 51 52 c6 44 24 ?? 43 c6 44 24 ?? 74 c6 44 24 ?? 54 c6 44 24 ?? 68 88 5c 24 24 c6 44 24 ?? 4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e 88 44 24 ?? 88 44 24 ?? 88 5c 24 ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GMF_2147888490_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GMF!MTB"
        threat_id = "2147888490"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 45 f0 33 db 50 8d 45 e0 50 c6 45 f0 43 c6 45 f1 72 c6 45 f2 65 c6 45 f3 61 c6 45 f4 74 c6 45 f5 65 c6 45 f6 54 c6 45 f7 68 c6 45 f8 72 c6 45 f9 65 c6 45 fa 61 c6 45 fb 64 ?? ?? ?? c6 45 e0 4b c6 45 e1 45 c6 45 e2 52 c6 45 e3 4e c6 45 e4 45 c6 45 e5 4c c6 45 e6 33 c6 45 e7 32 c6 45 e8 2e c6 45 e9 64 c6 45 ea 6c c6 45 eb 6c}  //weight: 10, accuracy: Low
        $x_1_2 = "211.167.73.23" ascii //weight: 1
        $x_1_3 = "tcpip2005.blogchina.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GMX_2147893402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GMX!MTB"
        threat_id = "2147893402"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c7 89 fa 61 8a 4c 07 01 32 0c 07 89 c2 d1 ea 83 c0 02 88 0c 17 3d}  //weight: 10, accuracy: High
        $x_10_2 = {8a 4c 07 01 32 0c 07 89 c2 d1 ea 57 bf ?? ?? ?? ?? 4f 5f 83 c0 02 88 0c 17 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Lotok_ALK_2147897050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.ALK!MTB"
        threat_id = "2147897050"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 49 32 06 88 07 83 c6 01 53 bb ?? ?? ?? ?? 4b 5b 83 c7 01 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_KAA_2147897392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.KAA!MTB"
        threat_id = "2147897392"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ac 51 59 49 32 06 88 07 83 c6 01 83 c7 01 49 85 c9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GAB_2147898567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GAB!MTB"
        threat_id = "2147898567"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 93 04 db 42 00 00 30 00 00 07 33 80 ?? ?? ?? ?? 89 1c db 42 00 00 78 ?? 00 54 03 4e b9 ?? ?? ?? ?? 30 db 42 00 e7 59 00 00 48 7a}  //weight: 10, accuracy: Low
        $x_1_2 = "VirusKiller.scr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_AM_2147900315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.AM!MTB"
        threat_id = "2147900315"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c6 44 24 18 47 88 44 24 19 c6 44 24 1a 54 c6 44 24 1b 53 88 44 24 1c 88 4c 24 1d c6 44 24 1e 56 88 44 24 1f 88 4c 24 20 c6 44 24 21 32 c6 44 24 22 2e c6 44 24 23 30 88 5c 24 24 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNA_2147900378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNA!MTB"
        threat_id = "2147900378"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f7 31 db b9 ?? ?? ?? ?? ac 49 32 06 88 07 60 fd 89 d3 50 59 fc 61 83 c6 ?? 83 c7 ?? 49 85 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GNA_2147900378_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GNA!MTB"
        threat_id = "2147900378"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 45 d0 53 c6 45 d1 65 c6 45 d2 44 c6 45 d3 65 c6 45 d4 62 c6 45 d5 75 c6 45 d6 67 c6 45 d7 50 c6 45 d8 72 c6 45 d9 69 c6 45 da 76 c6 45 db 69 c6 45 dc 6c c6 45 dd 65 c6 45 de 67 c6 45 df 65 c6 45 e0 00}  //weight: 10, accuracy: High
        $x_10_2 = {8b 55 08 03 55 fc 0f be 02 83 f0 19 8b 4d 08 03 4d fc 88 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GZZ_2147905085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GZZ!MTB"
        threat_id = "2147905085"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {dc 52 65 41 6c 50 c7 45 ?? 6c 6f 63 00 c7 45 ?? 4b 45 52 4e c7 45 ?? 45 4c 33 32 c7 45 ?? 2e 64 6c 6c c6 45 ?? 00 c7 45 ?? 4c 6f 61 64 c7 45 ?? 4c 69 62 72 c7 45 ?? 61 72 79 41 c6 45 ?? 00 ff d3 50 ff d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_ASDN_2147906606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.ASDN!MTB"
        threat_id = "2147906606"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1c 31 80 c2 03 32 da 47 88 1c 31 b9 05 00 00 00 99 f7 f9 89 7d e8 85 d2 75}  //weight: 2, accuracy: High
        $x_1_2 = {8b 4d e4 6a 04 68 00 20 00 00 8b 51 50 52 56 ff 15 ?? ?? ?? 00 3b c6 89 45 ec}  //weight: 1, accuracy: Low
        $x_1_3 = "Fwnfwnfv Ogwofwofw Ogxogwo Hxpgxpgx Phy" ascii //weight: 1
        $x_1_4 = "Aqiyqi Ariariaq Jbrjarja Sjbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GZX_2147907258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GZX!MTB"
        threat_id = "2147907258"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 50 c7 44 24 ?? 45 50 45 72 c7 44 24 ?? 6f 45 63 65 c7 44 24 ?? 45 73 45 73 c7 44 24 ?? 45 33 45 32 c7 44 24 ?? 46 45 69 45 c7 44 24 ?? 72 45 73 45 c7 44 24 ?? 74 45 45 45 89 5c 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lotok_GZY_2147907670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lotok.GZY!MTB"
        threat_id = "2147907670"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lotok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d0 89 c1 61 31 db b9 ?? ?? ?? ?? ac 60 89 da 89 d1 61 49 32 06 88 07 83 c6 01 83 c7 01 49 85 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

