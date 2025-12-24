rule Trojan_Win32_Lazy_CC_2147811339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.CC!MTB"
        threat_id = "2147811339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 c1 34 0c c0 c8 07 04 21 04 21 2a c1 c0 c8 07 34 0c c0 c0 07 34 0c aa 4a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MA_2147836831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MA!MTB"
        threat_id = "2147836831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 04 01 00 00 66 5b 66 83 fb 00 74 0a 66 81 eb f7 00 88 1f 47 e2 ee 66 59 52 c3}  //weight: 1, accuracy: High
        $x_5_2 = "TyYi" ascii //weight: 5
        $x_2_3 = "dlvr.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MA_2147836831_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MA!MTB"
        threat_id = "2147836831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "libemb.dll" ascii //weight: 1
        $x_1_2 = "wwlib.dll" ascii //weight: 1
        $x_1_3 = "zlibwapi.dll" ascii //weight: 1
        $x_5_4 = "FreeLibraryMemoryAndExitThread" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lazy_NEAD_2147838653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.NEAD!MTB"
        threat_id = "2147838653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f7 e6 c1 ea 04 8d 04 52 c1 e0 03 2b c8 8a 04 31 30 04 37 46 3b f3 72 d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_CG_2147842497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.CG!MTB"
        threat_id = "2147842497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 5a 01 8d 52 02 80 eb 61 85 ff 74 17 c0 e0 04 2c 10 0a c3 32 c1 32 c7 88 06 32 e8 83 c6 02 83 c5 02 eb 0e 8a c8 bf 01 00 00 00 fe c9 c0 e1 04 0a cb 8a 02 84 c0 75}  //weight: 2, accuracy: High
        $x_1_2 = {8a 42 01 8d 52 02 c0 e1 04 8d 76 01 80 e9 10 2c 61 0a c8 32 cb 80 f1 d0 88 4e ff 8a 0a 84 c9 75}  //weight: 1, accuracy: High
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lazy_EM_2147845156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.EM!MTB"
        threat_id = "2147845156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f6 da fe c2 66 3b eb f8 f6 d2 f8 32 da}  //weight: 5, accuracy: High
        $x_5_2 = {f6 da fe c2 66 0f 43 cc c0 cc 8e f6 d2 98 66 0f c9 66 b9 1d 10 d0 c2 f7 d8 66 0f a4 d0 94 c0 e4 47 32 da c0 e1 a1 66 85 da 66 8b 0c 14 81 ef 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Lazy_CAF_2147845777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.CAF!MTB"
        threat_id = "2147845777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 5d e4 8a 44 1d 10 88 44 3d 10 88 4c 1d 10 0f b6 44 3d 10 03 c2 0f b6 c0 83 65 fc ?? 8a 44 05 10 32 86 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 83 4d fc ff eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_BW_2147845933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.BW!MTB"
        threat_id = "2147845933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 44 24 18 30 44 0c 19 41 83 f9 33 72}  //weight: 3, accuracy: High
        $x_2_2 = "BVQEDU0QFjY0k0h5FMER5C0lMN0JUEaRejQwQMZVUxMN0NFwJvCc2mQUefl1ujENSJRT9FWDThxCSU" ascii //weight: 2
        $x_2_3 = "bESuUQSUNZbCRDJkENN0xPJVZQL0FIQZEVxUsU1gNN0WEDARNVsExSfFxPvSVcHTlQR5D1BVmNLjj0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AB_2147849152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AB!MTB"
        threat_id = "2147849152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 7c 24 60 10 8d 44 24 4c 0f 43 44 24 4c 8a 04 10 2a 04 91 88 44 24 13 3b de 73 2e 8a 4c 24 13 8d 43 01 89 44 24 38 83 fe 10 8d 44 24 28 0f 43 c7 88 0c 18 c6 44 18 01 00 8b 74 24 3c 8b 5c 24 38 8b 7c 24 28}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_DM_2147849423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.DM!MTB"
        threat_id = "2147849423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e2 05 0b ca 0f b6 45 ?? 33 c8 8b 55 ?? 03 55 ?? 88 0a 8b 45 ?? 83 c0 01 99 b9 0c 00 00 00 f7 f9 89 55 dc eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_ALZ_2147851724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.ALZ!MTB"
        threat_id = "2147851724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 17 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 fb 80 eb e8 01 f4 89 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_ALZ_2147851724_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.ALZ!MTB"
        threat_id = "2147851724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 68 00 02 00 00 8d 85 e4 fd ff ff 50 e8 ?? ?? ?? ?? 83 c4 28 8d 86 08 04 00 00 8d 4e 08 6a 00 50 68 ff 03 00 00 51 6a fd 8d 85 e4 fd ff ff 50 6a 00 ff 37 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 00 8d 86 08 04 00 00 50 68 ff 03 00 00 8d 46 08 50 6a fd 8d 85 e4 fd ff ff 50 6a 00 ff 37 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_ALZ_2147851724_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.ALZ!MTB"
        threat_id = "2147851724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 68 58 1d 62 67 6a 00 ff 15 ?? ?? ?? ?? 68 98 1d 62 67 89 85 74 17 ff ff ff 15 ?? ?? ?? ?? 68 a4 1d 62 67 50 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {50 6a 00 8d 85 44 19 ff ff 50 ff 15 ?? ?? ?? ?? 8b b5 74 17 ff ff 8d 85 c0 2d ff ff 50 56 ff 15 ?? ?? ?? ?? 8b 3d fc c1 61 67 8d 85 c0 2d ff ff 50 56 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GNR_2147851938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GNR!MTB"
        threat_id = "2147851938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IDL_SEQUENCE_SessionTokenORB@@QAE@KKPAUSessionTokenORB@@E@Z" ascii //weight: 1
        $x_1_2 = "bind@ProxyFactory@CORBA@@UAEPAXPBD000ABVContext@2@AAVEnvironment@2@@Z" ascii //weight: 1
        $x_1_3 = "encodeOp@_IDL_SEQUENCE_string@@QBEXAAVRequest@CORBA@@@Z" ascii //weight: 1
        $x_1_4 = "_castDown@Object@CORBA@@SGPAXPAV12@PBDAAVEnvironment@2@@Z" ascii //weight: 1
        $x_1_5 = "G:\\CXR19\\BSF\\intel_a\\code\\bin\\PPRDCCCORBA_C.pdb" ascii //weight: 1
        $x_1_6 = "PPRDCCCORBA_C.dll" ascii //weight: 1
        $x_1_7 = ".ropf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GMB_2147853176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GMB!MTB"
        threat_id = "2147853176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {52 83 c4 04 83 c6 01 8a 46 ff 68 ?? ?? ?? ?? 83 c4 04 c7 44 24 ?? db 83 dd a3 32 02 68 ?? ?? ?? ?? 83 c4 04 83 c7 01 88 47 ff 89 c0 68 ?? ?? ?? ?? 83 c4 04 83 c2 02 4a 83 ec 04 c7 04 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GMC_2147853177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GMC!MTB"
        threat_id = "2147853177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 32 02 ?? 88 07 47 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 89 c0 52 83 04 24 01 5a 68 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 41 83 e9 02 89 c0 ?? 85 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_CN_2147853241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.CN!MTB"
        threat_id = "2147853241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {f3 a4 83 ec 04 c7 04 24 70 55 5b 5a 83 c4 04 57 97 5f 90 89 c0 83 c4 04 87 4c 24 fc 57 83 c4 04 90 8b 34 24 83 c4 04 c7 44 24 fc 53 f0 e1 84 53 83 c4 04 8b 3c 24 83 c4 04 c7 44 24 fc 4e 67 7c e8}  //weight: 3, accuracy: High
        $x_3_2 = {f3 a4 83 ec 04 c7 04 24 f0 07 81 98 83 c4 04 57 97 5f c7 44 24 fc 42 b1 99 5e 68 36 cf 90 29 83 c4 04 59 56 83 c4 04 83 ec 04 c7 04 24 74 38 1d 52 83 c4 04 83 c4 04 8b 74 24 fc}  //weight: 3, accuracy: High
        $x_3_3 = {f3 a4 90 57 58 89 c0 83 ec 04 c7 04 24 1a 91 e7 55 83 c4 04 83 c4 04 8b 4c 24 fc 90 57 83 c4 04 83 c4 04 87 74 24 fc c7 44 24 fc ca d3 85 fb 53 83 c4 04 8b 3c 24 83 c4 04 57 83 c4 04 c9}  //weight: 3, accuracy: High
        $x_3_4 = {f3 a4 c7 44 24 fc 20 95 69 9d 89 f8 89 c0 c7 44 24 fc 37 9c 8c 26 83 c4 04 87 4c 24 fc c7 44 24 fc 29 b6 4b e4 89 c0 87 34 24 83 c4 04 c7 44 24 fc fb 46 14 00}  //weight: 3, accuracy: High
        $x_2_5 = "xmtuzysdob" ascii //weight: 2
        $x_2_6 = "gcdufpmlvkn" ascii //weight: 2
        $x_2_7 = "uxojpgvcmbf" ascii //weight: 2
        $x_2_8 = "hjotmwxyklgz" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lazy_CO_2147853242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.CO!MTB"
        threat_id = "2147853242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {6b 66 76 61 74 6c 67 6f 2e 64 6c 6c 00 77 74 76 72 6d 71 70 73 65 79 00 78 6b 6c 75 77 67 73 79 00 76 78 62 6f 72 65 6e 7a 64}  //weight: 4, accuracy: High
        $x_4_2 = {6d 79 78 6e 74 69 68 7a 2e 64 6c 6c 00 79 71 63 78 65 77 72 76 6c 00 6d 6e 77 65 67 62 73 6f 63 6a 61 76 00 65 70 73 6c 62 71 67 68 6e 63 74 00 79 70 77 6d 73 6f}  //weight: 4, accuracy: High
        $x_4_3 = {67 70 75 66 79 69 6b 63 2e 64 6c 6c 00 78 70 72 6d 63 64 75 77 79 71 68 6f 00 7a 75 6e 79 6f 64 76 77 61 62 00 75 76 74 78 61 70 6e 63 6a 6d 73 72 00 67 7a 69 62 71 6d 78}  //weight: 4, accuracy: High
        $x_4_4 = {6d 73 76 68 64 66 75 71 2e 64 6c 6c 00 6b 75 6e 74 70 64 6f 67 79 7a 6a 00 6a 6e 67 74 68 70 73 7a 62 77 6f 00 62 68 73 71 6f 69 63 66 64 00 6a 6c 66 65 68 69}  //weight: 4, accuracy: High
        $x_4_5 = {77 68 62 65 6c 6e 79 72 2e 64 6c 6c 00 74 64 63 6b 67 73 71 70 66 6e 77 7a 00 70 65 69 73 75 6e 00 73 78 64 6c 63 6a 6b 65 71 62 00 62 70 6a 76 6e 6b 79}  //weight: 4, accuracy: High
        $x_4_6 = {74 70 65 75 66 76 64 78 2e 64 6c 6c 00 64 75 65 62 72 63 00 72 69 79 6d 67 7a 63 00 62 6a 68 74 77 64 6c 65 66 78 79 00 6b 73 77 66 6f 70 76 78 62 61 64 72}  //weight: 4, accuracy: High
        $x_1_7 = "awbsvfpu" ascii //weight: 1
        $x_1_8 = "lhjnzba" ascii //weight: 1
        $x_1_9 = "merzvk" ascii //weight: 1
        $x_1_10 = "wdbgvko" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lazy_CP_2147853276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.CP!MTB"
        threat_id = "2147853276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 70 76 62 7a 71 63 73 2e 64 6c 6c 00 6e 79 6b 73 72 62 77 00 6d 6a 73 75 71 72 6b 00 79 6d 6f 71 78 6c 75 72 61 70 69 6b}  //weight: 1, accuracy: High
        $x_1_2 = {69 68 65 74 61 71 6e 6d 2e 64 6c 6c 00 66 74 69 6a 77 78 00 65 6f 69 6e 6a 77 62 00 64 69 71 77 73 70 63 72}  //weight: 1, accuracy: High
        $x_1_3 = {6e 70 76 66 78 74 73 7a 2e 64 6c 6c 00 6b 66 71 79 78 62 6e 00 6b 79 6e 6d 78 69 76 73 65 66 71 00 67 61 73 62 65 69 72 68 6e 76 64}  //weight: 1, accuracy: High
        $x_1_4 = {6a 6e 67 78 61 7a 69 6c 2e 64 6c 6c 00 6f 71 6d 67 66 73 61 6a 77 62 00 61 6d 72 77 6e 64 66 7a 74 78 00 68 67 7a 71 73 6b 74}  //weight: 1, accuracy: High
        $x_1_5 = {7a 61 64 76 6d 65 67 74 2e 64 6c 6c 00 75 71 6f 6a 63 65 79 78 64 00 6e 6a 61 75 71 67 63 76 69 72 00 6f 62 6a 70 7a 71 6d 77 79}  //weight: 1, accuracy: High
        $x_1_6 = {6b 65 6d 61 76 77 62 75 2e 64 6c 6c 00 67 66 71 74 6d 6a 6e 6b 00 72 77 64 67 73 63 70 69 78 79 00 71 6f 66 75 64 62}  //weight: 1, accuracy: High
        $x_1_7 = {77 72 6d 71 76 79 6a 67 2e 64 6c 6c 00 6d 76 6b 77 63 73 6c 61 6a 68 66 00 68 74 79 73 72 78 7a 70 67 00 69 63 76 6d 70 61 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Lazy_CP_2147853276_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.CP!MTB"
        threat_id = "2147853276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {7a 6b 71 68 70 6d 72 6e 2e 64 6c 6c 00 79 6c 69 64 76 6f 00 66 69 6b 62 72 74 7a 6d 00 7a 76 77 73 71 74 63 6e 70 67 65 6f 00 6b 6e 79 68 76 6a 6c 66 69 00 71 7a 75 68 67 6a 74 6c 63 73}  //weight: 4, accuracy: High
        $x_4_2 = {72 78 64 61 7a 77 71 6f 2e 64 6c 6c 00 73 79 6c 72 76 66 64 00 6c 67 6b 78 7a 6f 62 71 75 64 76 00 70 79 74 78 6c 61 67 77 72 62 6b 65 00 63 62 65 70 66 79 64 61 67 6e 6d 76 00 6f 61 64 67 69 6e 63 71 62 6c}  //weight: 4, accuracy: High
        $x_4_3 = {79 66 6b 63 65 73 68 6e 2e 64 6c 6c 00 67 74 65 73 68 63 66 77 72 00 78 79 6f 72 62 6c 64 77 00 6b 6f 74 78 67 70 62 66 73 6e 77}  //weight: 4, accuracy: High
        $x_4_4 = {6e 76 6b 61 6c 67 75 72 2e 64 6c 6c 00 6b 73 61 65 69 78 6a 6d 00 71 7a 6b 63 72 76 74 00 68 79 74 73 62 78 63 76 00 67 65 74 7a 75 73 68 66 71 69 62 6e 00 66 79 73 6f 74 6c 62 78 75 65}  //weight: 4, accuracy: High
        $x_4_5 = {6e 63 6f 76 6b 65 72 70 2e 64 6c 6c 00 72 6b 62 66 77 6e 00 64 66 68 72 6b 67 6f 75 00 63 77 70 62 68 6a 00 76 79 7a 6c 65 66 61 64 00 64 62 61 79 76 74}  //weight: 4, accuracy: High
        $x_4_6 = {62 7a 75 73 74 79 6f 6a 2e 64 6c 6c 00 6a 77 79 6e 78 70 6c 00 79 64 65 74 6b 6d 6c 62 75 00 65 76 79 63 73 61 6c 6a 6b 00 62 68 71 78 75 6f 00 73 70 68 66 6a 78 74 6d 6f}  //weight: 4, accuracy: High
        $x_4_7 = {72 6f 71 77 65 73 64 67 2e 64 6c 6c 00 62 70 78 67 73 76 77 00 79 61 69 6f 67 71 77 73 68 6e 00 7a 68 73 61 6b 79 78 71 69 00 72 6d 71 70 78 6a 69 64 76 00 6d 75 79 65 67 70 6c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Lazy_CQ_2147887424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.CQ!MTB"
        threat_id = "2147887424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 a4 90 57 58 c7 44 24 fc 5b 56 56 76 90 87 0c 24 83 c4 04 57 83 c4 04 83 ec 04 c7 04 24 5c bb 47 d6 83 c4 04 8b 34 24 83 c4 04}  //weight: 1, accuracy: High
        $x_1_2 = {6e 70 71 69 77 75 64 6d 2e 64 6c 6c 00 7a 66 68 77 79 76 6f 6d 00 70 6c 6f 63 65 61 6a 6d 69 79 00 6f 61 79 7a 63 6d 76 00 65 62 71 6e 67 68 6a 70 72}  //weight: 1, accuracy: High
        $x_1_3 = {7a 69 67 71 76 63 66 64 2e 64 6c 6c 00 66 70 6d 7a 73 67 6f 6e 77 00 7a 6f 71 6d 62 70 69 77 6e 00 78 71 70 72 6e 79 7a 62 6a 6b 67 6f 00 75 71 6d 64 6f 63 68 65 79}  //weight: 1, accuracy: High
        $x_1_4 = {6b 62 69 75 76 66 7a 6f 2e 64 6c 6c 00 6a 7a 6e 62 73 74 66 78 6f 69 72 00 69 72 77 76 71 7a 78 6c 68 63 00 74 69 64 6e 75 6d 00 6c 63 66 6e 6d 77 69 7a 70 64}  //weight: 1, accuracy: High
        $x_1_5 = {70 6c 62 63 6f 7a 75 76 2e 64 6c 6c 00 6a 71 72 63 7a 64 00 6c 75 65 78 71 68 67 6d 73 62 70 00 76 70 66 71 77 6c 72 6d 7a 75 00 73 6a 69 7a 71 6c 61 70 78 6f}  //weight: 1, accuracy: High
        $x_1_6 = {79 63 6e 7a 67 64 6a 78 2e 64 6c 6c 00 6b 6f 6d 76 78 75 69 6a 00 72 78 67 74 66 70 62 6c 6a 00 6d 73 77 6f 66 75 61 6e 70 6b 72 00 72 6f 77 73 75 67 79 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Lazy_GMD_2147888113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GMD!MTB"
        threat_id = "2147888113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 06 46 89 c0 68 ?? ?? ?? ?? 83 c4 04 32 02 68 ?? ?? ?? ?? 83 c4 04 88 07 83 c7 01 c7 44 24 ?? a0 61 2c ba 68 ?? ?? ?? ?? 83 c4 04 52 ff 04 24 5a ?? 89 c0 83 e9 01 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 c7 44 24 ?? 10 ac 81 3b 85 c9}  //weight: 10, accuracy: Low
        $x_1_2 = "muphaxrt" ascii //weight: 1
        $x_1_3 = "tcpveyq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_EA_2147888212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.EA!MTB"
        threat_id = "2147888212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "afowkmsg" ascii //weight: 1
        $x_1_2 = "rteviawzpj" ascii //weight: 1
        $x_1_3 = "jihdkc" ascii //weight: 1
        $x_1_4 = "cmkbovd" ascii //weight: 1
        $x_1_5 = "pfiaymckwxz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_EB_2147888213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.EB!MTB"
        threat_id = "2147888213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "awxuniz" ascii //weight: 1
        $x_1_2 = "wjgucthpz" ascii //weight: 1
        $x_1_3 = "cmeyldpwujh" ascii //weight: 1
        $x_1_4 = "cbfkielvqt" ascii //weight: 1
        $x_1_5 = "ykgphlormb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_EB_2147888213_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.EB!MTB"
        threat_id = "2147888213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mokcpudsry" ascii //weight: 1
        $x_1_2 = "luxvinpzfbej" ascii //weight: 1
        $x_1_3 = "nodwcxjyptia" ascii //weight: 1
        $x_1_4 = "nvsmltkadqyi" ascii //weight: 1
        $x_1_5 = "qcbgtwxfmdnp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GMF_2147888457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GMF!MTB"
        threat_id = "2147888457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6a 37 59 33 d2 8b c3 f7 f1 80 c2 34 30 54 1c 19 43 83 fb 0e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GMF_2147888457_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GMF!MTB"
        threat_id = "2147888457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 55 d8 c7 45 ?? bc 7e 06 32 c7 45 ?? b8 7e 06 32 66 89 45 e4 c7 45 ?? 64 3b 05 32 c7 45 ?? 00 00 01 00 c7 45 ?? ec 7e 06 32 c7 45 ?? e8 7e 06 32 66 89 45 f8 39 4d 08 0f 85}  //weight: 10, accuracy: Low
        $x_10_2 = {ac ae 06 32 c7 85 ?? ?? ?? ?? a8 ae 06 32 66 89 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 0c 5b 05 32 c7 85 ?? ?? ?? ?? e0 ae 06 32 c7 85 ?? ?? ?? ?? dc ae 06 32 66 89 85}  //weight: 10, accuracy: Low
        $x_1_3 = "GA2RZNbm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lazy_A_2147888602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.A!MTB"
        threat_id = "2147888602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 04 c7 04 24 e4 dd ee 13 83 c4 04 83 c6 01 8a 46 ff 68 c8 b2 c8 fb 83 c4 04 c7 44 24 fc f5 5f c2 39 32 02 c7 44 24 fc 85 87 63 9a 83 c7 01 88 47 ff 89 c0 68 fe f9 1a ca 83 c4 04 83 c2 02 4a 90 c7 44 24 fc 0f 8c 2a 15 83 e9 02 41 57 83 c4 04 90 85 c9 75 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_CCBF_2147891345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.CCBF!MTB"
        threat_id = "2147891345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 32 02 aa ?? ?? 42 49 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GMK_2147891577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GMK!MTB"
        threat_id = "2147891577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d 10 8b 55 14 80 3a 00 74 ?? ?? ?? ?? ac 32 02 aa ?? ?? ?? 42 49 85 c9 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MBJC_2147891841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MBJC!MTB"
        threat_id = "2147891841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "raxoyxdxi" ascii //weight: 1
        $x_1_2 = "zsnvnjvndqvi" ascii //weight: 1
        $x_1_3 = "qowrqsmbpw" ascii //weight: 1
        $x_1_4 = "fffnogk" ascii //weight: 1
        $x_1_5 = "eswbxmjsziz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MBJE_2147891842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MBJE!MTB"
        threat_id = "2147891842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 66 ad 85 c0 74 18 01 c3 66 ad 85 c0 74 10 89 c1 51 53 57 e8 0b 00 00 00 01 cb 89 c7 eb e0}  //weight: 1, accuracy: High
        $x_1_2 = {62 79 65 7a 00 69 79 71 72 79 78 6e 77 6c 62 6c 7a 00 69 78 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_ASBD_2147893818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.ASBD!MTB"
        threat_id = "2147893818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://data1.vippin.cn/data.txt" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 61 00 74 00 61 00 2e 00 76 00 69 00 70 00 70 00 69 00 6e 00 2e 00 63 00 6e 00 2f 00 64 00 61 00 74 00 61 00 2e 00 74 00 78 00 74 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {30 1c f7 02 27 5c ff 0a 0d 00 04 00 35 5c ff 27 5c ff 0a 0e}  //weight: 1, accuracy: High
        $x_1_4 = "del /f del.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MKK_2147897126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MKK!MTB"
        threat_id = "2147897126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 8a 84 35 dc fe ff ff 88 84 3d dc fe ff ff 88 8c 35 dc fe ff ff 0f b6 84 3d dc fe ff ff 03 c2 8b 55 ?? 0f b6 c0 8a 84 05 dc fe ff ff 30 04 13 43 3b 5d e0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AMAB_2147899031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AMAB!MTB"
        threat_id = "2147899031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InjbyvtKminuby" ascii //weight: 1
        $x_1_2 = "OminubHvytc" ascii //weight: 1
        $x_1_3 = "UtvybRtvyb" ascii //weight: 1
        $x_1_4 = "UrctvKtcvyb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GAN_2147899724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GAN!MTB"
        threat_id = "2147899724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 c2 01 35 ?? ?? ?? ?? 83 c0 ?? 8d 05 ?? ?? ?? ?? 89 38 01 c2 83 f0 ?? 01 2d ?? ?? ?? ?? b8 ?? ?? ?? ?? 01 1d ?? ?? ?? ?? b9 02 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AMBA_2147900233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AMBA!MTB"
        threat_id = "2147900233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kdiczylgragegeazrkttjtduycn" ascii //weight: 1
        $x_1_2 = "njvnuvvsgccdfttzrpt" ascii //weight: 1
        $x_1_3 = "qtpjkbhpaumtjbcjywjbmabkphnaitsalkl" ascii //weight: 1
        $x_1_4 = "dqlyxalutgbvfrygyghhtamxqqeijvgje" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_SPD_2147900678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.SPD!MTB"
        threat_id = "2147900678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 3e b8 ed 2b 90 0f 21 c1 ba 09 ff 66 12 81 e7 ff 00 00 00 48 09 c2 31 3b 42 21 c9 43 f7 d1 48 81 e9 c7 e3 6a f4 46 09 c8 f7 d1 4a}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_KAG_2147900775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.KAG!MTB"
        threat_id = "2147900775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EngmT5177t1.DlL" ascii //weight: 1
        $x_1_2 = "kWover,hadsea" ascii //weight: 1
        $x_1_3 = "MLbeastl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GPB_2147901167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GPB!MTB"
        threat_id = "2147901167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {55 89 e5 8a 45 0c 8a 4d 08 c7 05 30 a5 20 10 ad 0b 00 00 c7 05 2c a5 20 10 39 14 00 00 30 c8 0f b6 c0 5d c3}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_NL_2147902618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.NL!MTB"
        threat_id = "2147902618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 f9 80 3e 00 75 ec 83 7c 24 ?? 01 75 63 eb 03 8d 49 00 8a 07 88 06 8a 0f 46 47}  //weight: 3, accuracy: Low
        $x_2_2 = {8d 9b 00 00 00 00 57 56 ff d3 85 c0 74 30 8a 06 46 84 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_NL_2147902618_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.NL!MTB"
        threat_id = "2147902618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "fwehfweojoir" ascii //weight: 2
        $x_2_2 = "presidentstatisticpro" ascii //weight: 2
        $x_2_3 = "KUQ4PwoXbg.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_NL_2147902618_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.NL!MTB"
        threat_id = "2147902618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "why u reverse my stub?(((" ascii //weight: 2
        $x_1_2 = "( i dont love u, bro(((" ascii //weight: 1
        $x_1_3 = "KillTimer" ascii //weight: 1
        $x_1_4 = "< i love u, bro)" ascii //weight: 1
        $x_1_5 = "OpenProcessToken" ascii //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_HNS_2147904987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.HNS!MTB"
        threat_id = "2147904987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 00 01 00 43 6c 61 73 73 69 63 45 78 70 6c 6f 72 65 72 33 32 5f 64 6c 6c 2e 64 6c 6c 00 44 6c 6c 45 78 70 6f 72 74 53 65 74 74 69 6e 67 73 58 6d 6c 00 53 68 6f 77 45 78 70 6c 6f 72 65 72 53 65 74 74 69 6e 67 73 00}  //weight: 2, accuracy: High
        $x_2_2 = {85 c0 78 0d 8b 40 ?? 8b 40 ?? 8b 00 8b 00 8b 40 ?? c3}  //weight: 2, accuracy: Low
        $x_2_3 = {8b c3 0f ac c1 ?? 0f b7 f1 33 c9 85 f6 74 1a 0f be 14 0b c1 cf ?? 80 3c 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_NF_2147906173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.NF!MTB"
        threat_id = "2147906173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "0t6-+C*Pd2+Wk!e+-.pdb" ascii //weight: 5
        $x_5_2 = "testAPP.exE" ascii //weight: 5
        $x_5_3 = "sELF.Exe" ascii //weight: 5
        $x_3_4 = "KeRNel32.DLl" ascii //weight: 3
        $x_1_5 = "SetupDiDestroyDeviceInfoList" ascii //weight: 1
        $x_1_6 = "MpReportEventEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MBFW_2147906464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MBFW!MTB"
        threat_id = "2147906464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "serxqdanjlniafrhczsrcyyixtkyiqwgtfffrwlnmoxmcwoxgjhjpvqvawwaftivtavjx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_HNB_2147906809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.HNB!MTB"
        threat_id = "2147906809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 c0 74 09 6a 04 8d 4d f8 51 56 ff d0 8d 45 fc 50 ff 75 fc 6a 04 56 ff 15 ?? ?? ?? ?? 5e 8b e5 5d c3}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 06 a3 00 30 00 10 a1 04 30 00 10 c7 45 f8 00 10 00 10}  //weight: 2, accuracy: High
        $x_2_3 = {46 77 70 6d 46 72 65 65 4d 65 6d 6f 72 79 30 00 66 77 70 75 63 6c 6e 74 2e 64 6c 6c ?? ?? ?? ?? 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 ?? ?? ?? ?? 44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 ?? ?? ?? 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 ?? ?? ?? ?? 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 ?? ?? 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_HNA_2147907552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.HNA!MTB"
        threat_id = "2147907552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 95 c0 89 45 e4 70 00 [0-21] 00 11 00 00 [0-5] 00 04 00 01 [0-31] 0a 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AMMH_2147909472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AMMH!MTB"
        threat_id = "2147909472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 3c ?? 03 c6 59 8b 4c 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 29 45 3b ac 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_WEE_2147911086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.WEE!MTB"
        threat_id = "2147911086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 0b 8d 4d ?? e8 ?? ?? ?? ?? 8b 55 ?? 43 3b 9d ?? ?? ?? ?? 89 5d ?? 8b 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_UNK_2147911421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.UNK!MTB"
        threat_id = "2147911421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 58 b7 0b 00 cc cc cc cc cc 68 10 ec 45 00 64 ff 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_HND_2147912002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.HND!MTB"
        threat_id = "2147912002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 27 2f c6 44 24 28 34 c6 44 24 29 2e c6 44 24 2a 30 c6 44 24 2b 20 c6 44 24 2c 28 c6 44 24 2d 63}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc ff 45 fc 8a 18}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 22 7a 88 54 24 23 88 4c 24 26}  //weight: 1, accuracy: High
        $x_1_4 = {b9 00 01 00 00 33 c0 8d 7c 24 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AI_2147913726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AI!MTB"
        threat_id = "2147913726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 f1 97 2a fb 32 49 f5 c1 c9 03 81 e9 6d 77 a7 64 81 f1 e1 2b 79 0a 33 d9 f5 3b d3 f8 03 e9}  //weight: 2, accuracy: High
        $x_2_2 = {8d ad 04 00 00 00 33 d3 f5 81 ea 61 52 0d 46 66 3b cb f7 d2 f5 66 3b f1 0f ca 66 81 fb 80 77 81 f2 36 70 3b 24 66 f7 c4 ea 72 e9}  //weight: 2, accuracy: High
        $x_1_3 = {70 61 69 79 61 6e 6e 6f 69 74 68 61 69 09 73 61 72 61 61 74 68 61 69}  //weight: 1, accuracy: High
        $x_1_4 = {6d 6f 6d 61 74 68 61 69 09 79 6f 79 61 6b 74 68 61 69 09 72 6f 72 75 61 74 68 61 69}  //weight: 1, accuracy: High
        $x_1_5 = "fontcraft@hotmail.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lazy_RF_2147916211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.RF!MTB"
        threat_id = "2147916211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 89 4a 52 8b 45 fc 83 c0 31 8b 0d ?? ?? ?? ?? 66 89 41 54 8b 55 fc 83 c2 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_SQDB_2147916238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.SQDB!MTB"
        threat_id = "2147916238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VzhhoaeEnwsasio" ascii //weight: 2
        $x_1_2 = "lhnwktp80.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AMAZ_2147917719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AMAZ!MTB"
        threat_id = "2147917719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GZ_2147918649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GZ!MTB"
        threat_id = "2147918649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 30 0f b7 d1 80 c3 ?? 32 5c 55 ?? 40 88 5c 30 ?? 41 3b c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_OKZ_2147921714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.OKZ!MTB"
        threat_id = "2147921714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 1c ff 50 10 8b 03 8b cb 6a 1c ff 50 18 8b 03 8b cb 6a 00 ff 50 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GV_2147921875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GV!MTB"
        threat_id = "2147921875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 80 c1 ?? 32 4c 45 ?? 8d 42 01 88 8e ?? ?? ?? ?? 46 0f b7 d0 81 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GV_2147921875_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GV!MTB"
        threat_id = "2147921875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4a 01 8a 02 88 4d ff 8a 4a 02 88 4d fe 8a 4a 03 83 c2 04 0f b6 c0 88 4d fd 89 55 ec 85 c0 74 34}  //weight: 1, accuracy: High
        $x_1_2 = ":\\Temp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GXT_2147923282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GXT!MTB"
        threat_id = "2147923282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 66 b9 a5 40 86 c9 66 f7 d1 66 89 45 04 f6 d5 9c 66 1b cf 12 ea 8f 44 25 00}  //weight: 10, accuracy: High
        $x_1_2 = "d3.largesder.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AMR_2147923872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AMR!MTB"
        threat_id = "2147923872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 0c 10 8b 86 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 89 0c 02 83 c2 04 8b 46 ?? 2b 46 ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 84 e7 fb ff 01 86 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 01 81 fa ?? ?? ?? ?? 7c}  //weight: 4, accuracy: Low
        $x_1_2 = {88 14 01 ff 86 [0-20] 88 1c 08 ff 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AAA_2147924027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AAA!MTB"
        threat_id = "2147924027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d f0 0f be 54 0d ?? 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_KAY_2147924318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.KAY!MTB"
        threat_id = "2147924318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {08 e8 4a be 06 00 8b 44 24 3c 8b 4c 24 50 39 c8 89 c2 8b 5c 24 6c 8b 6c 24 44}  //weight: 3, accuracy: High
        $x_3_2 = {06 75 78 65 57 58 43 00 06 65 58 67 72 43 4e 00 06 71 49 59 78 4e 66 00 06 7a 5a 39 52 63 70 00 06 6e 4a 6e 33 32 6b}  //weight: 3, accuracy: High
        $x_3_3 = {07 64 69 42 70 52 37 63 01 07 57 72 69 74 65 54 6f 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_NO_2147925554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.NO!MTB"
        threat_id = "2147925554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 3b d8 72 ea f6 14 3e 57 46 e8 ?? ?? 00 00 59 3b f0 72 cb 5b 8b c7 5f 5e c9 c3 55}  //weight: 2, accuracy: Low
        $x_1_2 = "WindowsDefender" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GTS_2147927576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GTS!MTB"
        threat_id = "2147927576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 d1 32 c3 81 d9 ?? ?? ?? ?? f6 d8 2c 04 d0 c0 03 ce f6 d1 8b cf}  //weight: 5, accuracy: Low
        $x_5_2 = {3b d6 32 d9 3b e2 88 04 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_NLA_2147928628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.NLA!MTB"
        threat_id = "2147928628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 66 81 3f ?? 00 0f 94 c7 20 fb f6 c3 01 89 85 84 fd ff ff}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 8d 88 fd ff ff 66 81 39 ?? 00 0f 94 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 95 8c fd ff ff 66 81 3a ?? 00 0f 94 c7}  //weight: 1, accuracy: Low
        $x_1_4 = "\\loader.cpp.bc.obj.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_ALA_2147928783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.ALA!MTB"
        threat_id = "2147928783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6a 00 68 b2 6c 41 00 68 f0 3e 41 00 6a 00 ff 15 2c f1 40 00 ff 75 14 ff 35 38 7b 41 00 ff 15 1c f1 40 00 ff 35 38 7b 41 00 ff 15 64 f1 40 00 6a 6d 53 ff 15}  //weight: 3, accuracy: High
        $x_2_2 = {8b 0d 00 60 41 00 56 8b 35 bc 73 41 00 83 e1 1f 33 35 00 60 41 00 d3 ce 85 f6}  //weight: 2, accuracy: High
        $x_1_3 = {8b 0d 00 60 41 00 8b 15 bc 73 41 00 83 e1 1f 33 15 00 60 41 00 d3 ca 85 d2 0f 95 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_ALA_2147928783_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.ALA!MTB"
        threat_id = "2147928783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 85 1c f7 ff ff 4c c6 85 1d f7 ff ff 6f c6 85 1e f7 ff ff 61 c6 85 1f f7 ff ff 64 c6 85 20 f7 ff ff 4c c6 85 21 f7 ff ff 69 c6 85 22 f7 ff ff 62 c6 85 23 f7 ff ff 72 c6 85 24 f7 ff ff 61 c6 85 25 f7 ff ff 72 c6 85 26 f7 ff ff 79 c6 85 27 f7 ff ff 57}  //weight: 2, accuracy: High
        $x_1_2 = {b9 6b 00 00 00 66 89 8d 6c e8 ff ff ba 65 00 00 00 66 89 95 6e e8 ff ff b8 72 00 00 00 66 89 85 70 e8 ff ff b9 6e 00 00 00 66 89 8d 72 e8 ff ff ba 65 00 00 00 66 89 95 74 e8 ff ff b8 6c 00 00 00 66 89 85 76 e8 ff ff b9 33 00 00 00 66 89 8d 78 e8 ff ff ba 32 00 00 00 66 89 95 7a e8 ff ff b8 2e 00 00 00 66 89 85 7c e8 ff ff b9 64 00 00 00 66 89 8d 7e e8 ff ff ba 6c 00 00 00 66 89 95 80 e8 ff ff b8 6c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_ALY_2147928906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.ALY!MTB"
        threat_id = "2147928906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 00 8d 86 ?? ?? ?? ?? 50 68 ff 03 00 00 8d 46 08 50 6a fd 8d 85 e4 fd ff ff 50 6a 00 ff 33}  //weight: 3, accuracy: Low
        $x_2_2 = {ab ab ab ab 8d 85 e4 dd ff ff 50 ff 15 ?? ?? ?? ?? 68 e8 ce 55 00 8d 85 e4 dd ff ff 50 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_NIT_2147929718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.NIT!MTB"
        threat_id = "2147929718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 04 68 00 10 00 00 56 57 ff 15 00 d2 57 00 85 c0 74 1a 8d 45 ec 50 68 04 01 00 00 56 57 ff 15 38 d4 57 00 85 c0}  //weight: 2, accuracy: High
        $x_2_2 = {68 0a 6f 55 00 ff 75 0c 6a 00 ff 15 28 d4 57 00 8b f8 85 ff 75 1e ff 15 10 d4 57 00 50 e8 78 e8 ff ff 59 83 cf ff 8d 4d fc e8 af fe ff ff 8b c7 5f 5e c9 c3 57 89 7e 08 ff 15 60 d3 57 00 83 f8 ff}  //weight: 2, accuracy: High
        $x_1_3 = {6a 00 6a 00 ff 15 10 da 57 00 6a 00 6a 00 6a 00 6a 03 6a 06 6a 00 6a 00 6a ff 6a 00 ff 15 0c da 57 00 8d 45 b4 50 68 30 88 5a 00 6a 01 6a 00 68 40 88 5a 00 ff 15 08 da 57 00 8b 35 ac d4 57 00 8d 85 00 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GPPC_2147930744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GPPC!MTB"
        threat_id = "2147930744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8d 41 b4 30 44 0d a0 48 ff c1 48 83 f9 3f 72 f0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_ALZY_2147931218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.ALZY!MTB"
        threat_id = "2147931218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 56 ff 74 88 fc 53 57 ff 15 2c d0 43 00 6a 00 6a 00 53 ff 35 34 d0 43 00 6a 00 6a 00 57 ff 15 24 d0 43 00 8b f0 68 10 27 00 00 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GTR_2147936323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GTR!MTB"
        threat_id = "2147936323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 01 0b 01 0e 2a 00 d2 00 00 00 1a 00}  //weight: 5, accuracy: High
        $x_5_2 = {40 00 00 40 2e 41 43 45 30 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AMOA_2147936374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AMOA!MTB"
        threat_id = "2147936374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 ce ff 46 8d 3c 32 8d 2c 30 8a 1f 30 5d 00 39 ce 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_HNU_2147938934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.HNU!MTB"
        threat_id = "2147938934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c4 60 c3 48 8d 05 68 6d 17 00 bb 21 00 00 00 e8 ec 37 02 00 90 48 89 44 24 08 48 89 5c 24 10 48 89 4c 24 18 48 89 7c 24 20 e8 d2 dc 04 00 48 8b 44 24 08 48 8b 5c 24 10 48 8b 4c 24 18 48 8b 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_WQ_2147939390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.WQ!MTB"
        threat_id = "2147939390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 eb 3b e7 4f bb de d0 bf a0 bc a7 ef 57 ee 36 af 15 fa 3d cf 9d fe 42 bc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_BSA_2147939623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.BSA!MTB"
        threat_id = "2147939623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "aHR0cDovLzg0LjI0Ny4xNzAuMjM3OjQ4NTgvZmx5X2JhY2s=" ascii //weight: 30
        $x_10_2 = "ScreenCap.png" ascii //weight: 10
        $x_5_3 = "pkill" ascii //weight: 5
        $x_3_4 = "shellexec" ascii //weight: 3
        $x_2_5 = "upload" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GPJ_2147939646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GPJ!MTB"
        threat_id = "2147939646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 ff 74 01 ea 31 3b 81 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GW_2147939737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GW!MTB"
        threat_id = "2147939737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 80 c1 ?? 32 4c 45 ?? 8d 42 ?? 88 0c 3e 46 0f b7 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GX_2147939738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GX!MTB"
        threat_id = "2147939738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 33 d0 8b 45 08 03 45 f0 88 10 66 8b 4d ?? 66 83 c1 ?? 66 89 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GY_2147939739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GY!MTB"
        threat_id = "2147939739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 08 0f b7 d6 80 c3 20 32 5c 55 ?? 46 88 1c 08 41 3b 4d 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_SC_2147939746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.SC!MTB"
        threat_id = "2147939746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 90 0c 00 00 10 00 00 00 e0 04 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 73 72 63 00 00 00 14 03 00 00 00 a0 0c 00 00 02 00 00 00 f0 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AYC_2147940217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AYC!MTB"
        threat_id = "2147940217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Encrypting payload with ChaCha20+XOR." ascii //weight: 2
        $x_1_2 = "Encrypted payload size: %u bytes." ascii //weight: 1
        $x_1_3 = "Output saved to packed.exe" ascii //weight: 1
        $x_1_4 = "\\Release\\bigDawg.pdb" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_HNV_2147940511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.HNV!MTB"
        threat_id = "2147940511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 00 5c 00 5c 00 25 00 6c 00 73 00 5c 00 25 00 6c 00 73 00 5c 00 25 00 6c 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_2_2 = "CreateToolhelp32Snapshot" ascii //weight: 2
        $x_1_3 = "GetComputerNameW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MBZ_2147940964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MBZ!MTB"
        threat_id = "2147940964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d ID: \"N2ILNbUimIXCE0IMV_xd/Cin94ZCSPQPVagQSCpa0/cT5BkHWKzhyB0QFem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_SCP_2147941654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.SCP!MTB"
        threat_id = "2147941654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 08 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8b 51 0c 31 c9 29 c1 31 c0 29 d0 01 c1 31 c0 29 c8 89 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GVA_2147942760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GVA!MTB"
        threat_id = "2147942760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 f7 bd ?? ?? ?? ?? 8a 04 ?? 30 04 31 41 3b ?? 72 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_GVB_2147942761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GVB!MTB"
        threat_id = "2147942761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 60 01 00 00 99 f7 ff 8b bd ?? ?? ?? ?? 8a 04 3a 8b bd ?? ?? ?? ?? 30 04 39 41 3b ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_TRZ_2147944204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.TRZ!MTB"
        threat_id = "2147944204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a ff 68 f0 87 0a 10 50 64 89 25 00 00 00 00 81 ec f0 02 00 00 33 c0 8a 88 ?? ?? ?? ?? 32 ca 42 88 4c 05 dd 81 e2 ff 00 00 80 79}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AF_2147944989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AF!MTB"
        threat_id = "2147944989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 85 4c e8 ff ff 33 c0 88 85 98 e8 ff ff 33 c9 88 8d 97 e8 ff ff 0f b6 95 98 e8 ff ff 52 0f b6 85 97 e8 ff ff 50 0f b6 8d 66 e8 ff ff 51 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AG_2147945017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AG!MTB"
        threat_id = "2147945017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f0 6d 66 89 45 e0 0f bf 4d c4 33 4d ec 81 f1 e4 03 00 00 88 4d fa 6b 15 40 21 4c 00 00 83 f2 3a 89 15 58 21 4c 00 8b 45 d8 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_KK_2147945650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.KK!MTB"
        threat_id = "2147945650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8a 08 32 ca 02 ca 88 08 40 4e}  //weight: 20, accuracy: High
        $x_10_2 = "Dkcsk.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_KK_2147945650_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.KK!MTB"
        threat_id = "2147945650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {0c b1 b5 01 db dd 33 c6 6e 32 97 4c 65 3e 9c}  //weight: 20, accuracy: High
        $x_10_2 = {ac 32 c4 fe c4 c0 c4 02 80 c4 90 aa e2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_KK_2147945650_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.KK!MTB"
        threat_id = "2147945650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {6a 00 57 6a 00 6a 00 6a 00 68 00 00 00 80 6a 00 68 00 00 00 80 68 00 00 cf 00 68 a0 74 ?? 00 68 d8 73 ?? 00 6a 00 ff}  //weight: 20, accuracy: Low
        $x_10_2 = {8b 4d bc 8b 14 8d 28 71 ?? 00 03 55 b4 8a 0c 03 03 d3 43 88 4c 32 2e 3b df}  //weight: 10, accuracy: Low
        $x_5_3 = "FakeChrome\\Release\\Chrome.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AD_2147945966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AD!MTB"
        threat_id = "2147945966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 83 e0 0f 8a 80 f8 e0 42 00 30 81 10 1b 43 00 8d ?? 10 1b 43 00 03 c1 83 e0 0f 8a 80 f8 e0 42 00 30 81 11 1b 43 00 8d ?? 10 1b 43 00 03 c1 83 e0 0f 8a 80 f8 e0 42 00 30 81 12 1b 43 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AE_2147945967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AE!MTB"
        threat_id = "2147945967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 83 f8 0a 0f 9c c3 20 c3 89 d0 20 c8 08 d8 30 d1 20 d1 89 ca 20 c2 30 c1 08 d1 89 c2 30 ca 80 f1 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_KKB_2147946091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.KKB!MTB"
        threat_id = "2147946091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {09 00 44 41 54 41 2e 62 61 74 00 0d 00 00 00 6e 6f 74 65 70 61 64 2e 65 78 65 0d 0a 31 07 00 5c 78 2e 65 78 65 00 04 00 00 00 61 42 43 44 72 0c 00 6e 6f 74 65 70 61 64 2e 65 78 65 00 00}  //weight: 20, accuracy: High
        $x_10_2 = {01 47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 00 00 94 02 57 69 6e 45 78 65 63 00 9e 02 57 72 69 74 65 46 69 6c 65 00 b5 02 6c 73 74 72 63 61 74 41 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_NS_2147946309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.NS!MTB"
        threat_id = "2147946309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a1 04 d0 40 00 56 85 c0 be 04 d0 40 00 74 17 8b 0d 00 d0 40 00 6a 00 51 6a 01 ff d0 8b 46 04 83 c6 04 85 c0 75 e9}  //weight: 2, accuracy: High
        $x_1_2 = {a1 40 dc 40 00 5e 85 c0 74 02 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_PGLZ_2147947940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.PGLZ!MTB"
        threat_id = "2147947940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 f0 8b 45 f4 01 d0 0f b6 00 89 c2 8b 45 d8 89 d1 31 c1 8b 55 f0 8b 45 f4 01 d0 89 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 ec 72 d4}  //weight: 5, accuracy: High
        $x_5_2 = {8b 55 fc 48 8b 45 f0 48 01 d0 0f b6 00 89 c2 8b 45 cc 89 d1 31 c1 8b 55 fc 48 8b 45 f0 48 01 d0 89 ca 88 10 83 45 fc 01 8b 45 fc 3b 45 ec 72 d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Lazy_GVH_2147949374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.GVH!MTB"
        threat_id = "2147949374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 5c 24 14 8b 74 24 10 8b ce b8 ?? ?? ?? ?? 83 e1 07 ba ?? ?? ?? ?? c1 e1 03 e8 14 40 00 00 30 04 3e 83 c6 01 83 d3 00 75 05 83 fe 0f 72 d9}  //weight: 2, accuracy: Low
        $x_1_2 = {80 f9 40 73 15 80 f9 20 73 06 0f ad d0 d3 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MK_2147952545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MK!MTB"
        threat_id = "2147952545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 69 64 61 74 61 20 20 00 10 00 00 00 f0 05 00 00 02 00 00 00 e2 05}  //weight: 10, accuracy: High
        $x_10_2 = {20 20 20 00 20 20 20 20 00 d0 05 00 00 10 00 00 00 d0 05 00 00 10}  //weight: 10, accuracy: High
        $x_10_3 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? 02 00 00 00 e0 05 00 00 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MKA_2147952546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MKA!MTB"
        threat_id = "2147952546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {80 f1 01 34 01 08 d1 20 c5 30 e0 80 f1 01 08 e8 08 d9 88 c4}  //weight: 15, accuracy: High
        $x_10_2 = {0f 94 c5 0f 95 c4 83 fa 0a 0f 9c 04 24 83 fa ?? 88 e8 88 64 24 10 88 6c 24 14 0f 9f c1 30 e0 20 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MKB_2147953529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MKB!MTB"
        threat_id = "2147953529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {8a d1 2a d3 88 13 8d 43 01 89 85 00 af ff ff 8b c7 99 f7 bd 00 af ff ff 89 85 a0 ae ff ff 3b f3}  //weight: 15, accuracy: High
        $x_10_2 = {0f b7 95 18 af ff ff 03 95 f0 ae ff ff 2b c6 03 85 a8 ae ff ff 0f b6 f9 03 85 a0 ae ff ff 0f b6 cb 03 f9 3b d7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_CM_2147953811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.CM!MTB"
        threat_id = "2147953811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_new.exe" ascii //weight: 1
        $x_1_2 = "MLogin.exe" ascii //weight: 1
        $x_1_3 = "http://110.42.4.105" ascii //weight: 1
        $x_1_4 = "Unable to install hook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_PGLY_2147953986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.PGLY!MTB"
        threat_id = "2147953986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 e9 80 e5 ?? f6 d1 89 ca 80 e2 ?? 08 d5 89 c2 24 ?? 80 f2 ?? 08 d1 80 e2 ?? 08 d0 f6 d1 30 e8 08 c1 88 4c 3d 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MKC_2147956189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MKC!MTB"
        threat_id = "2147956189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {2b cf 03 de f7 f1 8b 4d ec 46 8a 04 3a 32 04 0b 88 03 8b 5d f0 3b 75 e4}  //weight: 15, accuracy: High
        $x_10_2 = {83 7d e8 07 8d 45 d4 89 7d e4 0f 47 45 d4 89 45 c0 8d 3c 48 85 d2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AHM_2147956202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AHM!MTB"
        threat_id = "2147956202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8b f4 89 75 f0 89 3e 89 7e ?? 89 7e ?? 8b 45 e0 2b 45 dc 74}  //weight: 30, accuracy: Low
        $x_20_2 = "MianVjsdhan" ascii //weight: 20
        $x_10_3 = "NYIRNWRG" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_PGLC_2147957436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.PGLC!MTB"
        threat_id = "2147957436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 c0 81 ef ?? ?? ?? ?? 29 c7 e8 ?? ?? ?? ?? 29 c0 bf ?? ?? ?? ?? 09 c0 31 0b 01 c0 81 c3 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 39 f3 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MB_2147957460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MB!MTB"
        threat_id = "2147957460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e0 03 0f b6 80 ?? ?? ?? ?? 66 33 44 4c 60 66 89 84 4c ?? ?? ?? ?? 41 83 f9 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MKD_2147958983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MKD!MTB"
        threat_id = "2147958983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "VFPower_32.dll" ascii //weight: 15
        $x_10_2 = "VFPower_32" ascii //weight: 10
        $x_5_3 = "YourSharedSecretKey" ascii //weight: 5
        $x_3_4 = "KEY_BOARD_DATA" ascii //weight: 3
        $x_2_5 = "KEY_BOARD_DATA_MD5" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_MKF_2147958984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.MKF!MTB"
        threat_id = "2147958984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {56 00 6c 00 61 00 64 00 69 00 6d 00 69 00 72 00 b5 00 f9 00 24 00 73 00 64 00 73 00 34 00 31 00 32 00 31 00 32 00 31 00 00 00 00 00 90 90 00 00}  //weight: 15, accuracy: High
        $x_10_2 = "spideggghj$+9999%%" ascii //weight: 10
        $x_5_3 = "\\windowsupdate\\mservice.exe" ascii //weight: 5
        $x_3_4 = "//b //nologo" ascii //weight: 3
        $x_2_5 = "{CONTROLDOWN}l{CONTROLUP}" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_LMJ_2147959067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.LMJ!MTB"
        threat_id = "2147959067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {89 7d b4 8d 45 b0 89 45 ac 8d 45 a8 89 45 a0 c7 45 c0 75 18 bc a3 c7 45 c4 3e 06 83 0d 33 c0 66 89 45 c8 b8 01 00 00 00 66 89 45 b8 8d 45 c0 89 45 bc 8d 45 b8 89 45 9c}  //weight: 20, accuracy: High
        $x_10_2 = {8b 4c 24 30 8b c2 d1 ff 2b c1 89 4c 24 18 3b f8 77 ?? 8d 04 39 83 fa 07 89 44 24 30 8d 74 24 20 0f 47 74 24 20}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_AHL_2147959804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.AHL!MTB"
        threat_id = "2147959804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "AV Killer ON" ascii //weight: 10
        $x_20_2 = "Check this to Enable the Anti-Virus Killer option" ascii //weight: 20
        $x_30_3 = "Check this to change the icon of the output file" ascii //weight: 30
        $x_40_4 = "Crypt the file" ascii //weight: 40
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_ARR_2147959952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.ARR!MTB"
        threat_id = "2147959952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Starting HTTP Bypass Flood on" ascii //weight: 4
        $x_6_2 = "{\"query\":\"{ __schema { types { name fields { name } } } }\"}" ascii //weight: 6
        $x_10_3 = "https://bitbucket.org/sekkka/taha/raw/main/ryx.txt" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazy_LML_2147960056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazy.LML!MTB"
        threat_id = "2147960056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {66 89 04 6e b9 4b 00 00 00 66 89 4c 24 28 ba 45 00 00 00 66 89 54 24 2a b8 52 00 00 00 66 89 44 24 2c 66 89 54 24 30 b9 4e 00 00 00 66 89 4c 24 2e b8 4c 00 00 00 66 89 44 24 32 ba 32 00 00 00 66 89 54 24 36 b9 33 00 00 00 66 89 4c 24 34 ba 4c 00 00 00 b8 2e 00 00 00 66 89 44 24 38 8b c2 b9 44 00 00 00 66 89 54 24 3c 66 89 4c 24 3a b2 72}  //weight: 20, accuracy: High
        $x_10_2 = "Micros0ftEdgeUpdateTask0UA Task-S-1-5-18" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

