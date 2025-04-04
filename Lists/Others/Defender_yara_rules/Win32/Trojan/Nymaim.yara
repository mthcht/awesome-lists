rule Trojan_Win32_Nymaim_2147688041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim"
        threat_id = "2147688041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fe 00 74 ?? 31 c0 2b 01 f7 d8 f8 83 d9 fc f8 83 d8 1e 01 d0 f8 83 d0 ff 8d 10 50 8f 07 8d 7f 04 8d 76 fc eb}  //weight: 1, accuracy: Low
        $x_1_2 = {6f 64 62 63 63 6f 6e 66 2e 64 6c 6c 00 63 6e 61 61 61 72 6f 5f 65 73 73 5f 5f 6d 6f 72 79 00 63 69 72 74 75 75 6c 41 6c 6c 6f 63 00 64 62 72 6e 65 6c 33 32 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_SD_2147729935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.SD!MTB"
        threat_id = "2147729935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 c0 2b 06 f7 d8 83 ee fc 83 e8 2e c1 c8 08 29 f8 83 e8 01 50 5f c1 c7 0a c1 cf 02 c7 03 00 00 00 00 31 03 83 c3 04 83 e9 04 85 c9 75 d2 5b 8b 15 04 f7 49 00 52 89 1d 14 f7 49 00 ff 15 14 f7 49 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_VC_2147730484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.VC!MTB"
        threat_id = "2147730484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 5a 52 6a ff 5b 23 1f 8d 7f 04 83 eb 2e c1 cb 08 29 cb 4b 53 59 c1 c1}  //weight: 5, accuracy: High
        $x_5_2 = {46 58 5a 73 3d 47 06 55 40 5e 50 d7 8b b9 c1 f0 dc 29 02 45 7c b9 af}  //weight: 5, accuracy: High
        $x_1_3 = {8b 74 24 04 55 e8 c8 05 00 00 58 50 ff d6 8b d8 e8 f0 05 00 00 5d 8b f5 b9 11 00 00 00 ad e8 cc 02 00 00 89 46 fc e2 f5 8b 45 2c 80 38 8b 75}  //weight: 1, accuracy: High
        $x_1_4 = {ad 50 83 e8 00 35 ac 32 41 95 2b c2 5a ab 83 e9 03 e2 db 61 c3 66 33 f6 66 ba 4d 5a}  //weight: 1, accuracy: High
        $x_1_5 = {57 56 53 e8 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e8 13 00 00 00 5b 5e 5f c3}  //weight: 1, accuracy: High
        $x_1_6 = {8a 1c 2f 81 e2 00 ff ff ff 0f b6 c1 09 c2 89 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 30 cb 03 54 24 18 c1 c2 08 88 1c 2f}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 4e 0c 8b 44 31 24 85 c0 74 02 89 07 8d 56 10 03 54 31 20 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nymaim_YA_2147734385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.YA"
        threat_id = "2147734385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ybhinllytnhglmvsi" ascii //weight: 1
        $x_1_2 = "jfllzundpxmxpszl" ascii //weight: 1
        $x_1_3 = "pbkilfkyu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_PB_2147734481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.PB!MTB"
        threat_id = "2147734481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 fe 88 06 00 00 74 34 6a ff 5f 23 38 83 c0 04 8d 7f cd c1 cf 08 29 cf 83 c7 ff 8d 0f c1 c1 09 d1 c9 6a 00 8f 02 01 3a 8d 52 04 83 c6 04 8d 3d 1e 16 e1 ff 81 c7 c7 21 5f 00 57 c3}  //weight: 1, accuracy: High
        $x_1_2 = {5a 8b 35 bc 4a 4a 00 56 8d 35 46 7c 21 fd 81 c6 4e bb 1e 03 56 52 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_PA_2147734570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.PA!MTB"
        threat_id = "2147734570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 88 06 00 00 74 34 6a ff 5f 23 38 83 c0 04 8d 7f cd c1 cf 08 29 cf 83 c7 ff 8d 0f c1 c1 09 d1 c9 6a 00 8f 02 01 3a 8d 52 04 83 c6 04 8d 3d ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 57 c3 5a 8b 35 ?? ?? ?? ?? 56 8d 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 56 52 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {29 db 2b 19 f7 db 83 e9 fc 83 c3 cd c1 cb 08 29 fb 8d 5b ff 31 ff 29 df f7 df c1 c7 09 d1 cf 6a 00 8f 02 01 1a 83 c2 04 83 e8 fc 3d 88 06 00 00 75 ce 5a 8b 3d ?? ?? ?? ?? 57 8d 3d ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 57 52 83 c4 04 ff 64 24 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {31 c0 2b 01 f7 d8 83 c1 04 83 c0 dd 01 d0 83 e8 01 50 5a c7 03 00 00 00 00 09 03 83 c3 04 83 ef fc 81 ff 88 06 00 00 75 d7 5b 8d 3d ?? ?? ?? ?? ff 37 31 ff 68 ?? ?? ?? ?? ff e3}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 11 8d 49 04 83 c2 cd c1 ca 08 29 fa 4a 29 ff 29 d7 f7 df c1 c7 09 d1 cf 6a 00 8f 03 01 53 00 8d 5b 04 8d 40 04 3d 88 06 00 00 75 d3 5b 8b 0d ?? ?? ?? ?? 51 8d 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 51 53 89 e3 83 c4 04 ff 23}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 11 8d 49 04 83 c2 cd c1 ca 08 29 fa 4a 29 ff 29 d7 f7 df c1 c7 09 d1 cf 6a 00 8f 03 01 53 00 8d 5b 04 8d 40 04 3d 88 06 00 00 75 d3 5b 8b 0d ?? ?? ?? ?? 51 8d 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 51 ff e3}  //weight: 1, accuracy: Low
        $x_1_6 = {81 f9 88 06 00 00 74 2c 31 d2 2b 13 f7 da 83 c3 04 83 c2 dd 01 f2 4a 29 f6 01 d6 c6 07 00 01 17 83 c7 04 83 e9 fc 8d 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 52 c3 5f 8d 1d ?? ?? ?? ?? ff 33 31 db 68 ?? ?? ?? ?? 57 c3}  //weight: 1, accuracy: Low
        $x_1_7 = {68 88 06 00 00 5f 8d 08 51 85 ff 74 33 31 db 2b 1e f7 db 83 c6 04 83 c3 dd 01 d3 83 c3 ff 29 d2 29 da f7 da c7 01 00 00 00 00 09 19 83 c1 04 83 c7 fc 8d 1d b3 70 3e 00 81 c3 40 e2 01 00 53 c3 59 8d 05 ?? ?? ?? ?? ff 30 31 c0 68 ?? ?? ?? ?? 51 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Nymaim_2147740108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim!MTB"
        threat_id = "2147740108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 04 83 c6 ?? c1 ce 08 29 ce 83 c6 ff 31 c9 09 f1 c1 c1 0a c1 c9 02 c7 07 00 00 00 00 01 37 83 c7 04 8d 5b 04 81 fb 88 06 00 00 75 cf 5f 8b 0d ?? ?? ?? 00 51 89 3d ?? ?? ?? 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c3 04 83 c7 ?? c1 cf 08 29 d7 83 c7 ff 57 5a c1 c2 ?? c1 ca ?? c7 06 00 00 00 00 01 3e 83 ee fc 83 e8 fc 3d 88 06 00 00 75 ?? 5e 8b 0d ?? ?? ?? 00 51 89 35 ?? ?? ?? 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Nymaim_DEA_2147757616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.DEA!MTB"
        threat_id = "2147757616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 2b 13 f7 da 83 eb fc 83 c2 dd 01 f2 4a 29 f6 01 d6 c6 07 00 01 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_NEAA_2147835904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.NEAA!MTB"
        threat_id = "2147835904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "XxNWhka" ascii //weight: 5
        $x_5_2 = "ZTUWVSPRTj" ascii //weight: 5
        $x_5_3 = "1.3.2.8" wide //weight: 5
        $x_5_4 = "Searcher" wide //weight: 5
        $x_3_5 = "C:\\TEMP\\is-JBN0K.tmp" ascii //weight: 3
        $x_3_6 = "is-N9G0B.tmp" wide //weight: 3
        $x_1_7 = "VirtualAlloc" ascii //weight: 1
        $x_1_8 = "Inno Setup Setup Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_NEAB_2147835906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.NEAB!MTB"
        threat_id = "2147835906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\TEMP\\is-JBN0K.tmp\\is-N9G0B.tmp" ascii //weight: 5
        $x_4_2 = "GTSearcher" ascii //weight: 4
        $x_4_3 = "1.3.2.84" ascii //weight: 4
        $x_3_4 = "lsdsemihidden0" ascii //weight: 3
        $x_3_5 = "Moja glasba" wide //weight: 3
        $x_2_6 = "Spawning _RegDLL.tmp" ascii //weight: 2
        $x_1_7 = "IsPowerUserLoggedOn" ascii //weight: 1
        $x_1_8 = "regsvr32.exe" ascii //weight: 1
        $x_1_9 = "Inno Setup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_RPY_2147898669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.RPY!MTB"
        threat_id = "2147898669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 f8 8b 45 f8 8b 48 1c 89 4d f4 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 55 f4 89 45 fc 8b 45 fc 8b e5 5d c2 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_RPZ_2147898670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.RPZ!MTB"
        threat_id = "2147898670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f8 6e c6 45 f9 74 c6 45 fa 64 c6 45 fb 6c c6 45 fc 6c c6 45 fd 00 c6 45 ec 61 c6 45 ed 64 c6 45 ee 76 c6 45 ef 61 c6 45 f0 70 c6 45 f1 69 c6 45 f2 33 c6 45 f3 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_GPD_2147902203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.GPD!MTB"
        threat_id = "2147902203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {df e2 20 38 ee ce 16 b6 98 cf 59 2d 66 98 73 78 d7 5a b6 91 66 b5 e4 e1 bd 87 fc fb ff df bf}  //weight: 5, accuracy: High
        $x_5_2 = {73 de c7 8b c8 9a 19 b1 37 65 8a 23 a5 32 94 b9 48 7d 19 ef 79 e2 c4 7b 79 7e 41 8c c3 48 0c a6 2e 04 46 9c d9 3c c9 c7 c0 7a 39 32 f6 a3 4a a9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_GXZ_2147903618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.GXZ!MTB"
        threat_id = "2147903618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 c0 13 1d ?? ?? ?? ?? 01 f8 b5 01 00 c5 83 db ?? 18 35 ?? ?? ?? ?? 81 1d ?? ?? ?? ?? b2 00 00 00 29 fb 19 ca 0b 0d ?? ?? ?? ?? 6a 00 81 34 24 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 40 50 8d 05 ?? ?? ?? ?? 40 50 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_NM_2147910277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.NM!MTB"
        threat_id = "2147910277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ec 10 89 44 24 ?? 8b 4c 24 18 89 e2 89 4a ?? 89 02 e8 39 00 00 00 83 ec ?? 8b 44 24 1c 05 ?? ?? ?? ?? 89 44 24 40 8b 44 24 ?? 8b 4c 24 1c 89 48 ?? 8b 44 24 44 8b 4c 24 ?? 89 48 58 8b 44 24 1c}  //weight: 5, accuracy: Low
        $x_1_2 = "swank_tool2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_NI_2147911646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.NI!MTB"
        threat_id = "2147911646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c1 e0 04 8b 44 01 ?? 89 44 24 50 8b 44 24 ?? 8b 4c 24 30 89 8c 24 ?? ?? ?? ?? 8b 54 24 2c}  //weight: 3, accuracy: Low
        $x_3_2 = {0f b7 b4 24 ?? ?? ?? ?? 01 f6 66 89 f7 66 89 bc 24 ?? ?? ?? ?? 89 44 24 54 8b 74 24 50 31 c6}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_BAC_2147934269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.BAC!MTB"
        threat_id = "2147934269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {58 23 02 83 ea ?? f8 83 d0 ?? c1 c8 ?? 29 f8 83 c0 ?? 89 c7 c1 c7 ?? 89 03 f8 83 d3}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_BAB_2147934832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.BAB!MTB"
        threat_id = "2147934832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8f 45 e4 8b c8 50 8f 45 e8 8a 4d e3 0a 4d ed 80 e1 00 0b c1 8d 00 32 05 ?? ?? ?? ?? 88 45 ef}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_BAA_2147935599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.BAA!MTB"
        threat_id = "2147935599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5b 23 1f 8d 7f 04 83 eb 2f c1 cb 08 29 cb 4b 53 59 c1 c1 09 d1 c9 89 1a 8d 52 04 83 ee fc 81 fe 88 06 00 00 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_BAD_2147935604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.BAD!MTB"
        threat_id = "2147935604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {21 c6 56 ff 32 58 f8 83 d2 04 f8 83 d0 d4 c1 c8 08 29 d8 48 89 c3 c1 c3 08 89 06}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_BAE_2147935994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.BAE!MTB"
        threat_id = "2147935994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {31 c0 33 01 83 e9 fc f8 83 d0 d4 c1 c8 08 29 d8 83 c0 ff 89 c3 c1 c3 08 50 8f 02 8d 52 04 f8 83 d6 fc 85 f6}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymaim_BAF_2147937899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymaim.BAF!MTB"
        threat_id = "2147937899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 59 51 29 c0 0b 02 f8 83 d2 04 83 e8 2c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

