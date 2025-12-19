rule Trojan_Win64_StealC_MKV_2147848524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.MKV!MTB"
        threat_id = "2147848524"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 c1 e8 ?? ?? ?? ?? 48 63 45 ?? 0f b6 44 05 ?? 48 63 4d c0 0f b6 4c 0d e0 01 c8 b9 ?? ?? ?? ?? 99 f7 f9 48 63 c2 44 0f b6 44 05 ?? 48 8b 85 ?? ?? ?? ?? 48 63 4d bc 0f b6 14 08 44 31 c2 88 14 08 8b 45 ?? 83 c0 01 89 45 bc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_YAB_2147891506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.YAB!MTB"
        threat_id = "2147891506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 03 c8 48 8b c1 48 89 84 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 8b 00 33 c1 48 8b 8c 24 ?? ?? ?? ?? 89 01 8b 44 24 5c 83 c0 04 89 44 24}  //weight: 5, accuracy: Low
        $x_5_2 = {ff c0 89 44 24 28 8b 44 24 24 39 44 24 28 73 33 48 8b 84 24 ?? ?? ?? ?? ff 50 10 48 98 33 d2 b9 1a 00 00 00 48 f7 f1 48 8b c2 66 0f be 44 04 58 48 63 4c 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_DAZ_2147898565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.DAZ!MTB"
        threat_id = "2147898565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 ff c0 49 63 c8 42 0f b6 04 09 42 88 04 0e 48 8b 44 24 ?? 88 14 01 4c 8b 4c 24 ?? 42 0f b6 0c 0e 48 03 ca 0f b6 c1 42 0f b6 0c 08 41 30 0c 1b 49 ff c3 49 81 fb 1b d6 01 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_NS_2147902479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.NS!MTB"
        threat_id = "2147902479"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7d 20 48 63 44 24 ?? 48 8b 4c 24 58 8b 04 01 03 44 24 ?? 48 63 4c 24 ?? 48 8b 54 24 30 89 04}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 44 24 20 83 c0 ?? 89 44 24 20 81 7c 24 20 00 60}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_KAD_2147906221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.KAD!MTB"
        threat_id = "2147906221"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 04 80 6d ?? ?? 8b 45 ?? c1 e0 ?? 89 c2 8b 45 ?? 01 c2 0f b6 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_AST_2147906962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.AST!MTB"
        threat_id = "2147906962"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 c1 e4 38 49 c1 e7 30 4d 09 e7 49 c1 e6 28 48 c1 e3 20 48 c1 e7 18 49 c1 e3 10 49 c1 e1 08 4d 09 d1 4d 09 d9 49 09 f9 49 09 d9 4d 09 f1 4d 09 f9 4e 33 0c 00 4e 89 4c 05 f0 45 31 c9 49 89 d0}  //weight: 1, accuracy: High
        $x_1_2 = {44 0f b6 44 0a 02 41 c1 e0 10 44 0f b7 0c 0a 45 01 c8 41 81 c0 00 00 00 cb 44 33 04 10 44 89 44 15 f0 48 83 c2 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_GY_2147937379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.GY!MTB"
        threat_id = "2147937379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 d1 44 30 c1 20 ca 30 d1 08 d1 44 30 c1 44 30 c0 89 c2 30 ca 20 c8}  //weight: 3, accuracy: High
        $x_1_2 = {30 c8 20 d1 44 08 c2 44 30 e2 08 c2 89 d0 44 30 e0 44 20 c3 08 cb 89 c1 20 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_GZ_2147940726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.GZ!MTB"
        threat_id = "2147940726"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 94 c0 0f 94 44 24 7f 83 fd 0a 0f 9c 84 24 ?? ?? ?? ?? 4d 89 c6 49 89 d4 49 89 cd 0f 9c c1 08 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_GVB_2147944460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.GVB!MTB"
        threat_id = "2147944460"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 c1 0f b6 c1 8a 84 04 90 01 00 00 48 63 4c 24 74 41 30 04 0f}  //weight: 2, accuracy: High
        $x_2_2 = {01 c1 0f b6 c1 8a 84 04 90 01 00 00 48 63 4c 24 74 49 89 df 30 04 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_StealC_GVE_2147945300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.GVE!MTB"
        threat_id = "2147945300"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 c1 e1 02 45 01 c8 45 89 c0 44 89 c2 44 0f b6 04 10 44 31 c1 41 88 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_GVC_2147946064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.GVC!MTB"
        threat_id = "2147946064"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 c1 0f b6 c1 8a 84 04 90 01 00 00 48 63 4c 24 74 4d 89 f2 41 30 04 0e}  //weight: 2, accuracy: High
        $x_2_2 = {2f f2 69 c1 55 f4 c9 16 56 4b 59 8c 1e f1 00 d7 04 92 9c ee 96 83 8e 78 60 9a a2 88 05 a7 4d 9f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_StealC_VST_2147948370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.VST!MTB"
        threat_id = "2147948370"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 40 20 48 89 84 24 90 00 00 00 b8 fd 06 f1 b5 3d 78 51 f0 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_AHB_2147949112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.AHB!MTB"
        threat_id = "2147949112"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 4c 24 48 48 8b 51 ?? 48 89 10 48 8b 51 ?? 48 89 50 08 48 8b 54 24 28 48 89 50 ?? 48 8b 54 24 58 48 89 50}  //weight: 10, accuracy: Low
        $x_5_2 = {48 c7 84 24 08 01 00 00 6f 00 00 00 48 c7 84 24 10 01 00 00 61 00 00 00 48 c7 84 24 18 01 00 00 64 00 00 00 48 c7 84 24 20 01 00 00 44 00 00 00 48 c7 84 24 28 01 00 00 6c 00 00 00 48 c7 84 24 30 01 00 00 6c}  //weight: 5, accuracy: High
        $x_3_3 = "main.writeShellcodeToTarget" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_2147950837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.MTH!MTB"
        threat_id = "2147950837"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 7c 3c 18 41 31 f9 46 88 0c 00 49 8d 48 01 48 39 ce 7e 1e 48 89 cf 48 83 e1 f0 49 89 f8 48 29 cf 46 0f b6 0c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_GVF_2147951529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.GVF!MTB"
        threat_id = "2147951529"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 bc 34 7b 02 00 00 0f b6 94 14 6b 02 00 00 31 fa 88 14 30 48 8d 4e 01 48 83 f9 1d 7d 1d 48 89 ca 48 83 e1 f0 48 89 d6 48 29 ca 48 83 fa 10 72 ce}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 7c 34 29 0f b6 54 14 19 31 d7 40 88 3c 30 48 8d 4e 01 48 83 f9 17 7d 15 48 89 ca 48 83 e1 f0 48 89 d6 48 29 ca 48 83 fa 10 72 d3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_StealC_ASE_2147955148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.ASE!MTB"
        threat_id = "2147955148"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 04 3a 48 ff c7 66 ?? 48 39 f9 7e ?? 44 0f b7 04 7e 4c 39 c3 76 ?? 46 0f b6 04 00 48 39 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_SG_2147957049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.SG!MTB"
        threat_id = "2147957049"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 0f b6 94 04 ?? ?? ?? ?? 45 0f b6 1c 09 41 01 c3 45 31 d3 46 88 9c 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_AHC_2147958256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.AHC!MTB"
        threat_id = "2147958256"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 44 24 38 48 8d 4c 24 20 48 8d 84 24 90 00 00 00 c7 44 24 24 ?? 00 00 00 48 89 44 24 40 ff 15}  //weight: 5, accuracy: Low
        $x_30_2 = "/c bitsadmin /transfer job_%x /download /priority normal" ascii //weight: 30
        $x_20_3 = "-urlcache -split -f \"%s\" \"%s" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_AHD_2147958815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.AHD!MTB"
        threat_id = "2147958815"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {44 0f b6 73 11 41 c1 e6 ?? 41 0b ee 44 0f b6 73 12 41 c1 e6 ?? 41 0b ee 44 0f b6 73 13 41 c1 e6 ?? 41 0b ee}  //weight: 30, accuracy: Low
        $x_20_2 = {8b ce 40 0f b6 7c 0b ?? 49 8b cf e8 ?? ?? ?? ?? 33 c7 40 0f b6 f8 41 3b 76}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_SX_2147958877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.SX!MTB"
        threat_id = "2147958877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 11 44 24 54 0f 11 44 24 64 0f 11 44 24 74 0f 11 45 84 0f 11 45 94 0f 11 45 a4 0f 11 45 b0 48 8d 05 ?? ?? ?? ?? 48 89 44 24 60 48 8d 85 e0 ?? ?? ?? 48 89 44 24 68 48 89 7c 24 58 c7 45}  //weight: 10, accuracy: Low
        $x_5_2 = {48 63 c8 49 8b c6 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 44 0f b6 0c 29 48 8b 43 ?? 48 8b 53 ?? 48 3b c2 73}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_PGSC_2147958915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.PGSC!MTB"
        threat_id = "2147958915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b 04 24 48 ff c0 48 89 04 24 48 8b 44 24 ?? 48 39 04 24 73 ?? 33 d2 48 8b 04 24 48 f7 74 24 ?? 48 8b c2 48 8b 4c 24 ?? 0f b6 04 01 48 8b 0c 24 48 8b 54 24 ?? 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 0c 24 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 01 eb}  //weight: 5, accuracy: Low
        $x_5_2 = {40 65 63 68 6f 20 6f 66 66 0a 73 74 61 72 74 20 22 22 20 22 25 73 22 0a 73 74 61 72 74 20 22 22 20 22 25 73 22 0a 74 69 6d 65 6f 75 74 20 2f 74 20 35 20 2f 6e 6f 62 72 65 61 6b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_FG_2147959317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.FG!MTB"
        threat_id = "2147959317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 9a 99 99 99 99 99 b9 3f 48 89 84 24 70 01 00 00 48 b8 9a 99 99 99 99 99 c9 3f 48 89 84 24 78 01 00 00 48 b8 33 33 33 33 33 33 d3 3f 48 89 84 24 80 01 00 00 48 b8 9a 99 99 99 99 99 d9 3f 48 89 84 24 88 01 00 00 48 b8 00 00 00 00 00 00 e0 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_StealC_MB_2147959839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealC.MB!AMTB"
        threat_id = "2147959839"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "genserv333.top" ascii //weight: 2
        $x_2_2 = "Notification Client/1.0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

