rule Trojan_Win32_Rhadamanthys_GA_2147839696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.GA!MTB"
        threat_id = "2147839696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 75 f8 ff 15 [0-4] 8d 45 f0 50 ff 25 30 ?? 42 00}  //weight: 10, accuracy: Low
        $x_1_2 = {8b 9b a8 00 00 00 8d 4d 08 03 5e 08 51 ff 76 10 50 53 ff d7}  //weight: 1, accuracy: High
        $x_1_3 = "7ARQAAAASCIJAQAEAAABIAIBA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rhadamanthys_A_2147841907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.A!MTB"
        threat_id = "2147841907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 95 e8 e5 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {f7 fb 89 74 24 20 db 44 24 20 d9 05 f8 ff 81 11 d9 c1 d8 c9 89 44 24 10 db 44 24 10 8b 84 24 ?? 00 00 00 de f9 d9 5c 24 6c d9 44 24 6c d9 80 f8 95 00 00 d9 c0 d8 35 fc ff 81 11 d9 05 e4 ff 81 11 d9 5c 24 5c d9 cb df f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_A_2147841907_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.A!MTB"
        threat_id = "2147841907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 da c1 e2 ?? 03 54 24 ?? 8d 3c 33 31 d7 89 da c1 ea ?? 01 ea 31 fa 29 d0 89 c2 c1 e2 ?? 03 14 24 8d 3c 06 31 d7 89 c2 c1 ea ?? 03 54 24 ?? 31 fa 29 d3 81 c6}  //weight: 2, accuracy: Low
        $x_2_2 = {89 c2 c1 e2 ?? 01 fa 89 fd 8d 3c 30 31 d7 89 c2 c1 ea ?? 03 54 24 ?? 31 fa 01 d3 89 da c1 e2 ?? 03 54 24 ?? 8d 3c 1e 31 d7 89 da c1 ea ?? 03 14 24 31 fa 89 ef 01 d0 81 c6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_B_2147842343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.B!MTB"
        threat_id = "2147842343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f9 6b c0 ?? c1 e0 ?? 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a eb}  //weight: 2, accuracy: Low
        $x_2_2 = {f7 fe 8b 45 08 0f be 14 10 6b d2 ?? 81 e2 ?? ?? ?? ?? 33 ca 88}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_GHN_2147844931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.GHN!MTB"
        threat_id = "2147844931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c3 8d 4c 24 28 03 f0 8a 16 02 f2 0f b6 c6 03 c8 0f b6 01 88 06 88 11 0f b6 0e 0f b6 c2 03 c8 0f b6 c1 8b 4c 24 ?? 0f b6 44 04 ?? 30 04 0f 47 3b 7c 24 14 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_MK_2147845127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.MK!MTB"
        threat_id = "2147845127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 44 24 ?? 03 fe 31 7c 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_JJH_2147845128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.JJH!MTB"
        threat_id = "2147845128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 c1 ea ?? 03 54 24 ?? 03 fe 31 7c 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_GHQ_2147845405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.GHQ!MTB"
        threat_id = "2147845405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d3 d3 ea 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 54 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_GHU_2147845575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.GHU!MTB"
        threat_id = "2147845575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 00 6c 00 c7 05 ?? ?? ?? ?? 32 00 2e 00 66 a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 6d 00 73 00 66 89 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 67 00 33 00 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_IKJ_2147845592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.IKJ!MTB"
        threat_id = "2147845592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 ?? 51 03 c5 50 8d 54 24 ?? 52 89 4c 24 ?? e8 ?? ?? ?? ?? 2b 74 24 ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 89 74 24 ?? 0f 85 42 00 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 33 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_RDA_2147845699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.RDA!MTB"
        threat_id = "2147845699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 54 24 18 89 56 48 03 6f 20 13 5f 24 89 6e 30 89 5e 34 8b 54 24 24 89 56 38 89 4e 3c 89 c1 83 c9 10 89 4e 1c a8 40}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_GMT_2147845945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.GMT!MTB"
        threat_id = "2147845945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4c 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cf 8d 44 24 ?? 89 54 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 50 51 8d 54 24 ?? 52 e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? ?? ?? ?? ?? 83 eb ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_MNV_2147846133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.MNV!MTB"
        threat_id = "2147846133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 03 cb 33 ca 03 c5 33 c1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 10 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ce c1 e9 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8d 14 37 31 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_USR_2147846953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.USR!MTB"
        threat_id = "2147846953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8a 16 02 f2 0f b6 c6 03 c8 0f b6 01 88 06 88 11 0f b6 06 0f b6 ca 03 c8 0f b6 c1 8b 8d ?? ?? ?? ?? 0f b6 84 05 ?? ?? ?? ?? 30 04 0f 47 3b bd ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_XWA_2147847944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.XWA!MTB"
        threat_id = "2147847944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 ?? 8d 34 2f c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 18 8b 44 24 28 01 44 24 18 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 4c 24 38 51 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 54 24 18 8b 44 24 14 33 d6 33 c2 2b d8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 14 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_VVI_2147848590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.VVI!MTB"
        threat_id = "2147848590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 8b 4d 10 83 c4 0c 2b c8 89 5d ?? 8a 14 06 32 10 88 14 01 40 ff 4d fc 75 ?? 53 8d 45 ec 50 ff 75 08 e8 ?? ?? ?? ?? 01 5d 0c 01 5d 10 83 c4 0c 2b f3 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_IKO_2147849114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.IKO!MTB"
        threat_id = "2147849114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 14 8b 44 24 ?? 31 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 57 57 57 ff 15 ?? ?? ?? ?? 8b 4c 24 10 33 4c 24 14 8d 44 24 2c 89 4c 24 10 e8 ?? ?? ?? ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_ILM_2147849115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.ILM!MTB"
        threat_id = "2147849115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 54 24 14 8b 44 24 38 01 44 24 14 8b 44 24 24 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 57 57 57 ff 15 ?? ?? ?? ?? 8b 44 24 10 33 44 24 ?? 89 44 24 10 2b f0 8d 44 24 ?? e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_THR_2147849405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.THR!MTB"
        threat_id = "2147849405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 03 32 18 83 c0 04 88 5c 28 fc 8b 5c 24 14 8a 1c 0b 32 58 fd 83 c1 04 88 59 fc 8a 58 fe 32 5e ff 83 c6 04 88 59 fd 8a 58 ff 32 5e fc 88 59 fe ff 4c 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_MPV_2147849491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.MPV!MTB"
        threat_id = "2147849491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 e9 ?? 8d 3c 33 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 18 8b 44 24 28 01 44 24 18 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 54 24 38 52 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 18 8b 44 24 14 33 cf 33 c1 2b e8 8d 44 24 1c e8 70 ?? ?? ?? ?? 4c 24 20 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_KMS_2147852419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.KMS!MTB"
        threat_id = "2147852419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 cb 0f b6 c1 88 8d ea fc ff ff 8d 8d ec fc ff ff 03 c8 0f b6 01 88 02 88 19 0f b6 0a 0f b6 c3 03 c8 0f b6 c1 8b 8d ?? ?? ?? ?? 0f b6 84 05 ec fc ff ff 30 04 0e 46 8a 8d ea fc ff ff 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_MOC_2147852732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.MOC!MTB"
        threat_id = "2147852732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c6 33 d2 f7 75 10 8a 82 00 90 49 00 32 04 0e 0f b6 1c 0e 8d 0c 18 8b 45 08 88 0c 06 fe c9 88 0c 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_NAY_2147893870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.NAY!MTB"
        threat_id = "2147893870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {75 04 84 c0 74 06 66 89 0c 7b eb b3 33 c0 66 89 04 7b 83 c6 ?? 0f b7 0e 51 e8 c8 55 ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "dwar.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_LAK_2147894004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.LAK!MTB"
        threat_id = "2147894004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c3 c1 e8 05 03 45 f8 8b f3 c1 e6 04 03 75 f4 33 c6 8d 34 1a 33 c6 29 45 08 8b 45 08 8b 75 08 c1 e8 05 03 45 fc c1 e6 04 03 f7 33 c6 8b 75 08 03 f2 33 c6 2b d8 81 c2 47 86 c8 61 ff 4d 10 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_NR_2147900683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.NR!MTB"
        threat_id = "2147900683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 33 d2 89 10 e8 9d 13 fb ff e8 ec 13 fb ff 83 7e ?? ?? 75 1d 8b c3 8b 15 3c 85 44}  //weight: 5, accuracy: Low
        $x_5_2 = {53 a1 0c 42 46 00 83 38 00 74 0a 8b 1d ?? ?? ?? ?? 8b 1b ff d3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_AMBE_2147903422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.AMBE!MTB"
        threat_id = "2147903422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d8 03 5d a4 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d4 31 18 83 45 ec 04 c7 45 88 ?? ?? ?? 00 c7 45 88 ?? ?? ?? 00 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_SPX_2147907376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.SPX!MTB"
        threat_id = "2147907376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c8 c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 45}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_RVE_2147911205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.RVE!MTB"
        threat_id = "2147911205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 83 7f 14 0f 8d 0c 10 8b c7 76 02 8b 07 8a 09 80 f1 2a 88 0c 10 42 3b 56 10 72 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_DA_2147919686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.DA!MTB"
        threat_id = "2147919686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "71"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "NBDeviceGetIdA" ascii //weight: 10
        $x_10_2 = "NBDeviceGetState" ascii //weight: 10
        $x_10_3 = "NBDeviceSupportsNBUApi" ascii //weight: 10
        $x_10_4 = "NBErrorsGetMessageA" ascii //weight: 10
        $x_10_5 = "NBErrorsSetLastA" ascii //weight: 10
        $x_10_6 = "NBUAbort" ascii //weight: 10
        $x_10_7 = "NBUidai.dll" ascii //weight: 10
        $x_1_8 = "AlphaBlend" ascii //weight: 1
        $x_1_9 = "TransparentB" ascii //weight: 1
        $x_1_10 = "CreateFontPacka" ascii //weight: 1
        $x_1_11 = "GradientFill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rhadamanthys_C_2147921680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.C!MTB"
        threat_id = "2147921680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 03 88 45 ?? 45 ff 44 24 ?? 41 83 e1 ?? 85 d2 08 00 8b 5c 24 ?? 8a 44 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_CV_2147922420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.CV!MTB"
        threat_id = "2147922420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {99 f7 7d d4 8b 45 e0 8b 0c 90 89 4d c8 8b 55 e4 8b 45 ec 8b 0c 90 33 4d c8 8b 55 e4 8b 45 ec 89 0c 90 eb}  //weight: 5, accuracy: High
        $x_1_2 = {88 4d fb 8b 55 e8 8d 04 95 01 00 00 00 99 f7 7d 0c 8b 45 08 8a 0c 10 88 4d fa 8b 55 e8 8d 04 95 02 00 00 00 99 f7 7d 0c}  //weight: 1, accuracy: High
        $x_1_3 = {89 45 f0 8b 55 0c 8b 02 89 45 f4 8b 4d f4 33 4d f0 8b 55 0c 89 0a 8b 45 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_AMQ_2147924102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.AMQ!MTB"
        threat_id = "2147924102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 12 33 14 88 8b 45 ?? 89 10 8b 4d ?? 8b 11 52 8b 4d ?? e8 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 8b 08 89 4d ?? 8b 55 ?? 33 55 ?? 8b 45 ?? 89 10 8b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_TBM_2147927686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.TBM!MTB"
        threat_id = "2147927686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c8 0f ca 0b d7 33 ca 33 4c 9c 10 33 ce 89 4c 9c 20 43 83 fb 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_DCP_2147935978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.DCP!MTB"
        threat_id = "2147935978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 08 8b 7c 24 0c 81 f1 1d 19 22 f0 81 f7 16 c6 8b 1d 09 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_AB_2147939496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.AB!MTB"
        threat_id = "2147939496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 0c 04 88 44 24 03 89 fb 00 c3 89 c8 31 d2 f7 b4 24 24 01 00 00 02 5c 15 00 89 df 0f b6 c3 0f b6 5c 24 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_AC_2147939501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.AC!MTB"
        threat_id = "2147939501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 81 70 6a 44 00 33 44 0c 18 83 c1 04 33 44 0c 1c 33 44 0c 18 8b d0 8b d8 c1 ea 18 c1 eb 10 0f b6 d2 0f b6 92 60 69 44 00 88 5c 24 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_GVA_2147939732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.GVA!MTB"
        threat_id = "2147939732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ec 8b c5 eb}  //weight: 2, accuracy: High
        $x_1_2 = {8b 4c 24 38 33 cc e8 ?? ?? ?? ?? 83 c4 48}  //weight: 1, accuracy: Low
        $x_1_3 = {8b cd eb 02 8b 09 eb 02}  //weight: 1, accuracy: High
        $x_1_4 = {0f be 08 eb 03}  //weight: 1, accuracy: High
        $x_1_5 = {0f 9d c2 4a 8b c2}  //weight: 1, accuracy: High
        $x_1_6 = {88 0a e9 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_GVB_2147939866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.GVB!MTB"
        threat_id = "2147939866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 fe 81 ef 89 15 00 00 03 c7 31 03 83 45 ec 04 6a 00}  //weight: 2, accuracy: High
        $x_1_2 = {33 c0 8b 55 ec 01 13 8b 75 d4 03 75 a4 03 75 ec 03 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_ARD_2147942193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.ARD!MTB"
        threat_id = "2147942193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c7 89 c1 c1 ef 18 c1 e9 10 0f b6 c9 0f b6 3c 3a c1 e7 18 0f b6 0c 0a c1 e1 10 09 f9 0f b6 fc 0f b6 c0 0f b6 34 3a c1 e6 08 09 ce 0f b6 3c 02 09 f7 0f ac f9 13 0f ac fe 09 33 7d f0 31 cf 31 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rhadamanthys_CA_2147947429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthys.CA!MTB"
        threat_id = "2147947429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {2b c1 8b 4d f4 89 55 f4 8a 44 18 03 32 45 ff 88 41 06 8b ca 8b 47 04 40 c1 e0 04 3b f0 8a 45 fe}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

