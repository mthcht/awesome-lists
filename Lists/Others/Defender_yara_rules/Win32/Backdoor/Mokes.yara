rule Backdoor_Win32_Mokes_RA_2147765447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.RA!MTB"
        threat_id = "2147765447"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 94 31 01 24 0a 00 88 14 30}  //weight: 2, accuracy: High
        $x_1_2 = {33 f5 33 f7 2b de 83 6c 24 18 01 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Mokes_GMP_2147892371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GMP!MTB"
        threat_id = "2147892371"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f be c9 0f bf d2 66 81 e2 e5 00 66 c1 d2 26 66 49 f7 eb 66 c1 e6 75 66 c1 e2 a8 66 83 c1 3e c1 c0 48 66 c1 d8 1c 66 81 e3 c9 01 66 33 ca 8b 45 d8 0f b7 c8 8b 45 d0 8b 40 1c 8d 04 88 8b 4d e0 8b 34 08 8d 4d e4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GZF_2147902811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GZF!MTB"
        threat_id = "2147902811"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 40 89 45 fc 83 7d fc 0d ?? ?? 8b 45 fc 0f be 44 05 dc 35 ?? ?? ?? ?? 8b 4d fc 88 44 0d dc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GZF_2147902811_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GZF!MTB"
        threat_id = "2147902811"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 5d c0 06 09 f9 b0 79 a4 52 b6 f3 45 94 56 35 ?? ?? ?? ?? b8 ?? ?? ?? ?? 07 b9 ?? ?? ?? ?? 69 0b}  //weight: 10, accuracy: Low
        $x_5_2 = {98 0e 31 5a ?? 22 c1 4f eb}  //weight: 5, accuracy: Low
        $x_5_3 = {01 ed b1 30 d0 30 30 29 9e 53 aa 35 ?? ?? ?? ?? 07 95 39 78}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Mokes_GXY_2147903507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GXY!MTB"
        threat_id = "2147903507"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 0c 33 83 ff 0f ?? ?? 8d 95 ?? ?? ?? ?? 52 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GXY_2147903507_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GXY!MTB"
        threat_id = "2147903507"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 69 72 74 66 c7 05 ?? ?? ?? ?? 6f 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 65 63 74 00 c6 05 ?? ?? ?? ?? 72 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GXY_2147903507_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GXY!MTB"
        threat_id = "2147903507"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 17 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 55 ?? 8b 4d ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 4d ?? 33 c8 2b d9 89 4d ?? 8b c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GXY_2147903507_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GXY!MTB"
        threat_id = "2147903507"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 4d ?? 03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 c9 89 45 ?? 89 4d ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GXN_2147909410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GXN!MTB"
        threat_id = "2147909410"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 13 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 4d ?? 33 db 33 4d ?? 8b 45 ?? 03 45 ?? 33 c1 89 4d ?? 8b 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GXZ_2147911073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GXZ!MTB"
        threat_id = "2147911073"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 14 30 83 7d ?? 0f ?? ?? 6a 00 6a 00 57 8d 85 ?? ?? ?? ?? 50 53}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GXZ_2147911073_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GXZ!MTB"
        threat_id = "2147911073"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 6b 58 6a 72 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 33 66 a3 ?? ?? ?? ?? 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 2e 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 66 a3 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? 33 c0 6a 65 66 a3 ?? ?? ?? ?? 58 6a 6e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GNK_2147916832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GNK!MTB"
        threat_id = "2147916832"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 08 59 8a 4d fc 03 c3 30 08 83 7d 0c 0f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GNK_2147916832_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GNK!MTB"
        threat_id = "2147916832"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c6 30 08 83 7d 0c 0f ?? ?? 57 ff 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GBX_2147918982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GBX!MTB"
        threat_id = "2147918982"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 f1 6b ca ?? 83 e1 07 d3 e6 0b de 88 5d fc 0f b6 45 fc 35 ?? ?? ?? ?? 88 45 fc 0f b6 45 fc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GNT_2147919601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GNT!MTB"
        threat_id = "2147919601"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d3 c1 ea ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f3 c1 e6 ?? 03 74 24 ?? 8d 04 1f 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GTT_2147919832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GTT!MTB"
        threat_id = "2147919832"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f8 40 89 45 f8 83 7d f8 0d ?? ?? 8b 45 f8 0f be 44 05 cc 83 f0 ?? 8b 4d f8 88 44 0d cc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GTN_2147921677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GTN!MTB"
        threat_id = "2147921677"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 55 c8 0f b6 02 35 94 00 00 00 8b 0d ?? ?? ?? ?? 03 4d c8 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GZT_2147922880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GZT!MTB"
        threat_id = "2147922880"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 14 38 83 fb ?? ?? ?? 6a 00 8d 85 ?? ?? ?? ?? 50 6a 00 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mokes_GXT_2147923270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokes.GXT!MTB"
        threat_id = "2147923270"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 ca 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 33 f9 8b 4d ?? 03 c1 33 c7 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

