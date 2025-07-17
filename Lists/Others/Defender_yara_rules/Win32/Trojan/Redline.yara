rule Trojan_Win32_Redline_SIB_2147812543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SIB!MTB"
        threat_id = "2147812543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 6f 8c 3f ?? ?? ?? ?? f3 0f 6f 94 3f ?? ?? ?? ?? 66 0f db d0 66 0f db c8 66 0f 67 ca f3 0f 7f 0c 3b 83 c7 ?? 81 ff ?? ?? ?? ?? 75 ?? a0 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 8d 7e ?? 88 83 ?? ?? ?? ?? 88 8b ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 88 93 ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 88 8b ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 88 93 ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 88 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f0 81 e6 ?? ?? ?? ?? f7 d0 89 c1 09 f8 83 e1 ?? f7 d0 09 ce 89 f9 83 e7 ?? f7 d1 81 e1 ?? ?? ?? ?? 09 f9 bf ?? ?? ?? ?? 31 f1 8b 75 ?? 09 c8 8b 4d ?? 88 01 31 c9 8a 45 ?? 28 c1 b0 ?? 28 c8 b1 ?? b5 ?? 28 c1 b0 ?? 28 c8 28 c5 b0 ?? 28 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_FG_2147822354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.FG!MTB"
        threat_id = "2147822354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 4d ec 0f be 11 33 d0 a1 04 df 43 00 03 45 ec 88 10}  //weight: 1, accuracy: High
        $x_1_2 = {33 4c 24 14 33 4c 24 18 2b d9 89 5c 24 24 8b 44 24 44 29 44 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_LDR_2147822383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.LDR!MTB"
        threat_id = "2147822383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 00 6a 00 8d 45 f4 50 ff 75 f8 8b 45 08 8b 40 04 ff 30 ff 75 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MB_2147826242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MB!MTB"
        threat_id = "2147826242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 28 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MB_2147826242_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MB!MTB"
        threat_id = "2147826242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c0 f6 17 80 07 ?? 80 2f ?? f6 2f 47 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MB_2147826242_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MB!MTB"
        threat_id = "2147826242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 2f 47 e2 37 00 f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MB_2147826242_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MB!MTB"
        threat_id = "2147826242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 5c 24 10 89 74 24 24 8b 44 24 2c 01 44 24 24 8b 44 24 18 90 01 44 24 24 8b 44 24 24 89 44 24 20 8b 4c 24 1c 8b 54 24 18 d3 ea 8b cd 8d 44 24 28 89 54 24 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MB_2147826242_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MB!MTB"
        threat_id = "2147826242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f7 c1 c1 0d f7 d6 33 fe c1 c8 17 f3 a4 81 f1 09 48 a0 61 33 1d ?? ?? ?? ?? 09 0d ?? ?? ?? ?? 2b c2 21 3d ?? ?? ?? ?? 2b fc c1 c2 1f 81 f3 ec 0c e1 82 0b 15 ?? ?? ?? ?? 09 35 ?? ?? ?? ?? 46 c1 ca 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MB_2147826242_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MB!MTB"
        threat_id = "2147826242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 64 24 10 8b 44 24 10 b8 ?? ?? ?? ?? f7 a4 24 48 02 00 00 8b 84 24 48 02 00 00 81 ac 24 60 01 00 00 ?? ?? ?? ?? b8 ?? ?? ?? ?? f7 a4 24 cc 00 00 00 8b 84 24 cc 00 00 00 81 ac 24 48 02 00 00 ?? ?? ?? ?? 8a 84 37 ?? ?? ?? ?? 88 04 0e 46 3b 35 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_UN_2147826308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.UN!MTB"
        threat_id = "2147826308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d fc 03 4d 08 0f b6 11 33 d0 8b 45 fc 03 45 08 88 10 8b e5 5d c3}  //weight: 10, accuracy: High
        $x_10_2 = {7a 08 e3 2c c7 45 ?? 3e 75 03 10 c7 45 ?? d4 44 89 40 c7 45 ?? bd 6a 3f 79 c7 85 ?? ?? ?? ?? 22 0b 95 10 c7 85 ?? ?? ?? ?? 7a 62 23 1f ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_UQ_2147826427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.UQ!MTB"
        threat_id = "2147826427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 fc 8b 4d fc 3b 4d 14 73 24 8b 45 fc 33 d2 f7 75 10 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f be 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb cb 8b 45 0c 8b e5 5d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_UR_2147826448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.UR!MTB"
        threat_id = "2147826448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 89 7c 24 ?? 89 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 89 4c 24 ?? 89 3d ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? 47 86 c8 61 ff 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_US_2147826572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.US!MTB"
        threat_id = "2147826572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 f8 8b 45 0c 01 d0 0f b6 08 8b 45 f8 ba ?? ?? ?? ?? f7 75 14 8b 45 08 01 d0 0f b6 00 89 c2 89 d0 c1 e0 ?? 01 d0 c1 e0 ?? 89 c3 8b 55 f8 8b 45 0c 01 d0 31 d9 89 ca 88 10 83 45 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_UT_2147826596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.UT!MTB"
        threat_id = "2147826596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 8b fa 39 75 ?? 76 13 33 d2 8b c6 f7 75 ?? 8a 04 0a 30 04 3e 46 3b 75 ?? 72 ed 8b c7 5f 5e 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_UW_2147826612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.UW!MTB"
        threat_id = "2147826612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 8b 5d 08 8b 56 04 0f b6 0c 18 88 0c 10 8b c8 8b 56 04 83 e1 ?? 0f b6 89 ?? ?? ?? ?? 30 0c 02 40 3b c7 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MA_2147826870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MA!MTB"
        threat_id = "2147826870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 89 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MA_2147826870_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MA!MTB"
        threat_id = "2147826870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 dc 99 b9 ?? ?? ?? ?? f7 f9 8b 45 08 0f be 0c 10 69 c9 ?? ?? ?? ?? 83 e1 ?? 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MA_2147826870_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MA!MTB"
        threat_id = "2147826870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 ?? ?? ?? ?? 88 0c 02 c9 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 d8 01 45 f0 8d 04 3e 89 45 f4 8b c7 c1 e8 05 83 3d ?? ?? ?? ?? 1b 89 45 0c 75 ?? 33 c0 50 50 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "UnlockFile" ascii //weight: 1
        $x_1_4 = "DeleteFileW" ascii //weight: 1
        $x_1_5 = "GetDiskFreeSpaceExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MA_2147826870_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MA!MTB"
        threat_id = "2147826870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "HATOTAG" wide //weight: 5
        $x_5_2 = "JEYAGOQ" wide //weight: 5
        $x_5_3 = "SOBEHAVOBA" wide //weight: 5
        $x_5_4 = "reroq nogineti fopaxa fah lanaf vecab" ascii //weight: 5
        $x_1_5 = "\\hedo.pdb" ascii //weight: 1
        $x_1_6 = "AbortSystemShutdownA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NA_2147827058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NA!MTB"
        threat_id = "2147827058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 f7 75 08 83 c7 ?? 0f b6 04 1a 33 d2 30 06 8d 04 31 f7 75 08 8d 76 02 0f b6 04 1a 30 46 ff 83 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NA_2147827058_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NA!MTB"
        threat_id = "2147827058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 31 08 5d}  //weight: 1, accuracy: High
        $x_1_2 = {8b c1 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 45 ?? 33 f8 89 7d ?? 8b 45 ?? 29 45 ?? 89 75 ?? 8b 45 ?? 01 45 ?? 2b 5d ?? ff 4d ?? 89 5d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NB_2147827073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NB!MTB"
        threat_id = "2147827073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 53 31 db 81 ec ?? ?? ?? ?? 8b 7d 0c 3b 5d 10 ?? ?? 89 d8 31 d2 8d 8d ?? ?? ?? ?? f7 75 14 8b 45 08 0f be 34 10 e8 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 69 c6 ?? ?? ?? ?? 30 04 1f 43 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NC_2147827139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NC!MTB"
        threat_id = "2147827139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {47 86 c8 61 ff 4d ?? 8b 45 ?? 0f 85 ?? ?? ?? ?? 41 00 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 33 c8 89 4d ?? 8b 45 ?? 29 45 ?? 81 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NF_2147827199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NF!MTB"
        threat_id = "2147827199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 3b c3 76 09 80 34 11 ?? 42 3b d0 72 f7 8d 55 bc 52 29 00 a1 ?? ?? ?? ?? 8b 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NH_2147827263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NH!MTB"
        threat_id = "2147827263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 54 24 18 8b 44 24 4c 01 44 24 18 8b 44 24 10 33 44 24 1c 89 74 24 34 89 44 24 10 89 44 24 54 8b 44 24 54 89 44 24 34 8b 44 24 18 31 44 24 34 8b 44 24 34 89 44 24 10 89 35 ?? ?? ?? ?? 8b 44 24 10 29 44 24 14 81 44 24 ?? 47 86 c8 61}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NXT_2147827687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NXT!MTB"
        threat_id = "2147827687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SHL_2147827688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SHL!MTB"
        threat_id = "2147827688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 89 85 48 ?? ?? ?? 8b 85 58 ?? ?? ?? 8b 8d 48 ?? ?? ?? 3b 48 02 73 1c 8b 45 f0 03 85 48 ?? ?? ?? 8b 8d 58 ?? ?? ?? 03 8d 48 ?? ?? ?? 8a 49 3a 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_HRD_2147827689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.HRD!MTB"
        threat_id = "2147827689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ad 54 fd ?? ?? ec f8 1e 4b 81 85 40 fe ?? ?? 7a 11 6e 08 81 85 c8 fe ?? ?? 25 62 73 2e 81 85 c8 fe ?? ?? 88 52 fd 38 81 ad 34 fd ?? ?? 25 7b f1 4d 81 ad 34 fd ?? ?? 4b 53 aa 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NP_2147827692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NP!MTB"
        threat_id = "2147827692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d0 0f b6 08 8b 45 f8 ba ?? ?? ?? ?? f7 75 14 8b 45 08 01 d0 0f b6 00 c1 e0 ?? 89 c3 8b 55 f8 8b 45 0c 01 d0 31 d9 89 ca 88 10 83 45 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NR_2147827795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NR!MTB"
        threat_id = "2147827795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 c1 ea ?? 03 55 e4 c1 e0 ?? 03 45 d4 89 4d f4 33 d0 33 d1 89 55 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 08 8b 45 08 c1 e0 ?? 03 45 d8 89 45 f0 8b 45 08 03 45 e8 89 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DF_2147827811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DF!MTB"
        threat_id = "2147827811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 db 0f b6 4d db 2b 4d dc 88 4d db 0f b6 55 db c1 fa 02 0f b6 45 db c1 e0 06 0b d0 88 55 db 0f b6 4d db 81 e9 8e 00 00 00 88 4d db 0f b6 55 db f7 da 88 55 db 0f b6 45 db f7 d0 88 45 db 8b 4d dc 8a 55 db 88 54 0d e8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DF_2147827811_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DF!MTB"
        threat_id = "2147827811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 44 24 10 8b 44 24 4c 01 44 24 10 8b 4c 24 28 33 ca 89 4c 24 38 89 5c 24 30 8b 44 24 38 89 44 24 30 8b 44 24 10 31 44 24 30 8b 54 24 30 89 54 24 38}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 18 c1 e8 05 89 44 24 10 8b 44 24 10 33 74 24 28 03 44 24 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_DA_2147827905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DA!MTB"
        threat_id = "2147827905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 80 04 1f}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 04 80 34 1f}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 04 80 34 1f ?? 43 39 de 0f 85}  //weight: 1, accuracy: Low
        $x_1_4 = "xbyuidgAYU7uikj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DA_2147827905_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DA!MTB"
        threat_id = "2147827905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 0c 8b 45 d8 01 45 0c ff 75 f4 8d 45 f0 50 e8 ?? ?? ?? ?? 8b 45 0c 31 45 f0 8b 45 f0 29 45 f8 83 65 fc 00 8b 45 d4 01 45 fc 2b 55 fc ff 4d e8 8b 45 f8 89 55 ec 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NG_2147827957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NG!MTB"
        threat_id = "2147827957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 08 8b 45 f8 ba ?? ?? ?? ?? f7 75 14 8b 45 08 01 d0 0f b6 00 ba ?? ?? ?? ?? 0f af c2 89 c3 8b 55 f8 8b 45 0c 01 d0 31 d9 89 ca 88 10 83 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NW_2147828078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NW!MTB"
        threat_id = "2147828078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d 08 88 01 8b e5 5d c3 35 00 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 08}  //weight: 10, accuracy: Low
        $x_1_2 = "cuabnjfguqbiu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NX_2147828109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NX!MTB"
        threat_id = "2147828109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 d9 8a 68 01 31 f1 66 89 08 0f b6 4d 02 30 48 02 eb 99}  //weight: 10, accuracy: High
        $x_10_2 = {8b 45 e4 8b 0c b8 31 c0 8d b4 26 ?? ?? ?? ?? ?? 0f b6 14 86 30 14 01 83 c0 ?? 8b 13 39 d0 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_QG_2147828303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.QG!MTB"
        threat_id = "2147828303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 08 01 d0 0f b6 00 89 c2 b8 ?? ?? ?? ?? 29 d0 c1 e0 ?? 89 c3 8b 55 f8 8b 45 0c 01 d0 31 d9 89 ca 88 10 83 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CE_2147828392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CE!MTB"
        threat_id = "2147828392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d fb 0f b6 45 fb 8b 0d 8c 52 48 00 03 4d e0 0f be 11 33 d0 a1 8c 52 48 00 03 45 e0 88 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 1c 89 44 24 18 8b 44 24 10 8b 4c 24 20 d3 e8 89 44 24 14 8b 44 24 40 01 44 24 14 33 54 24 18 8d 4c 24 30 89 54 24 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_PC_2147828560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PC!MTB"
        threat_id = "2147828560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 7c 24 ?? 03 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 33 54 24 ?? 8d 4c 24 ?? 89 54 24 ?? 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_QS_2147828576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.QS!MTB"
        threat_id = "2147828576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 00 89 c2 89 d0 01 c0 01 d0 c1 e0 ?? 89 c3 8b 55 f8 8b 45 0c 01 d0 31 d9 89 ca 88 10 83 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_FE_2147828596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.FE!MTB"
        threat_id = "2147828596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 49 00 8a 8c 02 3b 2d 0b 00 88 0c 30 40 3b 05 a4 1b 4c 02}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 38 01 44 24 10 33 74 24 18 31 74 24 10}  //weight: 1, accuracy: High
        $x_1_3 = {8a 8c 02 3b 2d 0b 00 88 0c 30 40 3b 05 34 22 4c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_PCO_2147828782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PCO!MTB"
        threat_id = "2147828782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e2 89 74 24 28 03 54 24 48 8b 44 24 14 01 44 24 28 8b 44 24 18 01 44 24 28 8b 44 24 28 89 44 24 1c 8b 44 24 18 8b 4c 24 20 d3 e8 89 44 24 10 8b 44 24 3c 01 44 24 10 33 54 24 1c 8d 4c 24 30 89 54 24 30 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GL_2147828801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GL!MTB"
        threat_id = "2147828801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d0 0f b6 08 8b 45 ?? ba ?? ?? ?? ?? f7 75 14 8b 45 ?? 01 d0 0f b6 00 89 c2 89 d0 c1 e2 ?? 29 d0 c1 e0 ?? 89 c3 8b 55 ?? 8b 45 ?? 01 d0 31 d9 89 ca 88 10 83 45}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_A_2147828922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.A!MTB"
        threat_id = "2147828922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 45 f0 89 75 ec 89 75 e4 8b 45 e8 83 c0 ff 89 45 e8 89 45 b0 8b 4d dc 83 d1 ff 89 4d dc 89 4d b4 8b 55 0c 42 89 55 0c e9 6b ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DCC_2147828957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DCC!MTB"
        threat_id = "2147828957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 0c 8b 45 e4 01 45 0c 8b 45 0c 33 45 f8 33 c8 89 4d ec 8b 45 ec 29 45 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_XA_2147828974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.XA!MTB"
        threat_id = "2147828974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 33 d2 f7 f7 0f be 04 2a 6b c0 d0 30 04 19 41 3b ce}  //weight: 10, accuracy: High
        $x_10_2 = {33 d2 8b c1 f7 f7 8a 04 2a 8a d0 02 c0 02 d0 c0 e2 ?? 30 14 19 41 3b ce 72 e6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PCC_2147829044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PCC!MTB"
        threat_id = "2147829044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 89 a0 94 47 00 88 4d fb 0f b6 45 fb 8b 0d 10 96 47 00 03 8d 10 5d ff ff 0f be 11 33 d0 a1 10 96 47 00 03 85 10 5d ff ff 88 10 e9 0b ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PCD_2147829045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PCD!MTB"
        threat_id = "2147829045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 e8 01 45 0c ff 75 fc 8d 45 f0 50 e8 ee fe ff ff 8b 45 f0 33 45 0c 2b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PCZ_2147829216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PCZ!MTB"
        threat_id = "2147829216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 5c 24 ?? 03 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b c7 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 89 1d ?? ?? ?? ?? 33 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PCX_2147829264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PCX!MTB"
        threat_id = "2147829264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 e3 89 c8 c1 ea ?? 6b d2 ?? 29 d0 0f b6 80 ?? ?? ?? ?? 32 81 ?? ?? ?? ?? 83 c1 01 83 f0 e5 88 81 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_FD_2147829291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.FD!MTB"
        threat_id = "2147829291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 ff 15 34 11 40 00 ff 45 fc 81 7d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AX_2147829362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AX!MTB"
        threat_id = "2147829362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c1 33 d2 f7 f7 0f be 04 2a 6b c0 a9 30 04 19 41 3b ce 72 eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPK_2147829368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPK!MTB"
        threat_id = "2147829368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 0c 8b 45 e8 03 f0 33 d2 f7 75 14 8b 45 08 8a 04 02 8a c8 02 c0 02 c8 c0 e1 05 30 0e ff 45 e8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PCY_2147829385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PCY!MTB"
        threat_id = "2147829385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 5c 24 ?? 03 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b c6 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 89 1d ?? ?? ?? ?? 33 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RS_2147829386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RS!MTB"
        threat_id = "2147829386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 03 4d ec 8b da c1 e3 04 03 5d e8 03 c2 33 cb 33 c8 89 45 fc 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? c1 e0 ?? 03 c7 89 45 f4 8b 45 ?? 03 45 f8 89 45 fc 8b 45 ?? 83 0d ?? ?? ?? ?? ?? c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 e4 01 45 ?? ff 75 fc 8d 45 f4 50 e8 ?? ?? ?? ?? 8b 45 f4 33 45 ?? 81 45 f8 ?? ?? ?? ?? 2b d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SC_2147829548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SC!MTB"
        threat_id = "2147829548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e0 7f 56 00 c7 05 ?? ?? ?? ?? dc 7f 56 00 c7 05 ?? ?? ?? ?? d8 7f 56 00 c7 05 ?? ?? ?? ?? 6c 00 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SD_2147829549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SD!MTB"
        threat_id = "2147829549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c2 83 e2 ?? 8a 8a ?? ?? ?? ?? 30 0c 38 40 3b c6 72}  //weight: 10, accuracy: Low
        $x_10_2 = {03 c8 83 e1 ?? 0f b6 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 83 c0 ?? 3d ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SD_2147829549_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SD!MTB"
        threat_id = "2147829549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 85 04 51 a8 22 ba ?? ?? ?? ?? b3 6c f6 3d ?? ?? ?? ?? c9 60 00 d0 09 e5 8d 8d ?? ?? ?? ?? 9a ?? ?? ?? ?? 7b c7 09 3d ?? ?? ?? ?? e0 96 60 72 f6 33 d3 66 3b e3 f9 e9 10 87 03 00 88 14 39 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TX_2147829550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TX!MTB"
        threat_id = "2147829550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d0 0f b6 08 8b 45 f4 ba ?? ?? ?? ?? f7 75 14 8b 45 08 01 d0 0f b6 00 ba ?? ?? ?? ?? 0f af c2 89 c3 8b 55 f4 8b 45 0c 01 d0 31 d9 89 ca 88 10 83 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DD_2147829559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DD!MTB"
        threat_id = "2147829559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 8c 02 3b 2d 0b 00 88 0c 30 40 3b 05 1c 35 49 00 72 ed}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 24 01 44 24 1c 8b 44 24 2c 01 44 24 1c 8b 44 24 1c 89 44 24 14 8b 4c 24 18 8b c6 d3 e8 89 44 24 10 8b 44 24 3c 01 44 24 10 33 54 24 14 8d 4c 24 2c 89 54 24 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_DD_2147829559_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DD!MTB"
        threat_id = "2147829559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 80 b6 ?? ?? ?? ?? ?? 6a 00 ff d7 80 86 ?? ?? ?? ?? ?? 6a 00 ff d7 80 86 ?? ?? ?? ?? ?? 6a 00 ff d7 80 b6 ?? ?? ?? ?? ?? 6a 00 ff d7 80 86 ?? ?? ?? ?? ?? 6a 00 ff d7 80 86 ?? ?? ?? ?? ?? 6a 00 ff d7 80 86 ?? ?? ?? ?? ?? 6a 00 ff d7 80 86 ?? ?? ?? ?? ?? 6a 00 ff d7 80 b6 ?? ?? ?? ?? ?? 46 81 fe 00 6e 03 00 72 94}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DE_2147829560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DE!MTB"
        threat_id = "2147829560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 f8 59 46 00 88 0c 02}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 fc 8b c6 c1 e8 05 03 45 e8 8b ce c1 e1 04 03 4d e0 33 c1 33 45 fc 89 45 0c 8b 45 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_DE_2147829560_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DE!MTB"
        threat_id = "2147829560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d db 0f b6 45 db 2d c2 00 00 00 88 45 db 0f b6 4d db f7 d1 88 4d db 0f b6 55 db 03 55 dc 88 55 db 0f b6 45 db f7 d0 88 45 db 0f b6 4d db 81 e9 a3 00 00 00 88 4d db 8b 55 dc 8a 45 db 88 44 15 e8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DE_2147829560_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DE!MTB"
        threat_id = "2147829560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 a3 0f b6 4d a3 33 4d a4 88 4d a3 0f b6 55 a3 2b 55 a4 88 55 a3 0f b6 45 a3 f7 d0 88 45 a3 0f b6 4d a3 33 4d a4 88 4d a3 0f b6 55 a3 f7 d2 88 55 a3 0f b6 45 a3 33 45 a4 88 45 a3 8b 4d a4 8a 55 a3 88 54 0d b0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DE_2147829560_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DE!MTB"
        threat_id = "2147829560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d a3 0f b6 55 a3 33 55 a4 88 55 a3 0f b6 45 a3 2b 45 a4 88 45 a3 0f b6 4d a3 f7 d1 88 4d a3 0f b6 55 a3 33 55 a4 88 55 a3 0f b6 45 a3 f7 d0 88 45 a3 0f b6 4d a3 33 4d a4 88 4d a3 8b 55 a4 8a 45 a3 88 44 15 b0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PCE_2147829574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PCE!MTB"
        threat_id = "2147829574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 08 89 54 24 ?? c7 04 24 ?? ?? ?? ?? 8b 44 24 ?? 89 04 24 8b 44 24 ?? 31 04 24 8b 04 24 89 01}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e2 89 5c 24 ?? 03 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b c6 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 33 54 24 ?? 8d 4c 24 ?? 89 54 24 ?? 52 8b 54 24 ?? e8 ?? ?? ?? ?? 8b 54 24 ?? 8d 4c 24 ?? 89 1d ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MC_2147829579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MC!MTB"
        threat_id = "2147829579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 2f 47 e2 37 00 f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 ?? 80 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MC_2147829579_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MC!MTB"
        threat_id = "2147829579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 45 fc 12 00 00 00 c7 45 fc ff ff ff ff 8b 75 0c 8b 45 e8 03 f0 33 d2 f7 75 14 8b 45 08 8a 04 02 8a c8 02 c0 02 c8 c0 e1 05 30 0e ff 45 e8 e9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MC_2147829579_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MC!MTB"
        threat_id = "2147829579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "huAFGsyGshAstu678e28r" ascii //weight: 10
        $x_5_2 = {0f b6 4d d7 8b 45 d8 33 d2 be 04 00 00 00 f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d df 8b 45 d8 8a 88 ?? ?? ?? ?? 88 4d d6 0f b6 55 df 8b 45 d8 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 d8 88 8a ?? ?? ?? ?? 68}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MC_2147829579_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MC!MTB"
        threat_id = "2147829579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c8 c1 ea 05 03 54 24 1c c1 e1 04 03 4c 24 20 03 c3 33 d1 33 d0 2b f2 8b ce c1 e1 04 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 10 8b 44 24 24 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 3c 33 75}  //weight: 5, accuracy: Low
        $x_5_2 = {8b c6 c1 e8 05 03 c5 33 c7 31 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 10 29 44 24 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MC_2147829579_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MC!MTB"
        threat_id = "2147829579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qsjamclyhilyvmrjynkrqflbyewfsevngbxeryzzcbnqcbnunvylzjwvjtxdnkjvspt" ascii //weight: 1
        $x_1_2 = "exqhltjvuybqanjnkiuyconjk" ascii //weight: 1
        $x_1_3 = "gaxxinejdwifbexcxrtfdcgafysxxqzosw" ascii //weight: 1
        $x_1_4 = "vyvglhxdqxumcnlypdlwbtrrhihecybfamwftgztupvzpzxeutvn" ascii //weight: 1
        $x_1_5 = "jvaijlzsniamrumkulwyyunqtmbnrmjlwydnnfsyhfrmqsgtulmmqgmyazlzae" ascii //weight: 1
        $x_1_6 = "ffkurnmpsuuckpekhvzvkkqgdbfrnftlmqcctoxyqncgei" ascii //weight: 1
        $x_1_7 = "czezsnjrwkejzqxpliasmaqtqtyehchknkwqtgmwaydaa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MD_2147829580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MD!MTB"
        threat_id = "2147829580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4c 24 10 8b 44 24 14 03 44 24 ?? c7 05 ?? ?? ?? ?? 00 00 00 00 33 ?? 33 ?? 2b ?? 89 44 24 14 8b ?? c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d ?? ?? 75 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MD_2147829580_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MD!MTB"
        threat_id = "2147829580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d3 80 34 3e ?? ff d3 80 04 3e ?? ff d3 80 34 3e [0-12] 80 34 3e ?? ff d3 80 04 3e ?? ff d3 80 04 3e ?? ff d3 80 04 3e ?? 46 3b 74 24 ?? 0f 82}  //weight: 10, accuracy: Low
        $x_5_2 = "_LoadEnvironment@0" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MD_2147829580_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MD!MTB"
        threat_id = "2147829580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 c0 29 c8 88 84 24 97 01 00 00 0f b6 84 24 97 01 00 00 83 e8 24 88 84 24 97 01 00 00 8b 8c 24 98 01 00 00 0f b6 84 24 97 01 00 00 31 c8 88 84 24 97 01 00 00 0f b6 84 24 97 01 00 00 83 f0 ff 88 84 24 97 01 00 00 0f b6 8c 24 97 01 00 00 31 c0 29 c8 88 84 24 97 01 00 00 8a 8c 24 97 01 00 00 8b 84 24 98 01 00 00 88 8c 04 9d 01 00 00 8b 84 24 98 01 00 00 83 c0 01 89 84 24 98 01 00 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MD_2147829580_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MD!MTB"
        threat_id = "2147829580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 10 73 ?? 8b 4d fc 03 4d f4 8b 55 f8 03 55 f4 8a 02 88 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "queyalodtakeytikepici" ascii //weight: 1
        $x_1_3 = "Refice jarew dijos liv quojok" ascii //weight: 1
        $x_1_4 = "CreateMutexW" ascii //weight: 1
        $x_1_5 = "GetCPInfoExA" ascii //weight: 1
        $x_1_6 = "ClientToScreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MD_2147829580_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MD!MTB"
        threat_id = "2147829580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 42 c1 8b 4d 04 0f 42 c3 03 0c 24 52 50 ff 75 00 51 c5 f8 77 ff 15 ?? ?? ?? ?? 8b 44 24 04 46 83 c5 28 0f b7 40 06 39 c6 72}  //weight: 1, accuracy: Low
        $x_1_2 = "frAQBc8Wsa1xVPfvJcrgRYwTiizs2trQF69AzBlax3CF3EDNhm3soLBPh71Yexui" ascii //weight: 1
        $x_1_3 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DL_2147829721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DL!MTB"
        threat_id = "2147829721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 49 00 8a 8c 02 3b 2d 0b 00 88 0c 30 40 3b 05 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DL_2147829721_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DL!MTB"
        threat_id = "2147829721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mesqjcoijgddrikayiodiaeudgkfwkiwdxchuqgvgnqgg" ascii //weight: 1
        $x_1_2 = "bpgdqdgtnjcyjqkmgwdituzyovplhvbondgilospdfdfgycdploztirnpwnataklarpkqqkttzynfvbpgjwz" ascii //weight: 1
        $x_1_3 = "cdmfijxafmvemfzxihsfwsmpeyadidm" ascii //weight: 1
        $x_1_4 = "tbriscxzkzcflfumkimesbyoeblpwsufdydwctorftepvy" ascii //weight: 1
        $x_1_5 = "rsiwsidewxyquoyvylpiawbjhhhnxumifjikixjz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TQ_2147829730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TQ!MTB"
        threat_id = "2147829730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e9 05 03 4d e8 8b da c1 e3 04 03 5d e4 8d 04 16 33 cb 33 c8 89 45 f8 89 4d 0c 8b 45 0c 01 05 bc 61 c4 02 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 45 e0 89 45 f4 8b 45 08 03 45 f0 89 45 f8 8b 45 08 83 0d c4 61 c4 02 ff c1 e8 05 c7 05 c0 61 c4 02 19 36 6b ff 89 45 0c 8b 45 dc 01 45 0c ff 75 f8 8d 45 f4 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_JN_2147829763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.JN!MTB"
        threat_id = "2147829763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 0c 89 54 24 ?? 89 0c 24 c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 31 04 24 8b 04 24}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e6 89 5c 24 ?? 03 74 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b d7 d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 54 24 ?? 8b ce e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PK_2147829764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PK!MTB"
        threat_id = "2147829764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c1 e1 04 03 4d ec 03 c3 33 c1 33 45 fc 89 45 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 c7 89 45 f4 8b 45 08 03 45 f8 89 45 fc 8b 45 08 83 0d ?? ?? ?? ?? ?? c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 e8 01 45 0c ff 75 fc 8d 45 f4 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PCF_2147829901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PCF!MTB"
        threat_id = "2147829901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 83 25 ?? ?? ?? ?? ?? 8d 0c 10 8b c2 c1 e0 ?? 89 4d f8 03 c7 33 c1 8b ca c1 e9 ?? 03 4d f0 89 45 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_G_2147829932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.G!MTB"
        threat_id = "2147829932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 33 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c7 83 e0 03 59 59 8a 04 28 30 06 47 46 3b 7c 24 ?? 72 de 5e 5d 5b}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MG_2147829960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MG!MTB"
        threat_id = "2147829960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 08 8b 55 f4 8b 45 08 01 d0 0f b6 55 e7 31 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 0c 7c ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MG_2147829960_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MG!MTB"
        threat_id = "2147829960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {99 bf 37 00 00 00 f7 ff 8b 45 08 0f be 14 10 6b d2 34 83 e2 13 83 e2 51 33 f2 03 ce 8b 45 0c 03 45 fc 88 08 0f be 4d fb 8b 55 0c 03 55 fc 0f be 02 2b c1 8b 4d 0c 03 4d fc 88 01 eb}  //weight: 5, accuracy: High
        $x_2_2 = "shFleEjOBfR2LHAH5EddegKhN0O4jXdyRcxuVpbL2i1HsWumYBMQCC5PXmi3Lk5k5" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MG_2147829960_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MG!MTB"
        threat_id = "2147829960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {3b df 03 f1 e9 79 80 17 00 8b 0e 8b 56 04 f7 d1 c1 d8 dc f5 f7 d2 0f a4 d8 71 c0 ec 7e f5 0b ca 66 90 89 4e 04 66 0f b6 c1 9c 80 d4 2d 8f 06 c0}  //weight: 5, accuracy: High
        $x_5_2 = {85 f5 33 c3 f9 f8 d1 c8 2d 56 0f b0 1c f8 35 61 45 9b 7f 48 f7 c6 2c 70 d2 5d 35 16 68 93 4b e9 ef 0c 15 00 8b 0e 36 8b 11 0f b7 c4 03 c0 89 16}  //weight: 5, accuracy: High
        $x_5_3 = {e0 00 02 01 0b 01 0e 18 00 72 02 00 00 08 09 00 00 00 00 00 10 87 38 00 00 10}  //weight: 5, accuracy: High
        $x_2_4 = ".vmp0" ascii //weight: 2
        $x_2_5 = ".vmp2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MG_2147829960_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MG!MTB"
        threat_id = "2147829960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 10 73 ?? 8b 4d fc 03 4d f4 8b 55 f8 03 55 f4 8a 02 88 01 eb}  //weight: 5, accuracy: Low
        $x_5_2 = "mugokateripayasojelihupurizarumi" ascii //weight: 5
        $x_1_3 = "QueryDosDeviceW" ascii //weight: 1
        $x_1_4 = "GetDiskFreeSpaceExA" ascii //weight: 1
        $x_1_5 = "DebugSetProcessKillOnExit" ascii //weight: 1
        $x_1_6 = "hotkey32" wide //weight: 1
        $x_1_7 = "SetMailslotInfo" ascii //weight: 1
        $x_1_8 = "CreateMailslotA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_HD_2147830098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.HD!MTB"
        threat_id = "2147830098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 08 8b 45 f4 ba ?? ?? ?? ?? f7 75 14 89 d0 c1 e8 02 89 c2 8b 45 08 01 d0 0f b6 00 ba ?? ?? ?? ?? 0f af c2 89 c3 8b 55 f4 8b 45 0c 01 d0 31 d9 89 ca 88 10 83 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ME_2147830105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ME!MTB"
        threat_id = "2147830105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 55 ec 8b d7 d3 ea c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 89 55 ec 8b 45 ec 83 45 f8 64 29 45 f8 83 6d f8 64 83 3d 60 41 84 00 0c 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ME_2147830105_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ME!MTB"
        threat_id = "2147830105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 2f 47 e2 43 00 f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {f6 2f 47 e2 43 00 f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_ME_2147830105_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ME!MTB"
        threat_id = "2147830105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e2 06 0b ca 88 8d ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? f7 d1 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 33 95 ?? ?? ?? ?? 88 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8a 8d ?? ?? ?? ?? 88 8c 05 70 ff ff ff e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ME_2147830105_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ME!MTB"
        threat_id = "2147830105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e0 03 0b d0 88 95 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? f7 d1 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 83 ea 58 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? c1 f8 03 0f b6 8d ?? ?? ?? ?? c1 e1 05 0b c1 88 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 88 84 15 ?? ?? ?? ?? e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ME_2147830105_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ME!MTB"
        threat_id = "2147830105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sal hocihama hino jinaqu" ascii //weight: 1
        $x_1_2 = "tiquod kido" ascii //weight: 1
        $x_1_3 = "konaf saquope gig pobeje" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
        $x_1_6 = "GetCursorInfo" ascii //weight: 1
        $x_1_7 = "hotkey" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ME_2147830105_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ME!MTB"
        threat_id = "2147830105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 44 24 60 81 6c 24 38 27 ea 21 11 81 6c 24 28 6b 07 bb 7c 81 44 24 28 4a ed 6f 20 81 6c 24 38 17 ff 9e 54 b8 ce 53 c0 1c f7 64 24 40 8b 44 24 40 81 6c 24 7c 4a e2 62 25 81 6c 24 20 9c 3b df 75 81 6c 24 38 00 ac 9a 59 b8 9a 7b f6 4a f7 64 24 20 8b 44 24 20 81 6c 24 28 b5 d6 af 6e 81 44 24 68 1b ee 2f 65 b8 22 cf 72 1e}  //weight: 5, accuracy: High
        $x_1_2 = "UnhandledExceptionFilter" ascii //weight: 1
        $x_1_3 = "CreateMailslotW" ascii //weight: 1
        $x_1_4 = "GetCPInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_IA_2147830196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.IA!MTB"
        threat_id = "2147830196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 54 24 3c 01 54 24 14 c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 2c 31 44 24 10 8b 44 24 10 31 44 24 14 83 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {56 69 72 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 72 6f 74 65 c6 05 ?? ?? ?? ?? 63 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GA_2147830210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GA!MTB"
        threat_id = "2147830210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 3b f3 72 e4 83 65 fc 00 8d 45 fc 50}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ID_2147830372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ID!MTB"
        threat_id = "2147830372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d6 89 d8 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 83 c3 01 81 fb 00 ac 01 00 75 e1}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NL_2147830385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NL!MTB"
        threat_id = "2147830385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 8d 4c 24 14 89 54 24 14 8b 54 24 3c e8 ?? ?? ?? ?? 8b 44 24 14 33 44 24 2c 89 35 ?? ?? ?? ?? 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 40 29 44 24 18 4b 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SA_2147830386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SA!MTB"
        threat_id = "2147830386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8d 4c 24 14 89 44 24 14 e8 ?? ?? ?? ?? 8b 4c 24 14 33 4c 24 2c 89 35 ?? ?? ?? ?? 31 4c 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 40 29 44 24 18 4b 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MH_2147830393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MH!MTB"
        threat_id = "2147830393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b ca 8b c6 33 d2 f7 f1 8a 04 3a 30 04 2e 46 3b f3 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MH_2147830393_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MH!MTB"
        threat_id = "2147830393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 6c 24 10 c7 44 24 18 00 00 00 00 8b 44 24 24 01 44 24 18 8b 44 24 28 90 01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b c6}  //weight: 5, accuracy: High
        $x_5_2 = {d3 e8 8b 4c 24 10 03 44 24 30 89 44 24 14 33 44 24 20 33 c8 2b f9 8d 44 24 24 89 4c 24 10 89 7c 24 28 e8 ?? ?? ?? ?? 83 eb 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MH_2147830393_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MH!MTB"
        threat_id = "2147830393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PHQETCW.EXE" wide //weight: 10
        $x_1_2 = "Qeoeejpgsgko" wide //weight: 1
        $x_1_3 = "Omdmybr" wide //weight: 1
        $x_1_4 = {0e 00 00 66 00 00 00 00 0e 00 00 00 00 00 d0 6b 00 00 00 10}  //weight: 1, accuracy: High
        $x_1_5 = "cmd /c cmd < Poi.pst & ping -n 5 locK" ascii //weight: 1
        $x_1_6 = "DecryptFileA" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_8 = "System\\CurrentControlSet\\Control\\Session Manager\\FileRenameOperations" ascii //weight: 1
        $x_1_9 = "LockResource" ascii //weight: 1
        $x_1_10 = "GetDiskFreeSpaceA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MI_2147830395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MI!MTB"
        threat_id = "2147830395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 d3 e8 03 45 cc 89 45 f0 33 45 dc 31 45 fc 8b 45 fc 29 45 f8 81 c3 ?? ?? ?? ?? 89 5d ec 4f 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MI_2147830395_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MI!MTB"
        threat_id = "2147830395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 e7 89 c8 29 d0 d1 e8 01 c2 89 c8 c1 ea 06 6b d2 5b 29 d0 89 c2 89 f0 c1 ea 02 f6 a2 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 83 c1 01 81 f9 7e 07 00 00 75}  //weight: 10, accuracy: Low
        $x_1_2 = "akqhfrwyiuexrsfgepmj" ascii //weight: 1
        $x_1_3 = "QueryPerformanceCounter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MI_2147830395_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MI!MTB"
        threat_id = "2147830395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 6c 24 10 89 5c 24 18 8b 44 24 14 01 44 24 18 8b 44 24 24 90 01 44 24 18 8b 44 24 18 89 44 24 20 8b f7}  //weight: 5, accuracy: High
        $x_5_2 = {c1 ee 05 03 74 24 34 8b 44 24 20 31 44 24 10 81 3d f4 ?? ?? ?? ?? 01 00 00 75 [0-21] 8b 4c 24 10 33 ce 8d 44 24 28 89 4c 24 10 e8 ?? ?? ?? ?? 8b 44 24 30 29 44 24 14 83 6c 24 2c 01 8b 54 24 28 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MF_2147830453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MF!MTB"
        threat_id = "2147830453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d 08 f6 17 80 2f c2 fe 07 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MF_2147830453_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MF!MTB"
        threat_id = "2147830453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8d 45 f8 50 56 8d 85 ?? ?? ?? ?? 50 56 56 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MF_2147830453_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MF!MTB"
        threat_id = "2147830453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 0f be 34 10 8b 45 08 8b 4d f0 0f be 14 08 31 f2 88 14 08 8b 45 f0 83 c0 01 89 45 f0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MF_2147830453_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MF!MTB"
        threat_id = "2147830453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6b 75 d4 28 01 f2 03 4a 14 8b 55 dc 8b 75 d8 6b 7d d4 28 01 fe 03 56 0c 89 14 24 89 4c 24 04 89 44 24 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MF_2147830453_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MF!MTB"
        threat_id = "2147830453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 f8 83 c2 02 89 55 f8 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "GetForegroundWindow" ascii //weight: 1
        $x_1_4 = "GetSystemInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MF_2147830453_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MF!MTB"
        threat_id = "2147830453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 c4 08 8b 45 08 03 45 d0 8a 08 80 c1 01 8b 55 08 03 55 d0 88 0a 8b 45 08 03 45 d0 8a 08 80 c1 01 8b 55 08 03 55 d0 88 0a 8b 45 08 03 45 d0 8a 08 80 c1 01 8b 55 08 03 55 d0 88 0a}  //weight: 5, accuracy: High
        $x_5_2 = {8a 45 cc 88 45 cb 0f b6 4d cf 8b 55 08 03 55 d0 0f b6 02 03 c1 8b 4d 08 03 4d d0 88 01 8b 55 08 03 55 d0 8a 02 2c 01 8b 4d 08 03 4d d0 88 01 8b 55 08 03 55 d0 0f b6 02 83 e8 02 8b 4d 08 03 4d d0 88 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MF_2147830453_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MF!MTB"
        threat_id = "2147830453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {56 33 3d 00 56 33 3d 00 56 33 3d 00 56 33 3d 03 56 33 3d 00 56 33 3d 1e 56 33 3d 32 56 33 3d 00 56 33 3d 00 56 33 3d 01 56 33 3d 04 56 33 3d 02 56 33 3d 00 56 33 3d 00 56 33 3d 00 56 33 3d}  //weight: 2, accuracy: High
        $x_2_2 = "Unmerciful.exe" wide //weight: 2
        $x_2_3 = ".128xeq2" ascii //weight: 2
        $x_2_4 = "Please, contact yoursite@yoursite.com. Thank you!" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PCG_2147830484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PCG!MTB"
        threat_id = "2147830484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 8d 4c 24 30 89 54 24 30 8b 54 24 3c e8 ?? ?? ?? ?? 8b 44 24 30 33 44 24 28 89 35 ?? ?? ?? ?? 31 44 24 10 8b 44 24 10 29 44 24 18 8b 44 24 40 29 44 24 14 4b 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_IK_2147830508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.IK!MTB"
        threat_id = "2147830508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c8 31 d2 f7 b4 24 ac 00 00 00 89 e8 c1 ea 02 f6 24 17 30 04 0b 83 c1 01 39 f1 75 e3 81 c4 8c 00 00 00 5b 5e 5f 5d c3}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_IF_2147830620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.IF!MTB"
        threat_id = "2147830620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 5c 24 18 33 f6 39 74 24 20 76 17 ff d7 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 1e 46 3b 74 24 20 72 e9}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_JG_2147830636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.JG!MTB"
        threat_id = "2147830636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c8 ba 00 00 00 00 f7 f5 c1 ea 02 b0 74 f6 24 17 30 04 0b 41 39 ce 75 e7 83 c4 7c 5b 5e 5f 5d c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_HW_2147830648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.HW!MTB"
        threat_id = "2147830648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 ba 00 00 00 00 f7 f5 c1 ea 02 b0 74 f6 24 17 30 04 0b 41 39 ce 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_IN_2147830651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.IN!MTB"
        threat_id = "2147830651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f8 3b 45 0c 73 2d 8b 55 08 8b 45 f8 01 d0 0f b6 08 8b 45 f8 83 e0 03 89 c2 8b 45 10 01 d0 0f b6 10 8b 5d 08 8b 45 f8 01 d8 31 ca 88 10 83 45 f8 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_JH_2147830664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.JH!MTB"
        threat_id = "2147830664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 04 3b 45 10 0f 83 ?? ?? ?? ?? 8b 45 08 89 04 24 8b 44 24 04 31 d2 f7 75 14 8b 04 24 c1 ea 02 0f be 04 10 6b c0 48 6b c0 4f 6b f0 4b 8b 45 0c 8b 4c 24 04 0f be 14 08 31 f2 88 14 08 8b 44 24 04 83 c0 01 89 44 24 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKRL_2147830718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKRL!MTB"
        threat_id = "2147830718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 18 d3 e8 8b d5 8d 4c 24 ?? 89 44 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 33 4c 24 ?? 89 35 ?? ?? ?? ?? 31 4c 24 ?? 8b 44 24 ?? 29 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_JK_2147830745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.JK!MTB"
        threat_id = "2147830745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 c0 8d 74 26 00 89 c2 83 e2 03 0f b6 92 20 b6 48 00 30 90 20 c8 43 00 83 c0 01 3d 00 ee 04 00 75 e4}  //weight: 10, accuracy: High
        $x_10_2 = {89 de 83 c3 01 89 5c 24 04 c7 04 24 00 e0 52 00 e8 ?? ?? ?? ?? 83 e6 03 0f b6 86 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 81 fb 7e 07 00 00}  //weight: 10, accuracy: Low
        $x_1_3 = "\\Start Menu\\Programs\\Startup\\Product.exe" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redline_MKTT_2147830830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKTT!MTB"
        threat_id = "2147830830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 30 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? d3 ee c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 74 24 ?? 8b 44 24 ?? 31 44 24 ?? 33 74 24 ?? 83 3d ?? ?? ?? ?? ?? 89 74 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d0 d3 ea 8d 4c 24 ?? 89 54 24 ?? 8b 54 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 54 24 ?? 33 d1 8d 4c 24 ?? 89 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKYY_2147830842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKYY!MTB"
        threat_id = "2147830842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 83 25 ?? ?? ?? ?? ?? 8d 14 01 8b c8 c1 e1 ?? 03 4d ?? c1 e8 ?? 33 ca 03 c3 33 c1 89 55 ?? 89 4d ?? 89 45 ?? 8b 45 ?? 01 05}  //weight: 1, accuracy: Low
        $x_1_2 = {01 45 fc 83 6d fc ?? 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_JF_2147830850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.JF!MTB"
        threat_id = "2147830850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d8 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 83 c3 01 81 fb 7e 07 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KB_2147830892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KB!MTB"
        threat_id = "2147830892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e2 89 7c 24 20 03 54 24 3c 89 54 24 10 8b 44 24 2c 01 44 24 20 8b 44 24 18 90 01 44 24 20 8b 44 24 20 89 44 24 28 8b 44 24 18 8b 4c 24 1c d3 e8 89 44 24 14 8b 44 24 40 01 44 24 14 8b 4c 24 14 33 4c 24 28 8b 54 24 10 33 d1 8d 4c 24 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TA_2147830897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TA!MTB"
        threat_id = "2147830897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 31 d2 f7 b4 ?? ?? ?? ?? 00 89 e8 c1 ea 02 f6 24 17 30 04 0b 83 c1 01 39 f1 75 e3 83 c4 7c 5b 5e 5f 5d c3}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKLK_2147830925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKLK!MTB"
        threat_id = "2147830925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 83 25 ?? ?? ?? ?? ?? 8d 14 01 8b c8 c1 e1 ?? 03 4d ?? c1 e8 ?? 33 ca 03 c3 33 c1 89 55 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {01 45 fc 83 6d fc ?? 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKIK_2147831004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKIK!MTB"
        threat_id = "2147831004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8d 14 06 c1 e1 ?? 03 4d ?? c1 e8 ?? 03 45 ?? 33 ca 33 c1 89 4d ?? 89 45 ?? 8b 45 ?? 01 05}  //weight: 1, accuracy: Low
        $x_1_2 = {01 45 fc 83 6d ?? ?? 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKNK_2147831005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKNK!MTB"
        threat_id = "2147831005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 31 4c 24 ?? 83 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 44 24 ?? 33 c1 2b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_IBKP_2147831006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.IBKP!MTB"
        threat_id = "2147831006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a ca 66 8b f0 66 0f ab f6 d3 c0 f8 81 ce ?? ?? ?? ?? 8d b4 15 fc fe ff ff f8 02 c2 f8 81 fd ?? ?? ?? ?? 32 04 37}  //weight: 1, accuracy: Low
        $x_1_2 = {88 06 0f 84 11 00 00 00 42 3c 76 f9 f5 81 fa 04 01 00 00 0f 82 7b e8 13 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TD_2147831074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TD!MTB"
        threat_id = "2147831074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 08 89 45 ec 8b 45 f0 31 d2 f7 75 14 8b 45 ec c1 ea 02 0f be 04 10 6b c0 18 b9 ?? ?? ?? ?? 99 f7 f9 c1 e0 04 6b c0 4c 6b f0 62 8b 45 0c 8b 4d f0 0f be 14 08 31 f2 88 14 08 8b 45 f0 83 c0 01 89 45 f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TB_2147831121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TB!MTB"
        threat_id = "2147831121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 84 24 ?? ?? ?? ?? 83 c8 20 89 44 24 64 e9 ?? ?? ?? ?? 0f be 84 24 ?? ?? ?? ?? 89 44 24 64 8b 44 24 68 8b 4c 24 64 31 c8 69 c0 93 01 00 01 89 84 24 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c [0-32] 5c 4d 53 42 75 69 6c 64 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YX_2147831122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YX!MTB"
        threat_id = "2147831122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {51 33 cb 59 8b c8 83 e1 03 8a 89 ?? ?? ?? ?? 30 0c 30 40 3b c2 72 e9 5e c3}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YY_2147831130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YY!MTB"
        threat_id = "2147831130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 e6 89 c8 29 d0 d1 e8 01 d0 c1 e8 06 6b c0 a5 01 c8 c1 e8 02 0f be 80 ?? ?? ?? ?? c1 e0 03 8d 04 40 0f bf d0 69 d2 ?? ?? ?? ?? c1 ea 10 01 c2 0f b7 c2 89 c2 c1 ea 0f c1 e8 05 01 d0 c0 e0 07 30 81 ?? ?? ?? ?? 83 c1 01 81 f9 7e 07 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YW_2147831144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YW!MTB"
        threat_id = "2147831144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 08 89 45 ec 8b 45 f0 31 d2 f7 75 14 8b 45 ec c1 ea 02 0f be 04 10 6b c0 57 b9 ?? ?? ?? ?? 99 f7 f9 6b c0 3d 6b c0 22 6b f0 41 8b 45 0c 8b 4d f0 0f be 14 08 31 f2 88 14 08 8b 45 f0 83 c0 01 89 45 f0 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KMM_2147831195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KMM!MTB"
        threat_id = "2147831195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f ab d0 b8 ?? ?? ?? ?? 66 0f a3 de 8a ca 66 f7 d6 d3 c0 8d b4 15 fc fe ff ff 81 fd ?? ?? ?? ?? 02 c2 66 f7 c1 2d 1f 66 81 fa 82 52 32 04 37}  //weight: 1, accuracy: Low
        $x_1_2 = {e9 e6 0e 0e 00 88 06 e9 2f 61 02 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKYL_2147831196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKYL!MTB"
        threat_id = "2147831196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 31 4c 24 ?? 83 3d ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 44 24 ?? 33 c1 2b f0 ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKZL_2147831259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKZL!MTB"
        threat_id = "2147831259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ee 05 03 75 ?? 03 c3 33 c1 33 f0 89 45 ?? 89 75 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 56 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {01 45 fc 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WX_2147831321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WX!MTB"
        threat_id = "2147831321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {51 33 cb 59 8b c8 83 e1 03 8a 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 40 3d 7e 07 00 00 72 e3}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKCY_2147831367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKCY!MTB"
        threat_id = "2147831367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 33 c1 33 f0 89 4d ?? 89 45 ?? 89 75 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 56 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {01 45 fc 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_UY_2147831404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.UY!MTB"
        threat_id = "2147831404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d0 c1 e8 02 89 c2 8b 45 08 01 d0 0f b6 00 0f be d0 89 d0 c1 e0 06 8d 0c 10 ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa 03 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 05 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0 01}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GD_2147831496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GD!MTB"
        threat_id = "2147831496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d 10 83 c4 08 eb 03 8d 34 3b 8b c3 43 83 e0 03 8a 04 08 30 06 8b 45 f0 3b 5d 0c 72 cd}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKKM_2147831527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKKM!MTB"
        threat_id = "2147831527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ce c1 ee ?? 03 75 ?? 03 c7 33 c1 33 f0 89 4d ?? 89 45 ?? 89 75 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 56 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {01 45 fc 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MK_2147831539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MK!MTB"
        threat_id = "2147831539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 80 07 ?? 80 2f ?? f6 2f 47 e2 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MK_2147831539_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MK!MTB"
        threat_id = "2147831539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d e8 8b 45 08 8b 75 0c 8d 55 ec 89 34 24 8a 12 88 54 24 04 89 44 24 08 e8 ?? ?? ?? ?? 83 ec 0c 89 45 f8 8b 45 f8 83 c4 20}  //weight: 5, accuracy: Low
        $x_3_2 = "jmnhbgvrypzwjbadzbbqyay" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ML_2147831540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ML!MTB"
        threat_id = "2147831540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 80 07 ?? b8 df 00 00 00 80 2f ?? f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ML_2147831540_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ML!MTB"
        threat_id = "2147831540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c8 ba 00 00 00 00 f7 f5 c1 ea 02 b8 68 00 00 00 f6 24 17 30 04 0b 83 c1 01 39 ce 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WY_2147831559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WY!MTB"
        threat_id = "2147831559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 84 24 ?? ?? ?? ?? 83 c8 20 89 44 24 ?? e9 ?? ?? ?? ?? 0f be 84 24 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 31 c8 69 c0 93 01 00 01 89 84 24 ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GH_2147831567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GH!MTB"
        threat_id = "2147831567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f0 0f b6 0c 37 c1 e8 02 0f be 98 ?? ?? ?? ?? 6b db 4c b8 ?? ?? ?? ?? f7 eb c1 fb 1f 89 d0 ba ?? ?? ?? ?? c1 f8 04 29 d8 0f af c2 31 c1 88 0c 37 83 c6 01 83 fe 10 75 c7}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKW_2147831644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKW!MTB"
        threat_id = "2147831644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 31 4c 24 ?? 83 3d ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GW_2147831649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GW!MTB"
        threat_id = "2147831649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 08 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 33 46 3b f7 72 da}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GC_2147831765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GC!MTB"
        threat_id = "2147831765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 15 04 60 56 00 a1 00 c0 56 00 03 85 ?? ?? ?? ?? 0f b6 08 33 ca 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 88 0a eb bc}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKU_2147831772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKU!MTB"
        threat_id = "2147831772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 08 0f be 4d ?? 31 c8 0f be 4d ?? 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f be 14 08 29 f2 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKU_2147831772_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKU!MTB"
        threat_id = "2147831772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 54 24 ?? 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 83 3d ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e2 8b 4c 24 ?? 03 c8 c1 e8 ?? 03 d5 89 54 24 ?? 89 4c 24 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 54 24 ?? 33 54 24 ?? 8b 44 24 ?? 33 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKWQ_2147831773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKWQ!MTB"
        threat_id = "2147831773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e0 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? 8b 55 ?? 03 55 ?? 89 55}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 33 55 ?? 89 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWY_2147831789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWY!MTB"
        threat_id = "2147831789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 08 8b 45 f4 01 d0 0f b6 08 8b 45 f4 83 e0 03 89 c2 8b 45 10 01 d0 0f b6 10 8b 5d 08 8b 45 f4 01 d8 31 ca 88 10 83 45 f4}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWZ_2147831794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWZ!MTB"
        threat_id = "2147831794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 74 24 20 c1 ea ?? 0f be 5c 15 ?? 6b db 57 b8 ?? ?? ?? ?? f7 eb 89 d0 c1 f8 04 c1 fb 1f 29 d8 ba ?? ?? ?? ?? 0f af c2 30 04 0e 83 c1 ?? 39 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWV_2147831805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWV!MTB"
        threat_id = "2147831805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d0 0f b6 00 0f be c0 6b c8 ?? ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 ba ?? ?? ?? ?? 0f af c2 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWU_2147831870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWU!MTB"
        threat_id = "2147831870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be c0 6b c8 ?? ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e2 ?? 29 d0 c1 e0 ?? 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SLA_2147831936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SLA!MTB"
        threat_id = "2147831936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f b6 d1 d0 c9 f6 de 81 fd ?? ?? ?? ?? 32 d9 89 04 0c 8d ad ?? ?? ?? ?? 8b 54 25 ?? 66 ?? ?? 33 d3 f7 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWC_2147831961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWC!MTB"
        threat_id = "2147831961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ec 33 c9 39 4d 0c 76 17 8b 55 08 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 11 41 3b 4d 0c 72 ec 5d}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKWW_2147832063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKWW!MTB"
        threat_id = "2147832063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? c7 85}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ea 05 89 55 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWE_2147832070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWE!MTB"
        threat_id = "2147832070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 33 c9 39 4d 0c ?? ?? 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 0a 41 3b 4d 0c 72 ec}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MM_2147832128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MM!MTB"
        threat_id = "2147832128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 80 07 ?? b8 ?? 00 00 00 80 2f ?? f6 2f 47 e2 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MM_2147832128_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MM!MTB"
        threat_id = "2147832128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 00 0f be c0 6b c8 ?? ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 03 01 d0 c1 e0 03 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0 01 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWG_2147832164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWG!MTB"
        threat_id = "2147832164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 f8 0f b6 84 3d ?? ?? ?? ?? 88 84 1d ?? ?? ?? ?? 8b c3 8b 5d f4 88 8c 3d ?? ?? ?? ?? 0f b6 84 05 ?? ?? ?? ?? 03 c2 0f b6 c0 0f b6 84 05 f0 fe ff ff 30 46 ff 8b 45 f8 85 db 75 a5}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MII_2147832239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MII!MTB"
        threat_id = "2147832239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 4d 0c 89 35 ?? ?? ?? ?? 33 4d ?? 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 51 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWA_2147832255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWA!MTB"
        threat_id = "2147832255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 c4 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 c4 0f b6 02 33 c1 8b 4d 08 03 4d c4 88 01 e9 7c ff ff ff}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWB_2147832256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWB!MTB"
        threat_id = "2147832256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 83 3d ?? ?? ?? ?? 6b 75 10}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWS_2147832278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWS!MTB"
        threat_id = "2147832278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 08 03 45 c0 0f b6 08 8b 45 c0 33 d2 be 04 00 00 00 f7 f6 8b 45 10 0f b6 14 10 33 ca 88 4d c7 8b 45 08 03 45 c0 8a 4d c7 88 08 eb 64 c6 45 fc 02 8d 4d c8}  //weight: 10, accuracy: High
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GF_2147832283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GF!MTB"
        threat_id = "2147832283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0a 66 45 33 f7 66 41 8b 6a 08 45 22 f3 41 80 f6 b6 41 0f a3 d6 49 81 c2 0a 00 00 00 36 66 89 29 41 d2 f6 66 41 0f ba e6 f6 f9 45 8b 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GWT_2147832292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GWT!MTB"
        threat_id = "2147832292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d0 c1 e8 02 89 c2 8b 45 08 01 d0 0f b6 00 0f be c0 6b c8 4c ba ?? ?? ?? ?? 89 c8 f7 ea 8d 04 0a c1 f8 04 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 89 c2 b8 ?? ?? ?? ?? 29 d0 c1 e0 06 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MVL_2147832449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MVL!MTB"
        threat_id = "2147832449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 01 85 ?? ?? ?? ?? 8b 45 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea 89 55 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 89 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTA_2147832451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTA!MTB"
        threat_id = "2147832451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c2 8b 45 08 01 d0 0f b6 00 0f be c0 6b c8 ?? ba ?? ?? ?? ?? 89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 ba ?? ?? ?? ?? 0f af c2 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0 01 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_HS_2147832461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.HS!MTB"
        threat_id = "2147832461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c3 83 e0 03 8a 04 10 30 01 43 8b 45 f0 3b df 72 ca}  //weight: 1, accuracy: High
        $x_1_2 = "alderson" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTB_2147832466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTB!MTB"
        threat_id = "2147832466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 45 c0 0f b6 08 8b 45 c0 33 d2 be 04 00 00 00 f7 f6 8b 45 10 0f b6 14 10 33 ca 88 4d c7 8b 45 08 03 45 c0 8a 4d c7 88 08 eb 64}  //weight: 10, accuracy: High
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MVN_2147832518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MVN!MTB"
        threat_id = "2147832518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 8b 4d ?? d3 e0 89 75 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 81 45 ?? ?? ?? ?? ?? 31 45 ?? 2b 5d ?? ff 4d ?? 89 35 ?? ?? ?? ?? 89 5d ?? 0f 85 b5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTC_2147832560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTC!MTB"
        threat_id = "2147832560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 83 3d ?? ?? ?? ?? 20 75 13 46 00 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTC_2147832560_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTC!MTB"
        threat_id = "2147832560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f4 33 d2 f7 75 ?? 8b 4d ?? 0f be 04 11 6b c0 ?? 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 6b c0 ?? 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb}  //weight: 10, accuracy: Low
        $x_10_2 = {31 f2 8b 75 b4 01 ce 89 34 24 89 7c 24 04 89 54 24 08 89 45 a8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_GTD_2147832568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTD!MTB"
        threat_id = "2147832568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 f8 8a 14 11 80 f2 42 88 14 01 41 3b 4d fc ?? ?? 8b 4d fc 50 88 1c 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTD_2147832568_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTD!MTB"
        threat_id = "2147832568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 ba ?? ?? ?? ?? 0f af c2 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0 01 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BT_2147832634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BT!MTB"
        threat_id = "2147832634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 45 f8 33 45 e8 81 45 e0 47 86 c8 61 31 45 fc 2b 5d fc ff 4d d8 89 35 84 bf 44 00 89 5d dc 0f 85 b6 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BT_2147832634_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BT!MTB"
        threat_id = "2147832634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f6 0f b6 92 [0-4] 33 ca 88 4d ff 8b 45 f8 8a 88 [0-4] 88 4d fd 0f b6 55 ff 8b 45 f8 0f b6 88 [0-4] 03 ca 8b 55 f8 88 8a}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 f8 0f b6 82 [0-4] 2b c1 8b 4d f8 88 81 [0-4] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GXZ_2147832644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GXZ!MTB"
        threat_id = "2147832644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 08 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GXZ_2147832644_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GXZ!MTB"
        threat_id = "2147832644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 55 53 8d 4c 24 ?? e8 ?? ?? ?? ?? 8d 4c 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 8d 4c 24 ?? 8a 44 04 ?? 30 87 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 5c 24 ?? 47 8b 6c 24 ?? 81 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTE_2147832645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTE!MTB"
        threat_id = "2147832645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 08 03 55 c0 0f b6 0a 8b 45 c0 33 d2 be 04 00 00 00 f7 f6 8b 45 10 0f b6 14 10 33 ca 88 4d eb 8b 45 08 03 45 c0 8a 4d eb 88 08 eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MJK_2147832731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MJK!MTB"
        threat_id = "2147832731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 8d 0c 07 33 4d 0c 89 35 ?? ?? ?? ?? 33 4d f4 89 4d f4 8b 45 f4 01 05 ?? ?? ?? ?? 51 8d 45 f8 50 e8 ?? ?? ?? ?? 8b 7d f8 c1 e7 04 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTH_2147832764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTH!MTB"
        threat_id = "2147832764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be c0 6b c8 57 ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 ba ?? ?? ?? ?? 0f af c2 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TS_2147832806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TS!MTB"
        threat_id = "2147832806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 03 33 4d ?? 89 35 ?? ?? ?? ?? 33 cf 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 51 8d 45 ?? 50 e8 ?? ?? ?? ?? 8b 5d ?? 8b fb c1 e7 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TS_2147832806_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TS!MTB"
        threat_id = "2147832806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 c8 88 45 ?? 0f b6 4d ?? 31 c0 29 c8 88 45 ?? 8b 4d ?? 0f b6 45 ?? 31 c8 88 45 ?? 0f b6 45 ?? 83 e8 ?? 88 45 ?? 0f b6 45 ?? c1 f8}  //weight: 2, accuracy: Low
        $x_2_2 = {35 f1 00 00 00 88 45 e3 8a 4d e3 8b 45 e4 88 4c 05 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTI_2147832818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTI!MTB"
        threat_id = "2147832818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 50 e8 ?? ?? ?? ?? 33 d2 8a 1c 33 8b c6 8b 4c 24 18 f7 75 08 83 c4 0c 8a 82 ?? ?? ?? ?? 32 c3 88 44 24 ?? 02 c3 88 04 31}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTI_2147832818_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTI!MTB"
        threat_id = "2147832818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 ba ?? ?? ?? ?? 0f af c2 89 c1 8b 55 ?? 8b 45 ?? 01 d0 31 cb 89 da 88 10 83 45 ec 01 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTJ_2147832837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTJ!MTB"
        threat_id = "2147832837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 5c 15 00 6b db ?? b8 ?? ?? ?? ?? f7 eb 89 d0 c1 f8 ?? c1 fb ?? 29 d8 ba ?? ?? ?? ?? 0f af c2 30 04 0e 83 c1 ?? 39 f9 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTK_2147832938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTK!MTB"
        threat_id = "2147832938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e0 1a f7 de 87 f7 f7 05 ?? ?? ?? ?? ac 87 6d 62 7e 05 e8 ?? ?? ?? ?? 48 33 15 ?? ?? ?? ?? c1 eb 01 f7 d6 c1 c3 18 81 ee ?? ?? ?? ?? c1 c2 09 e2 c2}  //weight: 10, accuracy: Low
        $x_10_2 = {b7 8c 76 70 81 f0 a7 1c 73 63 c7 05 ?? ?? ?? ?? 44 96 e9 68 09 3d ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
        $x_1_3 = "secure.logmein.com" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TZ_2147832947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TZ!MTB"
        threat_id = "2147832947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 31 08 5d}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 dc 8d 0c 07 33 4d ?? 89 35 ?? ?? ?? ?? 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 51 8d 45 ?? 50 e8 ?? ?? ?? ?? 8b 5d ?? 8b fb c1 e7 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTN_2147832949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTN!MTB"
        threat_id = "2147832949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d fc 8b 15 ?? ?? ?? ?? 80 34 11 55 8d 04 11 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 4d ?? 3b 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTN_2147832949_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTN!MTB"
        threat_id = "2147832949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c2 0f b6 45 e7 c1 e0 ?? 09 d0 88 45 e7 80 45 e7 4f 0f b6 45 e7 c1 f8 ?? 89 c2 0f b6 45 e7 c1 e0 ?? 09 d0 88 45 e7 80 75 e7 3a 80 45 e7 78 8b 45 ec 30 45 e7 8b 45 ec 00 45 e7 f6 55 e7 8b 45 ec 28 45 e7 f6 5d e7 8d 55 d0 8b 45 ec 01 c2 0f b6 45 e7 88 02 83 45 ec 01}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTO_2147832989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTO!MTB"
        threat_id = "2147832989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8a 1c 33 8b c6 8b 4c 24 18 f7 75 08 83 c4 0c 8a 82 ?? ?? ?? ?? ba ?? ?? ?? ?? 32 c3 88 44 24 ?? 02 c3 68 ?? ?? ?? ?? 88 04 31}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTO_2147832989_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTO!MTB"
        threat_id = "2147832989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 4c 05 dc 80 f1 c8 d0 c1 02 c8 f6 d1 32 c8 80 c1 ?? 80 f1 ef 02 c8 32 c8 80 c1 ?? 32 c8 80 e9 ?? c0 c1 ?? 88 4c 05 dc 40 83 f8 0f 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTQ_2147833021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTQ!MTB"
        threat_id = "2147833021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 4d f8 33 4d e8 8b 45 f4 81 45 ?? 47 86 c8 61 33 c1 2b f8 83 6d d8 01 89 45 f4 89 1d}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_JC_2147833071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.JC!MTB"
        threat_id = "2147833071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 e2 89 5d ?? 03 55 ?? 89 55 ?? 8b 45 ?? 01 45 ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 33 4d ?? 8b 45 ?? 33 c1 2b f8 89 45 ?? 89 1d ?? ?? ?? ?? 89 7d ?? 8b 45 ?? 29 45 ?? 83 6d d8 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTS_2147833088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTS!MTB"
        threat_id = "2147833088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {28 ca 80 f2 ?? d0 c2 0f b6 ca 01 c1 31 c1 b2 46 28 ca 80 f2 ?? 0f b6 ca 01 c1 31 c1 80 c1 ?? 30 c1 80 c1 ?? c0 c1 ?? 88 4c 05 d0 83 f8 0e 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTT_2147833152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTT!MTB"
        threat_id = "2147833152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 04 10 c1 e0 ?? 6b c0 ?? b9 ?? ?? ?? ?? 99 f7 f9 b9 ?? ?? ?? ?? 99 f7 f9 6b f0 ?? 8b 45 0c 8b 4d f0 0f be 14 08 31 f2 88 14 08 8b 45 f0 83 c0 ?? 89 45 f0 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTP_2147833185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTP!MTB"
        threat_id = "2147833185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d7 d3 ea 03 45 ?? 89 45 ?? 8b 45 ?? 03 55 ?? 03 c7 89 45 ?? 8b 45 ?? 31 45 ?? 31 55 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTW_2147833217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTW!MTB"
        threat_id = "2147833217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 08 03 55 bc 8a 02 88 45 c3 0f b6 4d c3 8b 45 bc 33 d2 f7 75 b4 8b 45 10 0f b6 14 10 33 ca 88 4d eb 8b 45 08 03 45 bc 8a 4d eb 88 08 eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTX_2147833278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTX!MTB"
        threat_id = "2147833278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 ba ?? ?? ?? ?? 0f af c2 89 c1 8b 55 f4 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTZ_2147833282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTZ!MTB"
        threat_id = "2147833282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f0 0f b6 1c 37 c1 e8 ?? 0f be 88 ?? ?? ?? ?? 6b c9 ?? b8 ?? ?? ?? ?? f7 e9 01 ca c1 f9 ?? c1 fa ?? 29 d1 c1 e1 ?? 31 d9 88 0c 37 83 c6 ?? 83 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GUA_2147833340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GUA!MTB"
        threat_id = "2147833340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 29 d0 89 c1 8b 55 f4 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NYK_2147833406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NYK!MTB"
        threat_id = "2147833406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 8b 4d ?? 89 45 ?? 8b c3 03 55 ?? d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 33 55 ?? 8d 4d ?? 52 ff 75 ?? 89 55 ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 89 45 fc 8b 45 08 31 45 fc 8b 45 fc 89 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GUD_2147833411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GUD!MTB"
        threat_id = "2147833411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d1 83 e1 03 0f b6 89 ?? ?? ?? ?? 30 8a ?? ?? ?? ?? 83 c2 ?? 81 fa 00 66 01 00 75}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GUF_2147833496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GUF!MTB"
        threat_id = "2147833496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 00 0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 29 d0 89 c1 8b 55 ?? 8b 45 ?? 01 d0 31 cb 89 da 88 10 83 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YO_2147833520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YO!MTB"
        threat_id = "2147833520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 83 65 fc 00 8b 45 0c 89 45 fc 8b 45 08 31 45 fc 8b 45 fc 89 01}  //weight: 1, accuracy: High
        $x_1_2 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 33 55 ?? 8d 4d ?? 52 ff 75 ?? 89 55 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTU_2147833539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTU!MTB"
        threat_id = "2147833539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 0c c7 45 ?? 00 00 00 00 b8 ?? ?? ?? ?? 99 33 c2 2b c2 89 45 d0 83 7d d0 d8 74}  //weight: 10, accuracy: Low
        $x_10_2 = {6b c9 28 c7 84 0d ?? ?? ?? ?? b1 7b ff 28 ba 04 00 00 00 6b d2 09 c7 84 15 ?? ?? ?? ?? a6 c3 65 bf b8 04 00 00 00 6b c0 4b c7 84 05 ?? ?? ?? ?? 12 02 ff 36}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CNC_2147833601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CNC!MTB"
        threat_id = "2147833601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 33 45 f8 8b 4d d4 03 cb 33 c8 89 45 0c 89 4d ec 89 35 ?? ?? ?? ?? 8b 45 ?? 01 05}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 03 45 e0 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 89 75 ?? 8b 45 ?? 01 45 ?? 2b 7d ?? ff 4d ?? 8b 4d ?? 89 7d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GI_2147833636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GI!MTB"
        threat_id = "2147833636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 83 e1 03 8a 89 ?? ?? ?? ?? 30 0c 07 40 3b c2 72}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WYK_2147833698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WYK!MTB"
        threat_id = "2147833698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 33 5d ?? 31 5d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 45 f8 33 45 ec 89 35 ?? ?? ?? ?? 33 d0 89 55 d8 8b 45 d8 29 45 f0 8b 45 d0 29 45 f4 ff 4d e0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJK_2147833808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJK!MTB"
        threat_id = "2147833808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d0 0f b6 00 0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 01 c0 01 d0 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJN_2147833830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJN!MTB"
        threat_id = "2147833830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c2 83 e2 03 0f b6 92 20 54 42 00 30 90 20 a8 40 00 83 c0 01 3d 00 ac 01 00 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJN_2147833830_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJN!MTB"
        threat_id = "2147833830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {88 4d df 0f b6 55 df 03 55 e0 88 55 df 0f b6 45 df c1 f8 07 0f b6 4d df d1 e1 0b c1 88 45 df 0f b6 55 df 2b 55 e0 88 55 df 0f b6 45 df f7 d0 88 45 df 0f b6 4d df f7 d9 88 4d df 0f b6 55 df 81 ea aa 00 00 00 88 55 df 8b 45 e0 8a 4d df 88 4c 05 e4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJM_2147833838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJM!MTB"
        threat_id = "2147833838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {88 45 df 0f b6 4d df c1 f9 02 0f b6 55 df c1 e2 06 0b ca 88 4d df 0f b6 45 df 03 45 e0 88 45 df 0f b6 4d df f7 d1 88 4d df 0f b6 55 df c1 fa 05 0f b6 45 df c1 e0 03 0b d0 88 55 df 8b 4d e0 8a 55 df 88 54 0d e4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJM_2147833838_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJM!MTB"
        threat_id = "2147833838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 c0 33 d2 f7 75 b4 8b 45 10 0f b6 14 10 33 ca 88 4d eb 8b 45 08 03 45 c0 8a 08 88 4d be 0f b6 55 eb 8b 45 08 03 45 c0 0f b6 08 03 ca 8b 55 08 03 55 c0 88 0a 0f b6 45 be 8b 4d 08 03 4d c0 0f b6 11 2b d0 8b 45 08 03 45 c0 88 10 eb}  //weight: 10, accuracy: High
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJO_2147833863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJO!MTB"
        threat_id = "2147833863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c1 83 e1 03 8a 89 ?? ?? ?? ?? 30 0c 07 40 3b c2 72}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c8 83 e1 03 8a 89 ?? ?? ?? ?? 30 0c 07 40 3b c2 72}  //weight: 10, accuracy: Low
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redline_GJP_2147833945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJP!MTB"
        threat_id = "2147833945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c2 83 e2 03 0f b6 92 20 74 45 00 30 90 20 c8 43 00 83 c0 01 3d 00 ac 01 00 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJP_2147833945_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJP!MTB"
        threat_id = "2147833945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f7 da 88 55 df 0f b6 45 df f7 d0 88 45 df 0f b6 4d df 2b 4d e0 88 4d df 0f b6 55 df f7 d2 88 55 df 0f b6 45 df 03 45 e0 88 45 df 8b 4d e0 8a 55 df 88 54 0d e4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJP_2147833945_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJP!MTB"
        threat_id = "2147833945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 89 c1 8b 55 ec 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 ec}  //weight: 10, accuracy: Low
        $x_10_2 = {0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 01 c0 01 d0 89 c1 8b 55 ec 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 ec}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_GJQ_2147833946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJQ!MTB"
        threat_id = "2147833946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 02 88 45 bf 0f b6 4d bf 8b 45 c0 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d c7 8b 45 08 03 45 c0 8a 08 88 4d be 8a 55 be 88 55 bd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJQ_2147833946_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJQ!MTB"
        threat_id = "2147833946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e8 31 d2 f7 74 24 2c 8b 44 24 20 c1 ea ?? 0f be 0c 10 69 c9 ?? ?? ?? ?? 89 c8 f7 ef 8d 04 0a c1 f9 ?? ba ?? ?? ?? ?? c1 f8 ?? 29 c8 0f af c2 30 04 2b 83 c5 01 39 6c 24 ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MN_2147833990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MN!MTB"
        threat_id = "2147833990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 80 07 ?? b8 ?? ?? ?? ?? b8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 80 2f ?? f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MN_2147833990_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MN!MTB"
        threat_id = "2147833990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 f0 31 d2 b9 7b 05 00 00 f7 75 14 8b 45 08 c1 ea 02 0f be 04 10 69 c0 ec 0d 00 00 99 f7 f9 b2 33 0f af c2 30 04 33 46 eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GSM_2147834042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GSM!MTB"
        threat_id = "2147834042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 33 7d ?? 31 7d ?? 83 3d ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e0 03 45 ?? 33 45 ?? 33 c2 89 45 ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MO_2147834050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MO!MTB"
        threat_id = "2147834050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 44 2c 3c 0f b6 44 1c 3c 03 44 24 34 0f b6 c0 8a 44 04 3c 30 04 39 8b 44 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MO_2147834050_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MO!MTB"
        threat_id = "2147834050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 d2 f7 75 14 8b 45 f0 c1 ea 02 0f be 04 10 6b c0 2b c1 e0 06 b9 2c 00 00 00 99 f7 f9 b9 17 00 00 00 99 f7 f9 6b f0 0b 8b 45 0c 8b 4d f4 0f be 14 08 31 f2 88 14 08 8b 45 f4 83 c0 01 89 45 f4 e9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_HEV_2147834077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.HEV!MTB"
        threat_id = "2147834077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 ?? 03 45 dc c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 f4 8b 45 ?? 31 45 ?? 8b 45 f4 31 45 ?? 8b 45 ?? 29 45 fc 68 ?? ?? ?? ?? 8d 45 f0 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AWC_2147834128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AWC!MTB"
        threat_id = "2147834128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 83 65 fc ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 03 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 68 ?? ?? ?? ?? 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJR_2147834134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJR!MTB"
        threat_id = "2147834134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c3 43 83 e0 03 8a 80 ?? ?? ?? ?? 30 06 8b 45 f0 3b 5d 0c 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJS_2147834219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJS!MTB"
        threat_id = "2147834219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3c d3 40 00 c7 45 ?? 35 45 00 00 c7 85 ?? ?? ?? ?? 48 d3 40 00 c6 45 ?? 77 c7 85 ?? ?? ?? ?? 60 d3 40 00 c7 85 ?? ?? ?? ?? 68 09 00 00 c7 85 ?? ?? ?? ?? 7c d3 40 00 b9 af 6e 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJS_2147834219_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJS!MTB"
        threat_id = "2147834219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 01 c0 01 d0 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MCR_2147834240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MCR!MTB"
        threat_id = "2147834240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d0 c1 e0 02 01 d0 01 c0 01 d0 89 c1 8b 55 ?? 8b 45 ?? 01 d0 31 cb 89 da 88 10 83 45 ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJT_2147834244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJT!MTB"
        threat_id = "2147834244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 2f ?? 47 e2}  //weight: 10, accuracy: Low
        $x_10_2 = {d1 f8 0f b6 8d ?? ?? ?? ?? c1 e1 07 0b c1 88 85 ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? f7 da}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJT_2147834244_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJT!MTB"
        threat_id = "2147834244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e8 31 d2 83 ec 04 f7 74 24 3c c1 ea ?? 0f be 0c 16 69 c9 ?? ?? ?? ?? 89 c8 f7 ef 01 ca c1 f9 ?? c1 fa ?? 29 ca 8d 04 92 8d 14 42 30 14 2b 83 c5 ?? 39 6c 24}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJV_2147834284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJV!MTB"
        threat_id = "2147834284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d6 d3 ea 03 c6 89 44 24 ?? 8b cb 8d 44 24 ?? 89 54 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJV_2147834284_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJV!MTB"
        threat_id = "2147834284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 c0 09 d0 88 45 a7 8b 45 f0 00 45 a7 f6 5d a7 80 75 a7 73 8b 45 f0 28 45 a7 8b 45 f0 30 45 a7 f6 5d a7 80 6d a7 43 8d 55 84 8b 45 f0 01 c2 0f b6 45 a7 88 02 83 45 f0 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJU_2147834304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJU!MTB"
        threat_id = "2147834304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 2f ?? 47 e2}  //weight: 10, accuracy: Low
        $x_10_2 = {d1 f9 0f b6 95 ?? ?? ?? ?? c1 e2 07 0b ca 88 8d ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJU_2147834304_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJU!MTB"
        threat_id = "2147834304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = "yxvxsiwvos" ascii //weight: 1
        $x_1_3 = "rjldovpvtmoahdud" ascii //weight: 1
        $x_1_4 = "eikhqqryqgbfat" ascii //weight: 1
        $x_1_5 = "SystemFunction036" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MP_2147834305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MP!MTB"
        threat_id = "2147834305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 83 65 fc 00 8b 45 10 90 01 45 fc 8b 45 08 8b 4d fc 89 08 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MP_2147834305_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MP!MTB"
        threat_id = "2147834305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 0a 34 73 2c 6c 34 74 04 4e 34 70 2c 65 34 22 2c 73 34 2a 88 04 0a 41 3b 4c 24 08 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MP_2147834305_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MP!MTB"
        threat_id = "2147834305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "pohuyis sofog lesamuwaliy" wide //weight: 5
        $x_5_2 = "cagapizagesi" wide //weight: 5
        $x_5_3 = "jewuwomekorecokoyujesac" wide //weight: 5
        $x_1_4 = "MoveFileWithProgressW" ascii //weight: 1
        $x_1_5 = "GetCurrentThreadId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_LOS_2147834374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.LOS!MTB"
        threat_id = "2147834374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e8 01 4d f8 33 c6 50 8d 45 f8 50 89 3d ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 03 45 e4 03 f1 33 f0 33 75 0c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 75 f8 8b 45 f8 29 45 fc 68 ?? ?? ?? ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ec 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_VIS_2147834433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.VIS!MTB"
        threat_id = "2147834433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 83 3d ?? ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea 8b 4d ?? 8d 45 ?? 89 5d ?? 89 55 ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 c3 31 45 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 81 45 d8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RE_2147834445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RE!MTB"
        threat_id = "2147834445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 02 0f b6 00 0f b6 c0 88 45 ?? c7 45 ?? 02 00 00 00 0f b6 45 ?? 8d 50 ?? 8b 45 ?? 83 ?? ?? 31 d0 88 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 83 c0 03 0f b6 00 0f b6 c0 88 45 ?? c7 45 ?? 03 00 00 00 0f b6 45 ?? 8d 50 ?? 8b 45 ?? 83 ?? ?? 31 d0 88 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJW_2147834459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJW!MTB"
        threat_id = "2147834459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 2f ?? 80 2f ?? 47 e2}  //weight: 10, accuracy: Low
        $x_10_2 = {d1 fa 0f b6 85 ?? ?? ?? ?? c1 e0 ?? 0b d0 88 95}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJW_2147834459_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJW!MTB"
        threat_id = "2147834459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gttwoytpmdciqiomjfos" ascii //weight: 1
        $x_1_2 = "bmuaiqkjgluaruzo" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RF_2147834463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RF!MTB"
        threat_id = "2147834463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 18 33 c1 69 c8 ?? ?? ?? ?? 33 f1 3b d5 7c df 0e 00 69 0c 93 ?? ?? ?? ?? 42 69 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RF_2147834463_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RF!MTB"
        threat_id = "2147834463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 bf 3c b6 22 f7 e2 c1 ea 03 0f be c2 8b 54 24 14 8a ca 6b c0 3b 2a c8 80 c1 33 30 4c 14 1c 42 89 54 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RF_2147834463_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RF!MTB"
        threat_id = "2147834463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37 68 ?? ?? ?? ?? 6a 00 e8 [0-48] 28 1c 37 46 8b 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RF_2147834463_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RF!MTB"
        threat_id = "2147834463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 f6 83 ec 18 c7 04 24 00 00 00 00 c7 44 24 04 00 00 00 00 89 54 24 08 89 4c 24 0c c7 44 24 10 00 00 00 00 c7 44 24 14 00 00 00 00 ff d0 89 c1}  //weight: 5, accuracy: High
        $x_2_2 = {31 f6 83 ee 01 89 c2 01 f2 0f af c2 83 e0 01 83 f8 00 0f 94 c0 83 f9 0a 0f 9c c1 88 c2 20 ca 30 c8 08 c2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJY_2147834466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJY!MTB"
        threat_id = "2147834466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 45 bb 8b 45 bc 33 d2 f7 75 ac 0f b6 8a ?? ?? ?? ?? 0f b6 55 bb 33 d1 88 55 eb 8b 45 bc 8a 88 ?? ?? ?? ?? 88 4d ba 31 d2 89 55 a8 8b 45 a8 89 45 e4 0f b6 4d eb 8b 55 bc 0f b6 82 ?? ?? ?? ?? 03 c1}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ZW_2147834518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ZW!MTB"
        threat_id = "2147834518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d d4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 e0 8d 45 e0 e8 ?? ?? ?? ?? 8b 45 d0 31 45 f8 8b 45 f8 31 45 e0 83 3d 9c 61 c4 02 1f 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea 8b 4d c4 8d 45 e0 89 55 e0 e8 ?? ?? ?? ?? 8b 45 e0 33 c3 31 45 f8 89 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJZ_2147834521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJZ!MTB"
        threat_id = "2147834521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 2f ?? 47 e2}  //weight: 10, accuracy: Low
        $x_10_2 = {f7 d2 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d8 88 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJZ_2147834521_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJZ!MTB"
        threat_id = "2147834521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 83 e1 03 8a 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WON_2147834528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WON!MTB"
        threat_id = "2147834528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e8 05 03 45 ?? 03 f1 33 f0 33 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 75 fc 8b 45 fc 29 45 08 68 ?? ?? ?? ?? 8d 45 f4 50 e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKA_2147834533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKA!MTB"
        threat_id = "2147834533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c9 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKA_2147834533_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKA!MTB"
        threat_id = "2147834533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 4d fe 0f b6 4d fe 8b 45 f8 33 d2 f7 75 f4 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 f8 8a 88 ?? ?? ?? ?? 88 4d fd 0f b6 55 ff 8b 45 f8 0f b6 88 ?? ?? ?? ?? 03 ca}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NEV_2147834569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NEV!MTB"
        threat_id = "2147834569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08}  //weight: 1, accuracy: High
        $x_1_2 = {8b c1 c1 e8 ?? 03 45 ?? 03 f2 33 f0 33 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 75 fc 8b 45 fc 29 45 08 81 45 f4 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKB_2147834590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKB!MTB"
        threat_id = "2147834590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {32 ca f6 d1 80 c1 75 32 ca 2a c1 b1 8b 32 c2 2a c8 2a ca 80 f1 0c 02 ca 32 ca 02 ca 32 ca 88 4c 14 18 42 83 fa 0f 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKB_2147834590_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKB!MTB"
        threat_id = "2147834590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8b c6 f7 74 24 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8a ba ?? ?? ?? ?? 32 fb e8 ?? ?? ?? ?? 8a 1c 3e 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 ?? 83 f8 ?? 75 ?? 2a fb 00 3c 3e 46 3b 74 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKC_2147834623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKC!MTB"
        threat_id = "2147834623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 d8 31 d2 f7 75 14 8b 45 08 0f be 04 10 69 c0 d6 cc e1 c2 30 04 1e 43 eb d1}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KIR_2147834669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KIR!MTB"
        threat_id = "2147834669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e8 05 03 45 ?? 03 f2 33 f0 33 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 75 ?? 8b 45 ?? 29 45 fc 89 7d f8 8b 45 ?? 01 45 f8 2b 5d f8 ff 4d ?? 89 5d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WW_2147834698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WW!MTB"
        threat_id = "2147834698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 89 c8 3a 43 00 88 8d ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKE_2147834710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKE!MTB"
        threat_id = "2147834710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 2f ?? 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKE_2147834710_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKE!MTB"
        threat_id = "2147834710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 c2 f6 d0 32 c2 2a c8 8a c2 80 f1 ?? 02 c0 02 ca 32 ca 80 f1 ?? 2a c8 fe c1 32 ca 88 4c 14 ?? 42 83 fa 0f 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKF_2147834719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKF!MTB"
        threat_id = "2147834719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 3c ?? ?? ?? ?? 03 44 24 14 0f b6 c0 8a 84 04 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKF_2147834719_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKF!MTB"
        threat_id = "2147834719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c0 01 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 3b 0d ?? ?? ?? ?? 73 ?? 0f b6 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 0f b6 08 33 ca 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 88 0a eb}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKG_2147834737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKG!MTB"
        threat_id = "2147834737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 83 e0 03 8a 80 ?? ?? ?? ?? 30 82 ?? ?? ?? ?? 42 81 fa ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NTU_2147834774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NTU!MTB"
        threat_id = "2147834774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08}  //weight: 1, accuracy: High
        $x_1_2 = {8b c1 c1 e8 ?? 03 45 ?? 03 f2 33 f0 33 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 75 fc 8b 45 fc 29 45 08 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 81 45 f4 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKH_2147834794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKH!MTB"
        threat_id = "2147834794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 94 05 ?? ?? ?? ?? 01 c2 31 c2 80 c2 ?? 80 f2 ?? 0f b6 d2 01 c2 31 c2 80 f2 ?? 00 ca 30 c2 88 94 05 ?? ?? ?? ?? 83 c0 ?? 80 c1 ?? 83 f8 ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_QAZ_2147834859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.QAZ!MTB"
        threat_id = "2147834859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08}  //weight: 1, accuracy: High
        $x_1_2 = {8b c2 c1 e8 ?? 03 45 ?? 03 f1 33 f0 33 75 0c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 75 fc 8b 45 fc 29 45 08 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 68 ?? ?? ?? ?? 8d 45 f4 50 e8 ?? ?? ?? ?? ff 4d f0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKK_2147834889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKK!MTB"
        threat_id = "2147834889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 3c ?? ?? ?? ?? 03 c6 59 8b 4c 24 ?? 0f b6 c0 8a 84 04 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 4c 24 ?? 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKK_2147834889_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKK!MTB"
        threat_id = "2147834889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 e7 89 c8 29 d0 d1 e8 01 d0 c1 e8 ?? 6b c0 ?? 01 c8 c1 e8 ?? 0f be 80 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 89 c2 c1 ea ?? c1 e8 ?? 01 d0 c0 e0 ?? 30 84 0e ?? ?? ?? ?? 83 c1 ?? 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NAZ_2147834926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NAZ!MTB"
        threat_id = "2147834926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08}  //weight: 1, accuracy: High
        $x_1_2 = {8b c3 c1 e8 ?? 03 45 ?? 03 f1 33 f0 33 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 75 fc 8b 45 fc 29 45 08 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 68 ?? ?? ?? ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TYT_2147834927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TYT!MTB"
        threat_id = "2147834927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8b d0 c1 ea ?? 03 55 ?? c1 e0 04 03 45 ?? 89 4d ?? 33 d0 33 d1 52 8d 45 fc 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 03 45 ?? 03 f3 33 c6 33 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 29 45 08 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 68 ?? ?? ?? ?? 8d 45 f8 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKM_2147834940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKM!MTB"
        threat_id = "2147834940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c1 01 89 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 3b 15 ?? ?? ?? ?? 73 ?? 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 0f b6 11 33 d0 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKN_2147834951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKN!MTB"
        threat_id = "2147834951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 d3 e8 8d 3c 13 89 45 fc 8b 45 d4 01 45 fc 8b 45 fc 33 c7 31 45 f8 89 35 ?? ?? ?? ?? 8b 45 f4 89 45 f0 8b 45 f8 29 45 f0 8b 45 f0 89 45 f4 81 c3 47 86 c8 61 ff 4d e4 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKP_2147834976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKP!MTB"
        threat_id = "2147834976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 c1 e0 03 01 d0 89 c1 8b 55 e8 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 e8 01 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MS_2147834999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MS!MTB"
        threat_id = "2147834999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 98 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2 ab}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 08 8b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 98 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_MS_2147834999_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MS!MTB"
        threat_id = "2147834999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 04 0f 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ?? 56 56 ff 15 ?? ?? ?? ?? 47 3b 3d ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_10_2 = "larelalukoxiyotujaxajiroxuy" ascii //weight: 10
        $x_10_3 = {b8 fc d8 6a 54 f7 65 ac 8b 45 ac 81 45 b4 62 8f d8 2c b8 26 19 23 63 f7 65 b4 8b 45 b4 81 85 40 ff ff ff 79 c3 29 41 81 6d ac 04 f7 4b 79 81 6d d8 04 b1 b7 69 b8 c4 97 c3 79 f7 a5 40 ff ff ff 8b 85 40 ff ff ff b8 da 98 b4 18 f7 65 d8 8b 45 d8 b8 f7 39 ab 6d f7 65 ac 8b 45 ac b8 cd cd 54 66 f7 a5 40 ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKQ_2147835041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKQ!MTB"
        threat_id = "2147835041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 33 f6 8a 9e ?? ?? ?? ?? 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 86 ?? ?? ?? ?? 8d 46 9b 3d ?? ?? ?? ?? 77}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RTR_2147835112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RTR!MTB"
        threat_id = "2147835112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 03 45 ?? 89 4d ?? 33 d0 33 d1 52 8d 45 f8 50 e8 ?? ?? ?? ?? 8b 75 f8 c1 e6 04 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 03 45 ?? 03 f2 33 c6 33 45 fc c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 f4 8b 45 f4 29 45 08 83 65 0c ?? 8b 45 ?? 01 45 ?? 2b 7d 0c ff 4d ?? 8b 45 ?? 89 7d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKS_2147835187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKS!MTB"
        threat_id = "2147835187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 04 02 6b c0 ?? 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb}  //weight: 10, accuracy: Low
        $x_10_2 = {0f be 04 11 6b c0 ?? 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b 55 0c 03 55 e0 0f be 0a 33 c8 8b 55 0c 03 55 e0 88 0a eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_DZ_2147835198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DZ!MTB"
        threat_id = "2147835198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 d3 0f b6 4d d3 2b 4d d4 88 4d d3 0f b6 55 d3 f7 da 88 55 d3 0f b6 45 d3 c1 f8 03 0f b6 4d d3 c1 e1 05 0b c1 88 45 d3 8b 55 d4 8a 45 d3 88 44 15 e0 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DZ_2147835198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DZ!MTB"
        threat_id = "2147835198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 88 c7 2c 81 6f 13 f8 f3 a6 fa 04 ed 6d 57 40 ed 3e 94 3f 48 85 21 4f a1 3d 45 3c 0a 3f 0e 07 06 38 f0 5b 24 63 6a 57 55 bb c2 27 78 89 cb 7c}  //weight: 1, accuracy: High
        $x_1_2 = {2b f9 ee ff 08 41 72 d0 f9 83 6a 63 a2 f1 cd ae 4e 7b 04 22 4d e3 cc 35 0c 5d 98 cd 8d 48 ea 6f 35 cb ad ce 93 56 96 b2 bf 89 51 d7 2a ef c7 50 7d 5e 06 ba a8 d7 c7 84 54 88 72 de 49 8e 3d 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKT_2147835200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKT!MTB"
        threat_id = "2147835200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 ea 8d 04 0a c1 f8 08 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 ba ?? ?? ?? ?? 0f af c2 89 c1 8b 55 ?? 8b 45 ?? 01 d0 31 cb 89 da 88 10 83 45 e4 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ZIM_2147835264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ZIM!MTB"
        threat_id = "2147835264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 55 ?? 89 45 08 8b 45 ?? 01 45 08 8b 45 08 33 45 ?? 33 d2 33 c1 50 89 45 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 c1 e8 ?? 03 45 ?? 03 f2 33 f0 33 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 89 75 ?? 8b 45 ?? 29 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKU_2147835272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKU!MTB"
        threat_id = "2147835272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 4d eb 8b 45 ec 33 d2 f7 75 dc 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d fb 8b 45 ec 8a 88 ?? ?? ?? ?? 88 4d ea 0f b6 55 fb 8b 45 ec 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 ec 88 8a ?? ?? ?? ?? 0f b6 45}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MRE_2147835334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MRE!MTB"
        threat_id = "2147835334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 24 0f b6 c0 2b cf 83 e1 f8 8a 44 04 48 30 86 ?? ?? ?? ?? 8b c7 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MRE_2147835334_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MRE!MTB"
        threat_id = "2147835334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 c1 e1 04 03 4d ?? c1 e8 ?? 89 55 0c 89 45 ?? 8b 45 ?? 01 45 08 8b 45 08 33 45 ?? 33 d2 33 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 c1 e8 ?? 03 45 ?? 03 f3 33 f0 33 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 89 75 ?? 8b 45 ?? 29 45 ?? 81 45 f4 ?? ?? ?? ?? ff 4d ?? 8b 45 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKV_2147835363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKV!MTB"
        threat_id = "2147835363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 04 11 6b c0 ?? 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKW_2147835383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKW!MTB"
        threat_id = "2147835383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 1c ?? ?? ?? ?? 88 84 0c ?? ?? ?? ?? 8a 44 24 ?? 88 84 1c ?? ?? ?? ?? 0f b6 84 0c ?? ?? ?? ?? 03 44 24 ?? 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKW_2147835383_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKW!MTB"
        threat_id = "2147835383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f8 33 d2 f7 75 e8 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 f8 8a 88 ?? ?? ?? ?? 88 4d fd 0f b6 55 ?? 8b 45 f8 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 f8 88 8a ?? ?? ?? ?? 0f b6 45 fd 8b 4d f8 0f b6 91 ?? ?? ?? ?? 2b d0 8b 45 f8 88}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKX_2147835446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKX!MTB"
        threat_id = "2147835446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 08 0f be 04 0a 8b 4d 0c 03 4d d0 0f be 11 33 c2 88 45 ce 8b 45 0c 03 45 d0 8a 08 88 4d cf 0f be 55 ce 0f be 45 cf 03 d0 8b 4d 0c 03 4d d0 88 11 0f be 55 cf 8b 45 0c 03 45 d0 0f be 08 2b ca 8b 55 0c 03 55 d0 88 0a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKY_2147835455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKY!MTB"
        threat_id = "2147835455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 04 02 6b c0 ?? 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 6b c0 ?? 8b 55 ?? 03 55 ?? 0f be 0a 33 c8 8b 55 ?? 03 55 ?? 88 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ZYZ_2147835495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ZYZ!MTB"
        threat_id = "2147835495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 4d ?? 8d 45 ?? 33 4d ?? 33 d2 33 4d ?? 89 15 ?? ?? ?? ?? 51 50 89 4d ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 8b 45 ?? 01 45 ?? 03 f3 33 75 ?? 8d 45 ?? 33 75 ?? 56 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RAW_2147835577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RAW!MTB"
        threat_id = "2147835577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 7d ?? 89 35 ?? ?? ?? ?? 03 45 ?? 33 c7 31 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPN_2147835585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPN!MTB"
        threat_id = "2147835585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 f6 80 c2 30 30 94 0d 47 ff ff ff 41 83 f9 0d 72 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPO_2147835586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPO!MTB"
        threat_id = "2147835586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 b9 17 00 00 00 f7 f9 6b c0 26 6b c0 38 99 b9 0b 00 00 00 f7 f9 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BH_2147835593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BH!MTB"
        threat_id = "2147835593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 75 e8 0f b6 92 [0-4] 33 ca 88 4d ff 8b 45 f8 8a 88 [0-4] 88 4d fd 0f b6 55 ff 8b 45 f8 0f b6 88 [0-4] 03 ca 8b 55 f8 88 8a [0-4] 8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 f8 0f b6 82 [0-4] 2b c1 8b 4d f8 88 81 [0-4] e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ZLZ_2147835689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ZLZ!MTB"
        threat_id = "2147835689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 cb 33 4d 08 8d 45 ?? 33 4d ?? 51 50 89 4d ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 03 c7 33 45 08 33 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 83 65 fc 00 8b 45 ?? 01 45 ?? 2b 55 ?? ff 4d ?? 89 55 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GLA_2147835708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GLA!MTB"
        threat_id = "2147835708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 55 f0 0f b6 02 33 c1 8b 0d 98 5f 52 00 03 4d f0 88 01 eb 32 00 0f b6 0d ?? ?? ?? ?? 8b 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GLB_2147835709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GLB!MTB"
        threat_id = "2147835709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 c4 0c 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BI_2147835722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BI!MTB"
        threat_id = "2147835722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 f7 75 e0 0f b6 82 [0-4] 33 c8 88 4d fb 8b 45 ec 8a 80 [0-4] 88 45 ea 8a 45 ea 88 45 e8 8b 45 ec 8a 80 [0-4] 88 45 e9 0f b6 45 e9 0f b6 4d fb 03 c1 89 45 dc 8b 45 ec 8a 4d dc 88 88 [0-4] 8b 45 ec 0f b6 80 [0-4] 0f b6 4d e8 2b c1 89 45 d8 8b 45 ec 8a 4d d8 88 88 [0-4] e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MQ_2147835823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MQ!MTB"
        threat_id = "2147835823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 8b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2 ab}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 08 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_MQ_2147835823_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MQ!MTB"
        threat_id = "2147835823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Good hAKJb17 xhVgs27" ascii //weight: 10
        $x_5_2 = {83 c4 04 89 45 ec c7 45 fc 00 00 00 00 8d 4d c0 6a 14 c7 45 c0 00 00 00 00 68 ?? ?? ?? ?? c7 45 d0 00 00 00 00 c7 45 d4 0f 00 00 00 c6 45 c0 00 e8}  //weight: 5, accuracy: Low
        $x_5_3 = {e0 00 02 01 0b 01 0e 20 00 56 07 00 00 06 04 00 00 00 00 00 ba 4a 02}  //weight: 5, accuracy: High
        $x_2_4 = "InitOnceExecuteOnce" ascii //weight: 2
        $x_2_5 = "GetTimeZoneInformation" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTF_2147835880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTF!MTB"
        threat_id = "2147835880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8b c6 f7 75 10 83 c4 0c 8a 82 ?? ?? ?? ?? 30 04 37 46 3b 75 08 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GTG_2147835890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GTG!MTB"
        threat_id = "2147835890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b cb 5b 33 d2 8b c1 f7 f3 02 d3 30 54 0d d0 41 83 f9 0e 72 ee}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NEAF_2147835905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NEAF!MTB"
        threat_id = "2147835905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 c6 02 23 f8 4a f7 d6 81 f3 b2 c6 38 dc 81 ea 8f 8b da 56 23 1d 68 e4 4e 00 31 3d 78 e0 4e 00 81 eb b5 e8 ab 0e 89 1d c2 e4 4e 00 c1 e0 0b 8b 35 75 e3 4e 00 e2 c9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MAC_2147835936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MAC!MTB"
        threat_id = "2147835936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 4d ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 0c 33 ?? fc 33 d2 33 45 ?? 89 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YRF_2147835937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YRF!MTB"
        threat_id = "2147835937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 55 08 0f be 04 0a 8b 4d ?? 03 4d ?? 0f be 11 33 c2 88 45 ?? 8b 45 ?? 03 45 ?? 8a 08 88 4d ?? 0f be 55 ?? 0f be 45 ?? 03 d0 8b 4d ?? 03 4d ?? 88 11 0f be 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKL_2147836070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKL!MTB"
        threat_id = "2147836070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 8b 45 ?? 03 45 ?? 8a 08 88 4d ?? 0f b6 4d ?? 8b 45 ?? 33 d2 f7 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 45 ee 88 45 ?? 0f b6 4d ?? 8b 55 ?? 03 55 ?? 0f b6 02 2b c1 8b 4d ?? 03 4d ?? 88 01 e9 ?? ?? ?? ?? 8b 4d ?? 33 cd e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKA_2147836071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKA!MTB"
        threat_id = "2147836071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 75 ?? 8b 4d ?? 0f be 04 11 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 0c 99 83 e2 ?? 03 c2 c1 f8 ?? 6b c0 ?? 8b 55 ?? 03 55 ?? 0f b6 0a 33 c8 8b 55 ?? 03 55 ?? 88 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BJ_2147836233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BJ!MTB"
        threat_id = "2147836233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 f7 ea 8d 04 0a c1 f8 05 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 03 01 d0 8d 14 c5 00 00 00 00 01 d0 31 c3 89 d9 8b 55 f0 8b 45 0c 01 d0 89 ca 88 10 83 45 f0 01 8b 45 f0 3b 45 10 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_LRT_2147836236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.LRT!MTB"
        threat_id = "2147836236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 75 ?? 8b 4d ?? 0f be 04 11 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 8b 55 ?? 03 55 ?? 0f b6 0a 33 c8 8b 55 ?? 03 55 ?? 88 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPA_2147836241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPA!MTB"
        threat_id = "2147836241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c8 88 4d d2 8b 4d 0c 03 4d d4 8a 11 88 55 d3 0f be 45 d2 0f be 4d d3 03 c1 8b 55 0c 03 55 d4 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GAB_2147836310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GAB!MTB"
        threat_id = "2147836310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 a3 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 c2 80 30 ?? 8d 8d ?? ?? ?? ?? 51 ff d6 01 3d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_QM_2147836328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.QM!MTB"
        threat_id = "2147836328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c1 8b 0d 18 5a 43 00 88 81 20 5a 43 00 8b 15 18 5a 43 00 0f b6 82 20 5a 43 00 89 45 bc a1 4c b8 42 00 0f b6 88 20 5a 43 00 33 4d bc 8b 15 4c b8 42 00 88 8a 20 5a 43 00 a1 4c b8 42 00 0f b6 88 20 5a 43 00 8b 15 18 5a 43 00 0f b6 82 20 5a 43 00 33 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GAD_2147836352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GAD!MTB"
        threat_id = "2147836352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 80 34 2f ?? 83 c4 08 6a 00 6a 00 ff d6 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 04 2f ?? 83 c4 08 6a 00 6a 00 ff d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GAD_2147836352_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GAD!MTB"
        threat_id = "2147836352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 08 88 4d ef 0f b6 4d ef 8b 45 f0 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d fb 8b 45 0c 03 45 f0 8a 08 88 4d ee 0f b6 55 fb 8b 45 0c 03 45 f0 0f b6 08 03 ca 8b 55 0c 03 55 f0 88 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_LSF_2147836363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.LSF!MTB"
        threat_id = "2147836363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 25 ?? ?? ?? ?? ?? c1 e1 ?? 03 cf 33 4d ?? 8d 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GAE_2147836375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GAE!MTB"
        threat_id = "2147836375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {42 89 54 24 1c 8b c1 c1 e8 18 33 c1 69 c8 ?? ?? ?? ?? 69 c7 ?? ?? ?? ?? 33 c8 8b 44 24 2c 8b f9 3b d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GAE_2147836375_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GAE!MTB"
        threat_id = "2147836375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8a 1c 33 8b c6 8b 4c 24 18 f7 75 08 83 c4 0c 8a 82 ?? ?? ?? ?? ba ?? ?? ?? ?? 32 c3 88 44 24 13 02 c3 88 04 31}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BK_2147836405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BK!MTB"
        threat_id = "2147836405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {29 c2 89 d0 ba 58 00 00 00 0f af c2 31 c3 89 d9 8b 55 f0 8b 45 0c 01 d0 89 ca 88 10 83 45 f0 01 8b 45 f0 3b 45 10 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ZMJ_2147836433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ZMJ!MTB"
        threat_id = "2147836433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? ff 75 ?? c1 e0 04 03 c7 33 45 ?? 89 45 ?? 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GAH_2147836440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GAH!MTB"
        threat_id = "2147836440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 e6 89 c8 29 d0 d1 e8 01 c2 89 c8 c1 ea ?? 6b d2 ?? 29 d0 c1 e8 ?? 0f b6 80 ?? ?? ?? ?? f7 d8 c1 e0 04 30 81 ?? ?? ?? ?? 83 c1 01 81 f9 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBA_2147836458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBA!MTB"
        threat_id = "2147836458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 d2 f7 75 14 8b 45 ec c1 ea 02 0f be 04 10 6b c0 ?? b9 ?? ?? ?? ?? 99 f7 f9 6b c0 ?? 6b c0 ?? 6b f0 ?? 8b 45 ?? 8b 4d ?? 0f be 14 08 31 f2 88 14 08 8b 45 ?? 83 c0 ?? 89 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJ_2147836515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJ!MTB"
        threat_id = "2147836515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 5c 50 72 c7 40 ?? 6f 67 72 61 c7 40 ?? 6d 73 5c 53 c7 40 ?? 74 61 72 74 c7 40 ?? 75 70 5c 6b c7 40 ?? 6c 53 65 72 c7 40 ?? 76 69 63 65 c7 40 ?? 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RB_2147836524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RB!MTB"
        threat_id = "2147836524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 f7 ea 89 d0 c1 f8 04 89 ca c1 fa 1f 29 d0 6b d0 22 89 c8 29 d0 89 c2 8b 45 08 01 d0 0f b6 08 8b 55 f4 8b 45 0c 01 d0 0f b6 00 31 c8 88 45 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KGF_2147836531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KGF!MTB"
        threat_id = "2147836531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? ff 75 ?? 8b c3 c1 e0 ?? 03 c7 33 45 ?? 89 45 ?? 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBD_2147836541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBD!MTB"
        threat_id = "2147836541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 0c 3e 8b c6 83 e0 03 88 4c 24 13 53 8a 80 ?? ?? ?? ?? 32 c1 02 c1 88 04 3e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_HG_2147836585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.HG!MTB"
        threat_id = "2147836585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 08 8b 55 f0 8b 45 0c 01 d0 0f b6 00 31 c8 88 45 ef 8b 55 f0 8b 45 0c 01 d0 0f b6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBE_2147836620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBE!MTB"
        threat_id = "2147836620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 2e 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 2e 0f b6 c3 50 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 28 1c 2e 83 c4 0c 46 3b f7 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBG_2147836626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBG!MTB"
        threat_id = "2147836626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 04 13 6b c0 ?? 8b 55 ?? 30 04 0a 8d 41 ?? 31 d2 f7 f7 c1 ea ?? 0f b6 04 13 89 da 6b c0 ?? 8b 7d ?? 30 44 0f ?? 8b 45 ?? 83 c1 ?? 39 4e ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BL_2147836676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BL!MTB"
        threat_id = "2147836676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b cf 73 0e 8b c1 83 e0 03 8a 80 [0-4] 30 04 0e 41 3b ca 72 e9}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBC_2147836715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBC!MTB"
        threat_id = "2147836715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c8 c7 05 ?? ?? ?? ?? 81 00 00 00 81 e1 ?? ?? ?? ?? 79 08 49 81 c9 ?? ?? ?? ?? 41 8a 84 0d ?? ?? ?? ?? 8b 9d ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 30 04 19 eb 06 8b 9d ?? ?? ?? ?? 43 3b 9d ?? ?? ?? ?? 89 9d ?? ?? ?? ?? bb 02 00 00 00 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBH_2147836722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBH!MTB"
        threat_id = "2147836722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 3e 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e 0f b6 c3 50 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 28 1c 3e 83 c4 ?? 46 3b 74 24 ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GP_2147836752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GP!MTB"
        threat_id = "2147836752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 10 8a 14 11 88 55 f3 0f b6 45 f3 8b 4d 08 03 4d dc 0f b6 11 33 d0 8b 45 08 03 45 dc 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBI_2147836803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBI!MTB"
        threat_id = "2147836803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 11 88 55 f3 0f be 45 f3 0f be 4d f3 8b 55 f4 83 e2 ?? 8b 75 08 0f be 14 16 33 ca 03 c1 8b 4d 0c 03 4d f4 88 01 0f be 55 f3 8b 45 0c 03 45 f4 0f be 08 2b ca 8b 55 0c 03 55 f4 88 0a eb aa}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBL_2147836891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBL!MTB"
        threat_id = "2147836891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 3e 8b c6 83 e0 03 ba ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 28 1c 3e 46 59 3b 75 ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BM_2147836897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BM!MTB"
        threat_id = "2147836897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 f0 83 c2 01 89 55 f0 8b 45 f0 3b 05 ?? ?? ?? ?? 73 22 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 f0 0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d f0 88 01 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBF_2147836910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBF!MTB"
        threat_id = "2147836910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {99 33 c1 8b 8d ?? ?? ?? ?? 33 d6 8b b5 ?? ?? ?? ?? 23 c1 23 d6 89 85 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 4f 75 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BN_2147836946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BN!MTB"
        threat_id = "2147836946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f be 14 32 31 d1 01 c8 88 c2 8b 45 0c 8b 4d f0 88 14 08 0f be 75 ef 8b 45 0c 8b 4d f0 0f be 14 08 29 f2 88 14 08 8b 45 f0 83 c0 01 89 45 f0 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBJ_2147836953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBJ!MTB"
        threat_id = "2147836953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 4c 24 14 80 05 ?? ?? ?? ?? 83 2d 8d 6f 24 4f 33 c1 c7 05 ?? ?? ?? ?? 02 00 00 00 89 35 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 66 89 44 24 14 39 35 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBK_2147836954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBK!MTB"
        threat_id = "2147836954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 0d ?? ?? ?? ?? 73 21 0f b6 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 fc 0f b6 08 33 ca 8b 15 ?? ?? ?? ?? 03 55 fc 88 0a eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBM_2147836956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBM!MTB"
        threat_id = "2147836956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af c1 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 99 01 45 a8 11 55 ac 0f b6 4d f2 81 f1 fe 00 00 00 88 4d f8 8d 95}  //weight: 10, accuracy: Low
        $x_10_2 = {66 89 45 d4 8a 8c 35 ?? ?? ?? ?? 80 f1 1b 66 0f b6 d1 66 89 94 75 ?? ?? ?? ?? 46 83 fe 0c 0f 8c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BO_2147836983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BO!MTB"
        threat_id = "2147836983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f8 8b c7 c1 e8 05 c7 05 [0-4] 19 36 6b ff 89 45 0c 8b 45 e4 01 45 0c 83 65 08 00 8b c7 c1 e0 04 03 45 f0 8d 0c 3e 33 c1 33 45 0c 2b d8 8b 45 e8 01 45 08 2b 75 08 ff 4d fc 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BO_2147836983_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BO!MTB"
        threat_id = "2147836983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d1 88 4d ?? 8b 45 ?? 03 45 ?? 8a 08 88 4d ?? 0f b6 55 ?? 8b 45 ?? 03 45 ?? 0f b6 08}  //weight: 1, accuracy: Low
        $x_1_2 = {03 ca 8b 55 ?? 03 55 ?? 88 0a 8a 45 ?? 88 45 ?? 0f b6 4d ?? 8b 55 ?? 03 55 ?? 0f b6 02 2b c1 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MFG_2147836999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MFG!MTB"
        threat_id = "2147836999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 8b c6 c1 e0 ?? 03 45 ?? 03 ce 33 c1 33 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBP_2147837059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBP!MTB"
        threat_id = "2147837059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 31 d2 8b c6 83 c4 04 f7 f1 8a 82 ?? ?? ?? ?? 32 c3 88 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_10_2 = {89 c1 33 d2 8b c6 83 c4 04 f7 f1 8a 82 ?? ?? ?? ?? 32 c3 88 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redline_GBS_2147837193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBS!MTB"
        threat_id = "2147837193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d 0c 03 4d f4 8a 11 88 55 f3 0f be 45 f3 0f be 4d f3 8b 55 f4 83 e2 2f 8b 75 08 0f be 14 16 33 ca 03 c1 8b 4d 0c 03 4d f4 88 01 0f be 55 f3 8b 45 0c 03 45 f4 0f b6 08 2b ca 8b 55 0c 03 55 f4 88 0a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBS_2147837193_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBS!MTB"
        threat_id = "2147837193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 37 46 3b f3 72}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redline_HP_2147837243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.HP!MTB"
        threat_id = "2147837243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d1 83 f1 ?? 83 f1 ?? 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f be 14 08 29 f2 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBT_2147837400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBT!MTB"
        threat_id = "2147837400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 75 dc 8b 5d d4 8b 7d d0 83 e7 03 8a 87 ?? ?? ?? ?? 30 04 33 46 eb}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BP_2147837472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BP!MTB"
        threat_id = "2147837472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 d0 0f b6 00 32 45 ef 89 c3 0f b6 4d ef 8b 55 f0 8b 45 0c 01 d0 8d 14 0b 88 10 8b 55 f0 8b 45 0c 01 d0 0f b6 10 0f b6 5d ef 8b 4d f0 8b 45 0c 01 c8 29 da 88 10 83 45 f0 01 8b 45 f0 3b 45 10 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBW_2147837603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBW!MTB"
        threat_id = "2147837603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c1 83 e1 2e 0f b6 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 8d 48 01 83 e1 2f 0f b6 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 83 c0 02 3d ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPZ_2147837638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPZ!MTB"
        threat_id = "2147837638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 17 33 f6 8b f0 8b d8 33 de}  //weight: 1, accuracy: High
        $x_1_2 = {33 c3 33 c3 33 c3 8b d8 33 f0 33 f0 f6 2f 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPZ_2147837638_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPZ!MTB"
        threat_id = "2147837638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 17 33 db 33 c3 33 d8 80 2f 80 8b f0 33 de 8b c6 80 07 34 33 d8 33 db 33 db f6 2f 47 e2 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPZ_2147837638_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPZ!MTB"
        threat_id = "2147837638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 ff 83 e0 4a 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb 8b 4d 0c 03 4d fc 0f b6 11 2b d0 8b 45 0c 03 45 fc 88 10 eb 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPZ_2147837638_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPZ!MTB"
        threat_id = "2147837638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 04 37 88 45 d3 ba}  //weight: 1, accuracy: Low
        $x_1_2 = {59 0f b6 1c 37 8a c3 02 45 d3 88 04 37 ba}  //weight: 1, accuracy: High
        $x_1_3 = {59 28 1c 37 46 8b 45 c8 eb b1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPZ_2147837638_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPZ!MTB"
        threat_id = "2147837638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 ca 88 4d ff 8b 45 0c 03 45 f8 8a 08 88 4d fd 0f b6 55 ff 8b 45 0c 03 45 f8 0f b6 08 03 ca 8b 55 0c 03 55 f8 88 0a 8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPZ_2147837638_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPZ!MTB"
        threat_id = "2147837638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c4 89 44 24 2c 8b 41 3c 53 8b da 89 4c 24 0c 55 8b 54 08 78 33 ed 8b 44 0a 20 03 d1 89 54 24 18 03 c1 56 57 8b 52 18 89 5c 24 14 89 44 24 10 89 54 24 1c 85 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPZ_2147837638_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPZ!MTB"
        threat_id = "2147837638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 fc 50 6a 40 8b 4d 0c 51 8b 55 08 52 ff 15 ?? ?? ?? 00 33 c0 33 d2 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f0 03 ce 8b 55 0c 03 55 dc 88 0a 0f be 45 db 8b 4d 0c 03 4d dc 0f b6 11 2b d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPZ_2147837638_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPZ!MTB"
        threat_id = "2147837638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.ip.sb" wide //weight: 1
        $x_1_2 = "FileZilla\\recentservers.xml" wide //weight: 1
        $x_1_3 = "Russia" wide //weight: 1
        $x_1_4 = "discord\\Local Storage\\leveldb" wide //weight: 1
        $x_1_5 = "user.config" wide //weight: 1
        $x_1_6 = "Opera GXcookies" wide //weight: 1
        $x_1_7 = "moz_cookies" wide //weight: 1
        $x_1_8 = "NordVpn.exe" wide //weight: 1
        $x_1_9 = "*wallet*" wide //weight: 1
        $x_1_10 = "string.Replace" wide //weight: 1
        $x_1_11 = "File.Write" wide //weight: 1
        $x_1_12 = "Moldova" wide //weight: 1
        $x_1_13 = "Armenia" wide //weight: 1
        $x_1_14 = "shell\\open\\command" wide //weight: 1
        $x_1_15 = "SOFTWARE\\Clients\\StartMenuInternet" wide //weight: 1
        $x_1_16 = "FromBase64CharArray" ascii //weight: 1
        $x_1_17 = "GetBrowsers" ascii //weight: 1
        $x_1_18 = "installedBrowsers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBZ_2147837736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBZ!MTB"
        threat_id = "2147837736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c2 8b 45 08 01 d0 0f b6 00 c1 e0 05 32 45 f3 89 c2 0f b6 45 f3 8d 0c 02 8b 55 f4 8b 45 0c 01 d0 89 ca 88 10 8b 55 f4 8b 45 0c 01 d0 0f b6 00 89 c2 0f b6 45 f3 89 d1 29 c1 8b 55 f4 8b 45 0c 01 d0 89 ca 88 10 83 45 f4 01 8b 45 f4 3b 45}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCA_2147837740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCA!MTB"
        threat_id = "2147837740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 4d d7 8b 45 d8 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d df 8b 45 0c 03 45 d8 8a 08 88 4d d6}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_LL_2147837775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.LL!MTB"
        threat_id = "2147837775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 33 d2 f7 75 ?? 0f b6 92 ?? ?? ?? ?? 33 ca 88 8d ?? ?? ?? ?? 8b 45 ?? 03 85 ?? ?? ?? ?? 8a 08 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 8b 45 ?? 03 85 ?? ?? ?? ?? 0f b6 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCB_2147837784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCB!MTB"
        threat_id = "2147837784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 d8 83 e0 03 8a b8 ?? ?? ?? ?? 32 fb 8b 45 dc 8a 1c 30 a1 ?? ?? ?? ?? 8b 48 04 81 c1 ?? ?? ?? ?? 8b 01 25 ?? ?? ?? ?? 0d ?? ?? ?? ?? 89 01 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 2a fb 8b 45 dc 00 3c 30}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCC_2147837789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCC!MTB"
        threat_id = "2147837789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 f7 75 08 0f b6 92 ?? ?? ?? ?? 33 ca 88 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8a 88 ?? ?? ?? ?? 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 0f b6 88 ?? ?? ?? ?? 03 ca 8b 95 ?? ?? ?? ?? 88 8a ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 88 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCD_2147837797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCD!MTB"
        threat_id = "2147837797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c2 0f b6 45 ca c1 e0 ?? 09 d0 88 45 ca 80 45 ca 0e f6 55 ca 80 45 ca 61 8b 45 f4 30 45 ca f6 5d ca 80 6d ca 3c f6 5d ca 8b 45 f4 00 45 ca f6 55 ca 8b 45 f4 30 45 ca 8b 45 f4 00 45 ca 8d 55 bb 8b 45 f4 01 c2 0f b6 45 ca 88 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCE_2147837851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCE!MTB"
        threat_id = "2147837851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 11 88 55 d3 0f be 45 d3 0f be 4d d3 8b 55 d4 83 e2 2b 8b 75 08 0f be 14 16 33 ca 81 f1 ?? ?? ?? ?? 03 c1 8b 4d 0c 03 4d d4 88 01 0f be 55 d3 8b 45 0c 03 45 d4 0f b6 08 2b ca 8b 55 0c 03 55 d4 88 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCF_2147837952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCF!MTB"
        threat_id = "2147837952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 f7 75 08 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 f8 8a 88 ?? ?? ?? ?? 88 4d fd 0f b6 55 ff 8b 45 f8 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 f8 88 8a ?? ?? ?? ?? 8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 f8 0f b6 82 ?? ?? ?? ?? 2b c1 8b 4d f8 88 81}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCH_2147838016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCH!MTB"
        threat_id = "2147838016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 d8 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ?? 8b 45 ?? 8a 88 ?? ?? ?? ?? 88 4d ?? 0f b6 55 ?? 8b 45 ?? 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 d8 88 8a ?? ?? ?? ?? 8a 45 ?? 88 45 ?? 0f b6 4d ?? 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 2b c1 8b 4d d8 88 81}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCI_2147838017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCI!MTB"
        threat_id = "2147838017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 c0 29 c8 88 45 c3 8b 4d c4 0f b6 45 c3 01 c8 88 45 c3 0f b6 45 c3 83 f0 ff 88 45 c3 8b 4d c4 0f b6 45 c3 31 c8 88 45 c3 8b 4d c4 0f b6 45 c3 01 c8 88 45 c3 8a 4d c3 8b 45 c4 88 4c 05 c9 8b 45 c4 83 c0 01 89 45 c4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBV_2147838028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBV!MTB"
        threat_id = "2147838028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c1 33 d2 b9 00 01 00 00 f7 f1 89 15 ?? ?? ?? ?? a1 60 35 46 00 0f b6 88 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 0d ?? ?? ?? ?? 88 81}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NEAN_2147838032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NEAN!MTB"
        threat_id = "2147838032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {88 55 b3 0f b6 45 b3 33 45 b4 88 45 b3 0f b6 4d b3 03 4d b4 88 4d b3 8b 55 b4 8a 45 b3 88 44 15 dc}  //weight: 10, accuracy: High
        $x_2_2 = "Indecisive leaking" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCJ_2147838069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCJ!MTB"
        threat_id = "2147838069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 be 04 00 00 00 f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ?? 8b 45 ?? 8a 88 ?? ?? ?? ?? 88 4d ?? 0f b6 55 ?? 8b 45 ?? 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 ?? 88 8a ?? ?? ?? ?? 8a 45 ?? 88 45 ?? 0f b6 4d ?? 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 2b c1 8b 4d ?? 88 81}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCG_2147838085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCG!MTB"
        threat_id = "2147838085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 89 55 ec 66 8b 45 e8 8b 15 ?? ?? ?? ?? 0f b7 c8 8d 44 11 01 0f b6 0d ?? ?? ?? ?? 33 c1 89 45 f4 8b 45 c0 8b 4d c4 5f}  //weight: 10, accuracy: Low
        $x_10_2 = {02 c9 b2 8f 2a d1 2a d3 b9 85 00 00 00 66 33 c1 88 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCK_2147838106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCK!MTB"
        threat_id = "2147838106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e0 ?? 03 45 e8 03 ce 33 c1 33 45 08 2b f8 81 3d ?? ?? ?? ?? 93 00 00 00 74 ?? 68 ?? ?? ?? ?? 8d 45 fc 50 e8 ?? ?? ?? ?? ff 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_JJ_2147838164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.JJ!MTB"
        threat_id = "2147838164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 14 32 31 d1 81 f1 ?? ?? ?? ?? 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f b6 14 08 29 f2 88 14 08 8b 45 ?? 83 c0 ?? 89 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCL_2147838165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCL!MTB"
        threat_id = "2147838165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c2 0f b6 45 aa c1 e0 07 09 d0 88 45 aa 80 45 aa 0e f6 55 aa 80 45 aa 61 8b 45 f4 30 45 aa f6 5d aa 80 6d aa 3c f6 5d aa 8b 45 f4 00 45 aa f6 55 aa 8b 45 f4 30 45 aa 8b 45 f4 00 45 aa 8d 55 9b 8b 45 f4 01 c2 0f b6 45 aa 88 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCM_2147838166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCM!MTB"
        threat_id = "2147838166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 08 88 4d fe 0f b6 4d fe 8b 45 f8 33 d2 be 04 00 00 00 f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 0c 03 45 f8 8a 08 88 4d fd 0f b6 55 ff 8b 45 0c 03 45 f8 0f b6 08 03 ca 8b 55 0c 03 55 f8 88 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCN_2147838170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCN!MTB"
        threat_id = "2147838170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 3e 8b c6 83 e0 03 68 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e e8 ?? ?? ?? ?? 28 1c 3e 46 59 3b f5 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MVK_2147838171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MVK!MTB"
        threat_id = "2147838171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ca 88 4d ?? 8b 45 ?? 03 45 ?? 8a 08 88 4d ?? 0f b6 55 ?? 8b 45 ?? 03 45 ?? 0f b6 08 03 ca 8b 55 ?? 03 55 ?? 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RJ_2147838173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RJ!MTB"
        threat_id = "2147838173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 e8 e9 c6 45 e9 29 c6 45 ea 35 c6 45 eb f4 c6 45 ec 73 c6 45 ed f5 c6 45 ee 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RJ_2147838173_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RJ!MTB"
        threat_id = "2147838173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 c4 0f 00 00 00 c7 45 c0 0a 00 00 00 c7 45 b0 71 6a 68 7a c7 45 b4 65 64 7a 75 66 c7 45 b8 64 6e c6 45 ba 00 c7 45 c8 00 00 00 00 c7 45 d8 00 00 00 00 c7 45 dc 0f 00 00 00 c6 45 c8 00 c7 45 f0 03 00 00 00 83 ec 0c 8a 45 e0 88 44 24 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RJ_2147838173_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RJ!MTB"
        threat_id = "2147838173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b c1 88 45 ?? 0f b6 55 ?? 83 f2 ?? 88 55 ?? 0f b6 45 ?? d1 ?? 0f b6 4d ?? c1 e1 ?? 0b c1 88 45 ?? 0f b6 55 ?? f7 da 88 55 ?? 0f b6 45 ?? c1 f8 ?? 0f b6 4d ?? d1 ?? 0b c1 88 45 ?? 0f b6 55 ?? f7 d2 88 55 ?? 0f b6 45 ?? 2d ?? ?? ?? ?? 88 45 ?? 8b 4d ?? 8a 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCP_2147838241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCP!MTB"
        threat_id = "2147838241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 3c 2e 8b c6 83 e0 03 68 ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 2a df 00 1c 2e 46 59 3b f7 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCQ_2147838276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCQ!MTB"
        threat_id = "2147838276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 02 88 45 fe 0f b6 4d fe 8b 45 f8 33 d2 be 04 00 00 00 f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 0c 03 45 f8 8a 08 88 4d fd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TN_2147838314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TN!MTB"
        threat_id = "2147838314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 29 c8 88 45 ?? 8b 4d ?? 0f b6 45 ?? 31 c8 88 45 ?? 0f b6 45 ?? 2d ?? ?? ?? ?? 88 45 ?? 8a 4d ?? 8b 45 ?? 88 4c 05 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f0 4b 88 45 ?? 8b 4d ?? 0f b6 45 ?? 29 c8 88 45 ?? 0f b6 45 ?? 83 f0 ?? 88 45 ?? 8b 4d ?? 0f b6 45 ?? 29 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCR_2147838323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCR!MTB"
        threat_id = "2147838323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 c0 29 c8 88 45 e3 8b 4d e4 0f b6 45 e3 31 c8 88 45 e3 0f b6 45 e3 2d ?? ?? ?? ?? 88 45 e3 8a 4d e3 8b 45 e4 88 4c 05 e9 8b 45 e4 83 c0 ?? 89 45 e4}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MDG_2147838335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MDG!MTB"
        threat_id = "2147838335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KA_2147838367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KA!MTB"
        threat_id = "2147838367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 45 c7 33 45 c8 88 45 c7 0f b6 4d c7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KA_2147838367_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KA!MTB"
        threat_id = "2147838367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KA_2147838367_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KA!MTB"
        threat_id = "2147838367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 81 45 e0 ?? ?? ?? ?? ff 4d ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCT_2147838393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCT!MTB"
        threat_id = "2147838393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 04 10 6b c0 ?? 99 bf ?? ?? ?? ?? f7 ff 6b c0 ?? 33 f0 03 ce 8b 55 0c 03 55 f4 88 0a 0f be 45 f3 8b 4d 0c 03 4d f4 0f b6 11 2b d0 8b 45 0c 03 45 f4 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BU_2147838491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BU!MTB"
        threat_id = "2147838491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f0 8b c6 c1 e0 04 03 45 ec c7 05 [0-4] 19 36 6b ff 89 45 fc 8b c6 c1 e8 05 89 45 0c 8d 45 0c 50 e8 [0-4] 8d 04 33 50 8d 45 fc 50 e8 [0-4] 8b 45 fc 33 45 0c 81 c3 47 86 c8 61 2b f8 ff 4d f8 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCS_2147838511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCS!MTB"
        threat_id = "2147838511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f bf 4c 24 4e 31 c8 66 89 84 24 ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 0f b6 00 0f b6 8c 24 ?? ?? ?? ?? d3 f8 88 c1 8b 84 24 ?? ?? ?? ?? 88 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NM_2147838675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NM!MTB"
        threat_id = "2147838675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 2b 5d ?? 8d 45 ?? 89 5d ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCX_2147838679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCX!MTB"
        threat_id = "2147838679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 c2 d1 d0 ca 80 c2 ad c0 c2 05 80 c2 5e 80 f2 7b 80 c2 3b 80 f2 44 00 ca 88 c5 30 d5 80 c5 67 88 6c 04 30 83 f8 2d 74}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCX_2147838679_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCX!MTB"
        threat_id = "2147838679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 4d bf 8b 45 c0 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d c7 8b 45 c0 8a 88 ?? ?? ?? ?? 88 4d be 0f b6 55 c7 8b 45 c0 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 c0 88 8a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GCZ_2147838697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GCZ!MTB"
        threat_id = "2147838697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c1 33 d2 b9 00 01 00 00 f7 f1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f b6 88 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 0d ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8b 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ALX_2147838790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ALX!MTB"
        threat_id = "2147838790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 7c 31 08 83 c5 ?? c9 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 c1 e8 ?? 89 45 ?? 8d 45 ?? 50 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 04 33 33 45 ?? 81 c3 ?? ?? ?? ?? 31 45 ?? 2b 7d ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDB_2147838804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDB!MTB"
        threat_id = "2147838804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 04 10 6b c0 ?? be ?? ?? ?? ?? 99 f7 fe 89 c2 8b 45 ?? 6b d2 ?? 31 d1 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f b6 14 08 29 f2 88 14 08 8b 45 ?? 83 c0 ?? 89 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDC_2147838810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDC!MTB"
        threat_id = "2147838810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 4d d7 8b 45 d8 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d df 8b 45 d8 8a 88 ?? ?? ?? ?? 88 4d d6 0f b6 55 df 8b 45 d8 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 d8 88 8a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_EXP_2147838862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.EXP!MTB"
        threat_id = "2147838862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 08 83 c5 70 c9 c2 08 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 8d 45 0c 50 e8 a8 f8 ff ff 8b 45 0c 33 45 fc 81 c3 47 86 c8 61 2b f8 ff 4d f8 0f 85 67 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RA_2147838876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RA!MTB"
        threat_id = "2147838876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 8b d1 83 c0 21 b9 60 01 00 00 42 e2 fd 03 c2 6a 00 50 c3 33 c0 5f 5e 8b 4d fc 33 cd e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BV_2147838940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BV!MTB"
        threat_id = "2147838940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 f7 fe 89 c2 8b 45 f0 6b d2 ?? 31 d1 01 c8 88 c2 8b 45 0c 8b 4d f8 88 14 08 0f be 75 f7 8b 45 0c 8b 4d f8 0f be 14 08 29 f2 88 14 08 8b 45 f8 83 c0 01 89 45 f8 e9}  //weight: 2, accuracy: Low
        $x_2_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DJST_2147838951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DJST!MTB"
        threat_id = "2147838951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8d 45 08 50 e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 68 ?? ?? ?? ?? 2b f8 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {31 08 83 c5 70 c9 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDE_2147838957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDE!MTB"
        threat_id = "2147838957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 ?? 51 51 f2 0f 11 04 24 8a 98 ?? ?? ?? ?? 32 1c 2e e8 ?? ?? ?? ?? 83 c4 08 88 1c 2e 46 dd d8 3b f7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MLC_2147839021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MLC!MTB"
        threat_id = "2147839021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 2b 5d ?? ff 4d ?? 89 5d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDI_2147839051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDI!MTB"
        threat_id = "2147839051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 04 10 6b c0 ?? 6b c0 ?? be ?? ?? ?? ?? 99 f7 fe 89 c2 8b 45 ?? 31 d1 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f b6 14 08 29 f2 88 14 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDJ_2147839074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDJ!MTB"
        threat_id = "2147839074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 59 8a 80 ?? ?? ?? ?? 32 c3 88 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AVX_2147839105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AVX!MTB"
        threat_id = "2147839105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 50 8d 45 ?? 50 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 03 f9 ff ff 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 2b f8 89 45 ?? 8b c7 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 0d ?? ?? ?? ?? ?? 8b c7}  //weight: 1, accuracy: Low
        $x_1_2 = {31 08 83 c5 70 c9 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ZMW_2147839149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ZMW!MTB"
        threat_id = "2147839149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 10 6b c0 ?? be ?? ?? ?? ?? 99 f7 fe 89 c2 8b 45 ?? 6b d2 ?? 31 d1 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TZX_2147839150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TZX!MTB"
        threat_id = "2147839150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 2e ?? 83 f0 ?? 81 c2 ?? ?? ?? ?? 03 c7 c1 e2 ?? 8a 04 02 88 44 2e ?? 8b c1 83 f8 ?? 7c ?? eb ?? 8d 9b ?? ?? ?? ?? 0f b6 14 30 0f b6 4c 30 ?? 81 c2 ?? ?? ?? ?? c1 e2 ?? 03 cf 8a 0c 0a 88 0c 30 48 83 f8 ?? 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "zasfafsa.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SMG_2147839186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SMG!MTB"
        threat_id = "2147839186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 89 1d ?? ?? ?? ?? 31 45 ?? 8b 45 ?? 29 45 ?? 81 45 ?? ?? ?? ?? ?? ff 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDL_2147839205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDL!MTB"
        threat_id = "2147839205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 0d ?? ?? ?? ?? ff 8b c7 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 03 c7}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 4c 24 04 51 66 00 c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WWA_2147839207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WWA!MTB"
        threat_id = "2147839207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 51 8d 45 ?? 50 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 2b f8 89 45 ?? 8b c7}  //weight: 1, accuracy: Low
        $x_1_2 = {31 08 83 c5 70 c9 33 00 b8 ?? ?? ?? ?? f7 65 ?? 8b 45 ?? 81 6d ?? ?? ?? ?? ?? 81 6d ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 81 6d ?? ?? ?? ?? ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_QPS_2147839242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.QPS!MTB"
        threat_id = "2147839242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 c7 05 c4 1d b9 02 fc 03 cf ff e8 f7 f8 ff ff 8b 45 0c 33 45 08 83 25 c4 1d b9 02 00 2b d8 89 45 0c 8b c3 c1 e0 04}  //weight: 1, accuracy: High
        $x_1_2 = {31 08 83 c5 70 c9 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPC_2147839254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPC!MTB"
        threat_id = "2147839254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 83 e0 03 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? 00 00 50 e8 ?? ?? 00 00 88 9e ?? ?? ?? ?? 46 59 81 fe ?? ?? ?? ?? 72 d4 33 f6 8b c6 83 e0 03 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? 00 00 50 e8 ?? ?? 00 00 88 9e ?? ?? ?? ?? 46 59 81 fe ?? ?? ?? ?? 72 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKJ_2147839330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKJ!MTB"
        threat_id = "2147839330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 89 1d ?? ?? ?? ?? 31 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDO_2147839379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDO!MTB"
        threat_id = "2147839379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e0 03 b9 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 86 ?? ?? ?? ?? 88 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 04 8b 4c 39 30 8b 49 04 89 8d ?? ?? ?? ?? 8b 11}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDP_2147839397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDP!MTB"
        threat_id = "2147839397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 04 0f b6 86 ?? ?? ?? ?? 8d 0c 03 88 8e ?? ?? ?? ?? 2a c8 88 8e ?? ?? ?? ?? 46 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDQ_2147839398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDQ!MTB"
        threat_id = "2147839398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f3 8b c6 ba ?? ?? ?? ?? 83 e0 03 b9 ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 88 9e ?? ?? ?? ?? 46 59 81 fe ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_FUI_2147839451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.FUI!MTB"
        threat_id = "2147839451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 1d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RAX_2147839568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RAX!MTB"
        threat_id = "2147839568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 ?? 03 45 ?? 68 ?? ?? ?? ?? 33 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 31 45 ?? 2b 75 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDT_2147839587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDT!MTB"
        threat_id = "2147839587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e0 03 b9 ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 08 8b 49 04 8b 4c 01 30 8b 49 04 89 8d ?? ?? ?? ?? 8b 11}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDT_2147839587_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDT!MTB"
        threat_id = "2147839587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ea 6a 0e 07 c7 45 ?? be 0f d6 65 c7 45 ?? fe 8c 7d 37 c7 45 ?? ee b1 e9 23 c7 45 ?? e1 02 5b 54 c7 45 ?? 29 9f b2 1f c7 45 ?? 81 1a 44 62 c7 45 ?? 8f 1e cb 6e c7 45 ?? cc af 7a 55 c7 45 ?? 53 72 3b 0b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BW_2147839620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BW!MTB"
        threat_id = "2147839620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 84 3c 10 01 00 00 88 84 34 10 01 00 00 88 8c 3c 10 01 00 00 0f b6 84 34 10 01 00 00 03 c2 0f b6 c0 0f b6 84 04 10 01 00 00 30 83 [0-4] 43 81 fb [0-4] 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SAC_2147839681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SAC!MTB"
        threat_id = "2147839681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 1d ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DGX_2147839852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DGX!MTB"
        threat_id = "2147839852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 03 45 ec 8d 0c 3b 33 c1 31 45 0c 2b 75 0c 81 c3 47 86 c8 61 ff 4d f8 c7 05 48 87 ba 02 19 36 6b ff 0f 85 54 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEA_2147840046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEA!MTB"
        threat_id = "2147840046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 f6 8b c6 ba ?? ?? ?? ?? 83 e0 03 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 04 8b 4c 39 30 8b 49 04 89 4c 24 14}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEB_2147840089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEB!MTB"
        threat_id = "2147840089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e0 03 8a 98 ?? ?? ?? ?? 32 1c 2e e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 ?? 8b 4c 39 ?? 8b 49 ?? 89 4c 24 ?? 8b 11 ff 52}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEC_2147840102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEC!MTB"
        threat_id = "2147840102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 29 d0 89 c2 8b 45 ?? 01 d0 0f b6 00 83 e0 ?? 31 d8 88 45 ?? 0f b6 45 ?? 8d 0c 00 8b 55 ?? 8b 45 ?? 01 d0 89 ca 88 10 8b 55 ?? 8b 45 ?? 01 d0 0f b6 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GDW_2147840108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GDW!MTB"
        threat_id = "2147840108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32" ascii //weight: 1
        $x_1_2 = "rundll32.exe %s,InstallHinfSection %s" ascii //weight: 1
        $x_1_3 = "DecryptFile" ascii //weight: 1
        $x_1_4 = "cmd /c \"temp.bat" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_6 = "wextract_cleanup%d" ascii //weight: 1
        $x_1_7 = "Command.com /c %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GED_2147840205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GED!MTB"
        threat_id = "2147840205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e0 03 8a 98 ?? ?? ?? ?? 32 1c 0e e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 ?? 8b 4c 39 ?? 8b 49 ?? 89 4c 24 ?? 8b 11 ff 52}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEF_2147840340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEF!MTB"
        threat_id = "2147840340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 3c 3e 8b c6 83 e0 03 ba ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 ?? 8b 4c 39 ?? 8b 49 ?? 89 4c 24}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEG_2147840390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEG!MTB"
        threat_id = "2147840390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 ?? 8a 98 ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 ?? 8b 4c 39 ?? 8b 49 ?? 89 4c 24 ?? 8b 11}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ITI_2147840402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ITI!MTB"
        threat_id = "2147840402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 08 83 c5 ?? 30 00 8b 45 ?? 81 6d ?? ?? ?? ?? ?? 81 6d ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 81 6d ?? ?? ?? ?? ?? 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c8 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 51 8d 45 ?? 50 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 2b f0 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEH_2147840449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEH!MTB"
        threat_id = "2147840449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 3c 3e 8b c6 83 e0 ?? 8a 98 ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 2a df 00 1c 3e 46 59 3b f5 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CI_2147840477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CI!MTB"
        threat_id = "2147840477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c6 ba 98 c7 44 00 83 e0 ?? 8b cf 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? 46 59 81 fe ?? ?? ?? ?? 72}  //weight: 5, accuracy: Low
        $x_5_2 = {83 e9 06 8b c2 d3 e8 4d 24 ?? 0c ?? 88 03 ff 06 8b 1e 85 ed 7f}  //weight: 5, accuracy: Low
        $x_1_3 = "VirtualProtectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YUQ_2147840572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YUQ!MTB"
        threat_id = "2147840572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 08 83 c5 18 00 81 45 ?? ?? ?? ?? ?? 81 6d ?? ?? ?? ?? ?? 8b 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 03 fe 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 6a ?? ff 15 fc 10 40 00 83 0d ?? ?? ?? ?? ?? 31 7d ?? 8b c6 c1 e8 ?? 03 45 ?? c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEK_2147840656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEK!MTB"
        threat_id = "2147840656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 02 88 45 fe 0f b6 4d fe 8b 45 f8 33 d2 f7 75 ?? 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 08 03 45 f8 8a 08 88 4d}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEL_2147840771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEL!MTB"
        threat_id = "2147840771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 2e ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b c6 ba ?? ?? ?? ?? 83 e0 03 59 8a b8 ?? ?? ?? ?? 32 fb 8a 1c 2e e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 2a fb 00 3c 2e 46 59 3b f7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEM_2147840772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEM!MTB"
        threat_id = "2147840772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 d2 f7 75 14 8b 45 f4 0f be 04 10 6b c0 ?? b9 ?? ?? ?? ?? 99 f7 f9 6b c0 1d 6b f0 1b 8b 45 0c 8b 4d f8 0f b6 14 08 31 f2 88 14 08 8b 45 f8 83 c0 01 89 45 f8 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AL_2147840959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AL!MTB"
        threat_id = "2147840959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 89 70 04 5e 5d 89 10 5b}  //weight: 1, accuracy: High
        $x_1_2 = {51 c7 04 24 00 00 00 00 8b 44 24 0c 89 04 24 8b 44 24 08 31 04 24 8b 04 24 89 01 59 c2 08 00}  //weight: 1, accuracy: High
        $x_1_3 = "acina49 vu.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEO_2147840966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEO!MTB"
        threat_id = "2147840966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 3c 2e 8b c6 83 e0 03 8a 98 ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 2a df 00 1c 2e 46 59 3b f7 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEP_2147840967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEP!MTB"
        threat_id = "2147840967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 04 10 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 6b c0 ?? 8b 55 ?? 03 55 ?? 0f b6 0a 33 c8 8b 55 ?? 03 55 ?? 88 0a}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEN_2147841021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEN!MTB"
        threat_id = "2147841021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d9 03 f9 81 a4 94 ?? ?? ?? ?? 8d 65 01 27 c1 c0 17 89 bc 14 ?? ?? ?? ?? c3 e8 ?? ?? ?? ?? c7 44 24 ?? 14 a6 2e c9 8b 44 25 ?? c7 04 24}  //weight: 10, accuracy: Low
        $x_1_2 = "P@.eh_fram" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GER_2147841028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GER!MTB"
        threat_id = "2147841028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 3c 3e 8b c6 83 e0 03 8a 98 ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 00 1c 3e 59 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 28 3c 3e 46 59 3b f5 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_2147841029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MTQ!MTB"
        threat_id = "2147841029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTQ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 0a 8b 45 ?? 99 be ?? ?? ?? ?? f7 fe 8b 45 ?? 0f be 14 10 6b d2 ?? 83 e2 ?? 83 e2 ?? 33 ca 88 4d ?? 0f be 45 ?? 0f be 4d ?? 03 c1 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GES_2147841116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GES!MTB"
        threat_id = "2147841116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c3 83 e0 03 8a 80 ?? ?? ?? ?? 32 04 1f 0f b6 0c 1f 8d 14 08 88 14 1f 2a d1 88 14 1f 43}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GET_2147841139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GET!MTB"
        threat_id = "2147841139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f3 8d 55 ?? 29 c1 c0 c1 ?? 29 cb 89 d9 89 fb 31 c1 f7 d9 c0 c9 ?? 29 cb 89 d9 31 c1 29 c1 31 c1 83 c1 ?? c0 c9 ?? 83 e9 ?? 88 4c 05 ?? 40 83 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEQ_2147841158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEQ!MTB"
        threat_id = "2147841158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 05 ?? ?? ?? ?? 03 d1 81 e2 ?? ?? ?? ?? 79 ?? 4a 81 ca ?? ?? ?? ?? 42 89 95 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 0f b6 84 15 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 0f b6 91 ?? ?? ?? ?? 33 d0 8b 85 ?? ?? ?? ?? 88}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 55 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CGM_2147841191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CGM!MTB"
        threat_id = "2147841191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 75 ?? 8b 45 ?? 0f be 04 10 6b c0 ?? 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 99 b9 ?? ?? ?? ?? f7 f9 8b 55 ?? 03 55 ?? 0f b6 0a 33 c8 8b 55 ?? 03 55 ?? 88 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MHV_2147841342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MHV!MTB"
        threat_id = "2147841342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 45 ?? 03 fe 31 7d ?? 50 89 45 ?? 8d 45 ?? 50 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 68 ?? ?? ?? ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ?? 8b 45 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_QQZ_2147841423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.QQZ!MTB"
        threat_id = "2147841423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4c 24 ?? 31 4c 24 ?? 03 c3 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75 ?? 55 55 55 55 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WZY_2147841433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WZY!MTB"
        threat_id = "2147841433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 45 ?? 03 fe 33 f8 31 7d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 29 45 ?? 68 ?? ?? ?? ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ?? 8b 45 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEW_2147841484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEW!MTB"
        threat_id = "2147841484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 04 10 6b c0 ?? 99 be ?? ?? ?? ?? f7 fe 83 e0 ?? 33 c8 88 4d ?? 0f be 4d ?? 0f be 55 ?? 03 ca 8b 45 ?? 03 45 ?? 88 08 0f be 4d ?? 8b 55 ?? 03 55 ?? 0f be 02 2b c1 8b 4d 0c 03 4d ?? 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MDZ_2147841569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MDZ!MTB"
        threat_id = "2147841569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 0a 8b 45 ?? 99 be ?? ?? ?? ?? f7 fe 8b 45 ?? 0f be 14 10 6b d2 ?? 83 e2 ?? 33 ca 88 4d ?? 0f be 45 ?? 0f be 4d ?? 03 c1 8b 55 ?? 03 55 ?? 88 02 0f be 45 ?? 8b 4d ?? 03 4d ?? 0f be 11 2b d0 8b 45 ?? 03 45 ?? 88 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEX_2147841575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEX!MTB"
        threat_id = "2147841575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 83 e1 03 8a 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 40 3d 00 1c 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 39 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GEY_2147841581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GEY!MTB"
        threat_id = "2147841581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e0 03 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 04 8b 4c 39 30 8b 49 04 89 4c 24 14 8b 11}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFC_2147841621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFC!MTB"
        threat_id = "2147841621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 14 30 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 4d dc 88 04 31}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFD_2147841636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFD!MTB"
        threat_id = "2147841636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 8b f2 8b 7d ?? 8b 5d ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0b fa 0b d8 f7 d7 f7 d3 0f bf 05 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 99 33 f8 33 da 2b cf 1b f3 89 4d ?? 89 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MYV_2147841669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MYV!MTB"
        threat_id = "2147841669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 03 c5 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75 ?? 57 57 57 57 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFF_2147841695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFF!MTB"
        threat_id = "2147841695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 44 35 10 88 44 1d 10 88 4c 35 10 0f b6 44 1d 10 03 c2 0f b6 c0 8a 44 05 10 32 87 ?? ?? ?? ?? 88 87 ?? ?? ?? ?? 47}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFA_2147841813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFA!MTB"
        threat_id = "2147841813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 e0 8b 4d e0 2b 4d c4 8b 45 c4 33 45 94 0f af c8 8b 45 e0 0f af 45 e0 0f af 45 c4 69 c0 06 03 00 00 3b c1 74 34 8a 45 dd 88 45 cd}  //weight: 10, accuracy: High
        $x_10_2 = {66 89 44 24 10 8a 4c 24 0b 8a 44 24 0c 33 c8 8a 44 24 0b 2b c1 88 44 24 0b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFH_2147841832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFH!MTB"
        threat_id = "2147841832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 04 33 0f b6 0c 33 8d 14 08 88 14 33 2a d1 88 14 33 46}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFJ_2147841842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFJ!MTB"
        threat_id = "2147841842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 1d ?? ?? ?? ?? 03 c2 0f b6 c0 8a 84 05 ?? ?? ?? ?? 32 87 ?? ?? ?? ?? 88 87 ?? ?? ?? ?? 47 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BX_2147841868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BX!MTB"
        threat_id = "2147841868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 ca 88 4d fb 0f be 45 fb 0f be 4d fb 03 c1 8b 55 0c 03 55 fc 88 02 0f be 45 fb 8b 4d 0c 03 4d fc 0f be 11 2b d0 8b 45 0c 03 45 fc 88 10 eb}  //weight: 2, accuracy: High
        $x_2_2 = {f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CFD_2147841875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CFD!MTB"
        threat_id = "2147841875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 75 14 8b 45 08 0f be 04 10 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFK_2147841922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFK!MTB"
        threat_id = "2147841922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 98 ?? ?? ?? ?? 32 1c 37 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 0f b6 04 37 8d 0c 03 88 0c 37 2a c8 88 0c 37 46 8b 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BY_2147842111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BY!MTB"
        threat_id = "2147842111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 14 10 6b d2 2e 81 e2 [0-4] 33 ca 88 4d d7 0f be 45 d7 0f be 4d d7 03 c1 8b 55 0c 03 55 d8 88 02 0f be 45 d7 8b 4d 0c 03 4d d8 0f be 11 2b d0 8b 45 0c 03 45 d8 88 10 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {f7 f9 6b c0 19 6b c0 11 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFM_2147842172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFM!MTB"
        threat_id = "2147842172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 44 3d 10 88 44 35 10 88 4c 3d 10 0f b6 44 35 10 03 c2 0f b6 c0 0f b6 44 05 10 30 83 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFN_2147842173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFN!MTB"
        threat_id = "2147842173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 03 0d ?? ?? ?? ?? 0f bf 05 ?? ?? ?? ?? 99 2b c1 66 a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 f2 1c 88 55 e6 a1 ?? ?? ?? ?? 03 45 94 66 89 45 d8 8b 8d ?? ?? ?? ?? 83 e9 ?? 89 8d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFN_2147842173_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFN!MTB"
        threat_id = "2147842173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 0a 8b 45 ?? 99 be ?? ?? ?? ?? f7 fe 8b 45 ?? 0f be 14 10 6b d2 28 81 e2 ?? ?? ?? ?? 33 ca 88 4d ?? 0f be 45 ?? 0f be 4d ?? 03 c1 8b 55 ?? 03 55 ?? 88 02 0f be 45 ?? 8b 4d ?? 03 4d ?? 0f be 11 2b d0 8b 45 ?? 03 45 ?? 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFI_2147842190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFI!MTB"
        threat_id = "2147842190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 ca f7 d1 6b c9 ?? 0f b6 05 ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 8d 8c 08 ?? ?? ?? ?? 88 4d fb c6 05 ?? ?? ?? ?? ?? 0f b7 55 ec f7 da 1b d2 83 c2 01 0f bf 45 d8 2b d0 f7 da 1b d2 83 c2 ?? 66 89 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFO_2147842210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFO!MTB"
        threat_id = "2147842210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 0c 33 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 c1 88 45 d3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFO_2147842210_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFO!MTB"
        threat_id = "2147842210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 0c 30 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 c1 88 45 cf}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KAK_2147842262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KAK!MTB"
        threat_id = "2147842262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d3 89 54 24 ?? e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75 ?? 6a ?? 6a ?? 6a ?? ff 15 ?? ?? ?? ?? 8b 44 24 ?? 33 44 24 ?? 8b c8 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {51 c7 04 24 ?? ?? ?? ?? 8b 44 24 ?? 01 04 24 8b 04 24 31 44 24 ?? 8b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NEAY_2147842281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NEAY!MTB"
        threat_id = "2147842281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d d0 0f b6 04 31 8d 0c 03 8b 5d d0 88 0c 33 2a c8 88 0c 33 46 eb bf}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MOO_2147842521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MOO!MTB"
        threat_id = "2147842521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ff 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 6b c0 ?? 99 bf ?? ?? ?? ?? f7 ff 99 bf ?? ?? ?? ?? f7 ff 83 e0 ?? 33 f0 03 ce 8b 55 ?? 03 55 ?? 88 0a 0f be 45 ?? 8b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFP_2147842533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFP!MTB"
        threat_id = "2147842533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 04 37 88 45 d3 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 0f b6 1c 37}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 04 33 88 45 d3 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 51 8b c8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_RPW_2147842547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPW!MTB"
        threat_id = "2147842547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d 08 f6 17 80 07 9f fe 07 47 e2 f6 5f 5e 5b 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RPW_2147842547_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RPW!MTB"
        threat_id = "2147842547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf 1d 00 00 00 f7 ff 83 e0 4a 33 f0 03 ce 8b 55 0c 03 55 f8 88 0a 0f be 45 f7 8b 4d 0c 03 4d f8 0f b6 11 2b d0 8b 45 0c 03 45 f8 88 10 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NEAZ_2147842642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NEAZ!MTB"
        threat_id = "2147842642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 c4 04 8b 4d c8 0f b6 1c 31 8a c3 02 45 cf 88 04 31}  //weight: 5, accuracy: High
        $x_5_2 = {83 c4 04 8b 45 c8 28 1c 30 46 eb a4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MVM_2147842650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MVM!MTB"
        threat_id = "2147842650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ff 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 6b c0 ?? 6b c0 ?? 99 bf ?? ?? ?? ?? f7 ff 83 e0 ?? 33 f0 03 ce 8b 55 ?? 03 55 ?? 88 0a 0f be 45 ?? 8b 4d ?? 03 4d ?? 0f be 11 2b d0 8b 45 ?? 03 45 ?? 88 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAA_2147842715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAA!MTB"
        threat_id = "2147842715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f be 04 10 69 c0 [0-4] c1 e0 05 6b c0 ?? 99 bf [0-4] f7 ff 83 e0 ?? 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb 8b 4d 0c 03 4d fc 0f b6 11 2b d0 8b 45 0c 03 45 fc 88 10 eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFS_2147842832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFS!MTB"
        threat_id = "2147842832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 28 1c 37 46 8b 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFT_2147842833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFT!MTB"
        threat_id = "2147842833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 0f 0f b6 06 03 c8 0f b6 c1 8a 84 05 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 8d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAB_2147842863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAB!MTB"
        threat_id = "2147842863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f be 04 10 69 c0 [0-4] 6b c0 ?? 99 bf [0-4] f7 ff 6b c0 ?? 83 e0 ?? 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb 8b 4d 0c 03 4d fc 0f b6 11 2b d0 8b 45 0c 03 45 fc 88 10 eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CDP_2147842949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CDP!MTB"
        threat_id = "2147842949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 0c 03 55 fc 8a 02 88 45 fb 0f be 4d fb 0f be 75 fb 8b 45 fc 99 bf ?? ?? ?? ?? f7 ff 8b 45 08 0f be 04 10 69 c0 ?? ?? ?? ?? 6b c0 ?? 6b c0 ?? 99 bf ?? ?? ?? ?? f7 ff 83 e0 ?? 33 f0 03 ce}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CPH_2147842950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CPH!MTB"
        threat_id = "2147842950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 18 8b d6 d3 ea 03 54 24 30 89 54 24 14 8b 44 24 20 31 44 24 10 8b 44 24 10 33 44 24 14 2b f8 89 44 24 10 8d 44 24 24 89 7c 24 28 e8 ?? ?? ?? ?? 83 eb 01 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAC_2147843037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAC!MTB"
        threat_id = "2147843037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f be 04 10 69 c0 [0-4] 6b c0 ?? 99 bf [0-4] f7 ff 25 [0-4] 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb 8b 4d 0c 03 4d fc 0f b6 11 2b d0 8b 45 0c 03 45 fc 88 10 eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YHI_2147843050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YHI!MTB"
        threat_id = "2147843050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 e9 ?? 03 4c 24 ?? 89 4c 24 ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 6a ?? 6a ?? 8d 54 24 ?? 52 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 33 4c 24 ?? 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 83 6c 24 ?? ?? 8b 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFU_2147843073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFU!MTB"
        threat_id = "2147843073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 14 30 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 4d cc 88 04 31}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NEBB_2147843108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NEBB!MTB"
        threat_id = "2147843108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {76 1f 8b 0d ?? ?? ?? 00 8a 94 01 1b 1b 01 00 8b 0d ?? ?? ?? 00 88 14 01 40 3b 05 ?? ?? ?? 00 72 e1}  //weight: 10, accuracy: Low
        $x_5_2 = {89 44 24 20 8b 4c 24 18 8b d6 d3 ea 03 54 24 30 89 54 24 14 8b 44 24 20 31 44 24 10 8b 44 24 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFV_2147843182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFV!MTB"
        threat_id = "2147843182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e8 05 89 44 24 ?? 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFW_2147843242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFW!MTB"
        threat_id = "2147843242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 4d 80 0f b6 55 d7 f7 d2 8b 45 b8 33 c2 03 45 ac f7 d8 1b c0 83 c0 ?? 66 a3 ?? ?? ?? ?? 0f be 45 83 99 52 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFW_2147843242_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFW!MTB"
        threat_id = "2147843242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 ff 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 99 bf ?? ?? ?? ?? f7 ff 25 ?? ?? ?? ?? 33 f0 03 ce 8b 55 ?? 03 55 ?? 88 0a 0f be 45 ?? 8b 4d ?? 03 4d ?? 0f b6 11 2b d0 8b 45 ?? 03 45 ?? 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WOA_2147843306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WOA!MTB"
        threat_id = "2147843306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ff 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 99 bf ?? ?? ?? ?? f7 ff 25 ?? ?? ?? ?? 83 e0 ?? 33 f0 03 ce 8b 55 ?? 03 55 ?? 88 0a 0f be 45 ?? 8b 4d ?? 03 4d ?? 0f b6 11 2b d0 8b 45 ?? 03 45 ?? 88 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CXL_2147843331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CXL!MTB"
        threat_id = "2147843331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c6 c1 e8 ?? 03 c5 89 44 24 14 8b 44 24 1c 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 28 89 4c 24 10 e8 ?? ?? ?? ?? 8d 44 24 24 e8 ?? ?? ?? ?? 83 ef 01 8b 4c 24 28 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFX_2147843362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFX!MTB"
        threat_id = "2147843362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 45 dc 99 8b 4d a8 8b 75 ac 33 c8 33 f2 89 8d ?? ?? ?? ?? 89 b5 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 0b 95 ?? ?? ?? ?? 75 0e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFY_2147843398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFY!MTB"
        threat_id = "2147843398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 34 ?? ?? ?? ?? 03 c2 0f b6 c0 8a 84 04 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GFZ_2147843490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GFZ!MTB"
        threat_id = "2147843490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 2e 8b c6 83 e0 03 ba ?? ?? ?? ?? 8a 80 a0 ?? ?? ?? ?? c3 02 c3 88 04 2e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RWW_2147843533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RWW!MTB"
        threat_id = "2147843533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ff 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 6b c0 ?? 99 bf ?? ?? ?? ?? f7 ff 25 ?? ?? ?? ?? 33 f0 03 ce 8b 55 ?? 03 55 ?? 88 0a 0f be 45 ?? 8b 4d ?? 03 4d ?? 0f b6 11 2b d0 8b 45 ?? 03 45 ?? 88 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHA_2147843551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHA!MTB"
        threat_id = "2147843551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 0e 8b c6 83 e0 03 ba ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 0e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RWO_2147843601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RWO!MTB"
        threat_id = "2147843601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 c5 03 d6 31 54 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 4b 8b 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAD_2147843654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAD!MTB"
        threat_id = "2147843654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {f7 ff 8b 45 08 0f be 04 10 69 c0 [0-4] 99 bf [0-4] f7 ff 6b c0 ?? 6b c0 ?? 83 e0 13 ?? f0 03 ce 8b 55 0c 03 55 dc 88 0a 0f be 45 db 8b 4d 0c 03 4d dc 0f b6 11 2b d0 8b 45 0c 03 45 dc 88 10 eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHB_2147843693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHB!MTB"
        threat_id = "2147843693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 2e 8b c6 83 e0 03 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04}  //weight: 10, accuracy: Low
        $x_10_2 = {8a 1c 2e 8b c6 83 e0 03 ba ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 2e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_GHC_2147843694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHC!MTB"
        threat_id = "2147843694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 0c 33 0f b6 1c 33 8d 04 19 8b 4d b4 88 04 31}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHD_2147843707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHD!MTB"
        threat_id = "2147843707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 3e 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PZC_2147843775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PZC!MTB"
        threat_id = "2147843775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 28 01 44 24 14 8b 44 24 14 33 c3 33 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24 10 8b 44 24 2c 01 44 24 10 8b d6 c1 ea 05 03 d5 03 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PZD_2147843776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PZD!MTB"
        threat_id = "2147843776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 7c 24 24 e8 ?? ?? ?? ?? 01 6c 24 14 89 74 24 18 8b 44 24 20 01 44 24 18 8b 44 24 24 ?? 01 44 24 18 8b 44 24 18 89 44 24 1c 8b 54 24 1c 31 54 24 14 8b f7 c1 ee 05 03 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RWZ_2147843824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RWZ!MTB"
        threat_id = "2147843824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ff 8b 45 ?? 0f be 14 10 69 d2 ?? ?? ?? ?? 33 f2 83 f6 ?? 03 ce 8b 45 ?? 03 45 ?? 88 08 0f be 4d ?? 8b 55 ?? 03 55 ?? 0f b6 02 2b c1 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHF_2147843833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHF!MTB"
        threat_id = "2147843833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 3e 8b c6 83 e0 03 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHF_2147843833_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHF!MTB"
        threat_id = "2147843833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 02 88 45 ?? 0f be 4d ?? 0f be 75 ?? 8b 45 ?? 99 bf ?? ?? ?? ?? f7 ff 8b 45 ?? 0f be 14 10 69 d2 ?? ?? ?? ?? 33 f2 03 ce 8b 45 ?? 03 45 ?? 88 08 0f be 4d ?? 8b 55 ?? 03 55 ?? 0f b6 02 2b c1 8b 4d ?? 03 4d ?? 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAE_2147843850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAE!MTB"
        threat_id = "2147843850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 ce f7 e1 8b c6 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 0f b6 80 [0-4] 30 86 [0-4] 83 c6 05 81 fe 00 9c 04 00 0f}  //weight: 2, accuracy: Low
        $x_1_2 = "[2] Aujindyu" ascii //weight: 1
        $x_1_3 = "[3] SXade67" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NEBC_2147843867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NEBC!MTB"
        threat_id = "2147843867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Bellicosity ardour schematic" wide //weight: 2
        $x_2_2 = "Courses clearway spending continuable yielded" wide //weight: 2
        $x_2_3 = "Beeps outlawing raining" wide //weight: 2
        $x_2_4 = "Foreplay" wide //weight: 2
        $x_2_5 = "Veneers" wide //weight: 2
        $x_2_6 = "vpakRxKn" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHG_2147843911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHG!MTB"
        threat_id = "2147843911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 3c ?? ?? ?? ?? 88 84 34 ?? ?? ?? ?? 88 8c 3c ?? ?? ?? ?? 0f b6 84 34 ?? ?? ?? ?? 03 c2 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 43 81 fb 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHH_2147844058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHH!MTB"
        threat_id = "2147844058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 3e 46 3b f3 72 ed}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHJ_2147844175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHJ!MTB"
        threat_id = "2147844175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 04 10 69 c0 ?? ?? ?? ?? 99 bf ?? ?? ?? ?? f7 ff 33 f0 83 f6 ?? 03 ce 8b 55 ?? 03 55 ?? 88 0a 0f be 45 ?? 8b 4d ?? 03 4d ?? 0f b6 11 2b d0 8b 45 ?? 03 45 ?? 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHK_2147844199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHK!MTB"
        threat_id = "2147844199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 3e 8b c6 83 e0 03 ba ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 28 1c 3e 46 59 3b f5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHL_2147844425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHL!MTB"
        threat_id = "2147844425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cb 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAG_2147844477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAG!MTB"
        threat_id = "2147844477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 ff 8b 45 08 0f be 14 10 69 d2 [0-4] 83 e2 0e 33 f2 83 f6 06 03 ce 8b 45 0c 03 45 dc 88 08 0f be 4d db 8b 55 0c 03 55 dc 0f b6 02 2b c1 8b 4d 0c 03 4d dc 88 01 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAH_2147844494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAH!MTB"
        threat_id = "2147844494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 ff 8b 45 08 0f be 14 10 69 d2 [0-4] 81 e2 6b 01 00 00 33 f2 03 ce 8b 45 0c 03 45 80 88 08 0f be 8d 7f ff ff ff 8b 55 0c 03 55 80 0f b6 02 2b c1 8b 4d 0c 03 4d 80 88 01 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHN_2147844654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHN!MTB"
        threat_id = "2147844654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 4c 1d 10 88 4c 3d 10 88 54 1d 10 0f b6 4c 3d 10 03 ce 0f b6 c9 c7 45 ?? ?? ?? ?? ?? 8a 4c 0d ?? 32 88 ?? ?? ?? ?? 88 88 ?? ?? ?? ?? c7 45 fc ?? ?? ?? ?? 40}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHN_2147844654_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHN!MTB"
        threat_id = "2147844654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 83 e2 03 8a 8a ?? ?? ?? ?? 30 0c 38 40 3b c6 72 ?? 5f 5e c3}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHO_2147844714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHO!MTB"
        threat_id = "2147844714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 44 1d 10 88 44 3d 10 88 4c 1d 10 0f b6 44 3d 10 03 c2 0f b6 c0 0f b6 44 05 10 32 86 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 46 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MOR_2147844779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MOR!MTB"
        threat_id = "2147844779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 cd 89 4c 24 ?? 8d 0c 03 c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? 31 7c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 15 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 74 ?? 81 c3 ?? ?? ?? ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TIM_2147844780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TIM!MTB"
        threat_id = "2147844780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ff 8b 45 ?? 0f be 14 10 69 d2 ?? ?? ?? ?? 83 e2 ?? 33 f2 83 f6 ?? 03 ce 8b 45 ?? 03 45 ?? 88 08 0f be 8d ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 0f b6 02 2b c1 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHP_2147844787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHP!MTB"
        threat_id = "2147844787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {88 01 8b 55 0c 03 55 dc 0f b6 02 83 f0 5a 8b 4d 0c 03 4d dc 88 01 8b 55 0c 03 55 dc 0f b6 02 35 ff 00 00 00 8b 4d 0c 03 4d dc 88 01 8b 55 0c 03 55 dc 0f b6 02 83 e8 10 8b 4d 0c 03 4d dc 88 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAF_2147844794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAF!MTB"
        threat_id = "2147844794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 8d 54 fd ff ff 2b c1 8b 4d a4 2b 8d 24 fe ff ff 8b 95 34 ff ff ff 2b d1 2b c2 a3 [0-4] 81 bd 60 ff ff ff b5 11 00 00 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TIY_2147844889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TIY!MTB"
        threat_id = "2147844889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 07 c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? 31 5c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 c7 ?? ?? ?? ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KDD_2147844982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KDD!MTB"
        threat_id = "2147844982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 45 ?? 0f be 0c 10 6b c9 ?? 83 f1 ?? 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DOP_2147845050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DOP!MTB"
        threat_id = "2147845050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 8b 4c 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 c1 e8 ?? 03 c5 33 44 24 ?? 33 c8 2b f9 8d 44 24 ?? 89 4c 24 ?? 89 7c 24 ?? e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAI_2147845058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAI!MTB"
        threat_id = "2147845058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f7 f9 8b 45 08 0f be 0c 10 6b c9 4c 83 f1 03 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAFD_2147845141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAFD!MTB"
        threat_id = "2147845141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 0e 8b c6 83 e0 ?? 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 0e e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 04 8b 4c 39 30 8b 49 04 89 4c 24 1c 8b 11 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKE_2147845215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKE!MTB"
        threat_id = "2147845215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 c1 ea ?? 03 54 24 ?? 8d 04 3e 31 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 89 5c 24 ?? 8b 44 24 ?? 01 44 24 ?? 2b 74 24 ?? 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MKR_2147845222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MKR!MTB"
        threat_id = "2147845222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 1f 83 e3 ?? 8a 8b ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 75 ?? 88 04 37 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 28 1c 37 8b de 43 89 5d ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHQ_2147845285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHQ!MTB"
        threat_id = "2147845285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 dc 99 b9 ?? ?? ?? ?? f7 f9 8b 45 08 0f be 0c 10 69 c9 ?? ?? ?? ?? 83 e1 7f 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHR_2147845300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHR!MTB"
        threat_id = "2147845300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 14 1f 83 e3 03 8a 8b ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 75 c0 88 04 37}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHS_2147845472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHS!MTB"
        threat_id = "2147845472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 14 1f 83 e3 03 8a 8b ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 75 c4 88 04 37}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAJ_2147845614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAJ!MTB"
        threat_id = "2147845614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 dc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 0c 10 69 c9 ff 00 00 00 81 e1 ff 00 00 00 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KIC_2147845644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KIC!MTB"
        threat_id = "2147845644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 45 ?? 0f be 0c 10 6b c9 ?? 81 e1 ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHU_2147845670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHU!MTB"
        threat_id = "2147845670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 dc 99 b9 ?? ?? ?? ?? f7 f9 8b 45 08 0f be 0c 10 6b c9 ?? 81 e1 ?? ?? ?? ?? 8b 55 0c 03 55 dc 0f be 02 33 c1 8b 4d 0c 03 4d dc 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHV_2147845737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHV!MTB"
        threat_id = "2147845737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 45 b4 b4 1d 32 c8 c6 45 bb 00 32 e8 88 4d b6 b6 1e 88 6d b9 32 d0}  //weight: 10, accuracy: High
        $x_10_2 = {8a 85 60 ff ff ff 30 84 0d 61 ff ff ff 41 83 f9 10 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHW_2147845748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHW!MTB"
        threat_id = "2147845748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 1d ?? ?? ?? ?? 0f b6 07 03 c8 0f b6 c1 8a 84 05 ?? ?? ?? ?? 32 86 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8b 8d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHX_2147845766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHX!MTB"
        threat_id = "2147845766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 03 55 d8 8a 02 88 45 d7 0f b6 4d d7 8b 45 d8 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d df 8b 45 08 03 45 d8 8a 08 88 4d d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAK_2147845793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAK!MTB"
        threat_id = "2147845793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 99 b9 [0-4] f7 f9 8b 45 08 0f be 0c 10 69 c9 [0-4] 81 e1 ff 00 00 00 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GHZ_2147845832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GHZ!MTB"
        threat_id = "2147845832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 55 c0 0f b6 45 c0 0f b7 4d bc 33 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 33 c8 33 d2 89 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 45 9c 8b 4d a0 05 ?? ?? ?? ?? 81 d1 ?? ?? ?? ?? 89 45 b0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GIA_2147845851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GIA!MTB"
        threat_id = "2147845851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 3c 30 8b c6 83 e0 03 8a 98 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 04 32 df 8b 45 dc 00 1c 30 ba}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GIB_2147845875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GIB!MTB"
        threat_id = "2147845875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 14 1e 83 e3 03 8a 8b ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 75 c0 8b 4d bc 88 04 31}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAL_2147845926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAL!MTB"
        threat_id = "2147845926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 99 b9 [0-4] f7 f9 8b 45 08 0f be 0c 10 6b c9 ?? 83 e1 ?? 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GIC_2147845953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GIC!MTB"
        threat_id = "2147845953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 0e 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 0e e8 ?? ?? ?? ?? 51 8b c8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GID_2147845981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GID!MTB"
        threat_id = "2147845981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 4c 3d ?? 88 4c 35 ?? 88 5c 3d ?? 0f b6 54 35 ?? 0f b6 cb 03 d1 0f b6 ca 0f b6 4c 0d 10 32 88 ?? ?? ?? ?? 88 88 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 40 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CATG_2147846175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CATG!MTB"
        threat_id = "2147846175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d dc 3b 4d 10 73 2d 8b 45 dc 99 b9 ?? ?? ?? ?? f7 f9 8b 45 08 0f be 0c 10 6b c9 ?? 83 e1 ?? 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAM_2147846367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAM!MTB"
        threat_id = "2147846367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e2 c1 ea 06 8b c2 c1 e0 06 03 c2 8b d6 2b d0 0f b6 82 [0-4] b2 1c f6 ea 24 45 30 86 [0-4] 83 c6 06 81 fe 00 a0 02 00 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAN_2147846368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAN!MTB"
        threat_id = "2147846368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e2 c1 ea 06 8b c2 c1 e0 06 03 c2 8b d6 2b d0 0f b6 82 [0-4] b2 1c f6 ea 24 45 30 86 [0-4] 03 f3 81 fe 00 a2 02 00 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAO_2147846370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAO!MTB"
        threat_id = "2147846370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 d2 0f b6 8c 35 [0-4] 03 d1 0f b6 ca 0f b6 8c 0d [0-4] 32 88 [0-4] 88 88 [0-4] c7 45 fc ff ff ff ff 40 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GIE_2147846458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GIE!MTB"
        threat_id = "2147846458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 11 88 55 db 0f b6 4d db 8b 45 dc 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d e3 8b 45 08 03 45 dc 8a 08 88 4d da 8a 55 da 88 55 d9 0f b6 45 e3 8b 4d 08 03 4d dc 0f b6 11 03 d0 8b 45 08 03 45 dc 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJA_2147846733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJA!MTB"
        threat_id = "2147846733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 dc 99 b9 ?? ?? ?? ?? f7 f9 8b 45 08 0f be 0c 10 6b c9 3b 81 e1 ?? ?? ?? ?? 79 ?? 49 83 c9 e0 41 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJB_2147846742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJB!MTB"
        threat_id = "2147846742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 02 88 45 db 0f b6 4d db 8b 45 dc 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d e3 8b 45 08 03 45 dc 8a 08 88 4d da 8a 55 da 88 55 d9 0f b6 45 e3 8b 4d 08 03 4d dc 0f b6 11 03 d0 8b 45 08 03 45 dc 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJC_2147846743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJC!MTB"
        threat_id = "2147846743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 1d ?? ?? ?? ?? 88 84 3d ?? ?? ?? ?? 88 8c 1d ?? ?? ?? ?? 0f b6 84 3d ?? ?? ?? ?? 03 c2 0f b6 c0 0f b6 84 05 ?? ?? ?? ?? 32 86 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 46 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJD_2147846749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJD!MTB"
        threat_id = "2147846749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 03 ef 31 6c 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 74 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJE_2147846930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJE!MTB"
        threat_id = "2147846930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 f9 8b 45 08 0f be 04 10 99 b9 ?? ?? ?? ?? f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_LKV_2147847100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.LKV!MTB"
        threat_id = "2147847100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ID: waasflletasfv11" wide //weight: 1
        $x_1_2 = "%appdata%\\discord\\Local Storage\\leveldb" wide //weight: 1
        $x_1_3 = "Removeg[@name=\\PasswString.Removeord\\]/valuString." wide //weight: 1
        $x_1_4 = "*wallet*" wide //weight: 1
        $x_1_5 = "bG9iamRwa2hlY2Fwa2lqamRrZ2NqaGtpYnxIYXJtb255V2FsbGV0CmFlYWNoa25tZWZwaGVwY2Npb25ib29oY2tvbm9lZW1nfENvaW45OFdhbGxldAp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJF_2147847119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJF!MTB"
        threat_id = "2147847119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 03 55 dc 8a 02 88 45 db 0f b6 4d db 8b 45 dc 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d e3 8b 45 08 03 45 dc 8a 08 88 4d da}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CREP_2147847275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CREP!MTB"
        threat_id = "2147847275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 45 08 0f be 0c 10 69 c9 ?? ?? ?? ?? 83 e1 ?? 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJG_2147847287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJG!MTB"
        threat_id = "2147847287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 02 88 45 d7 0f b6 4d d7 8b 45 d8 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d df c7 45 ?? ?? ?? ?? ?? 8b 45 08 03 45 d8 8a 08 88 4d d6 8a 55 d6 88 55 d5 0f b6 45 df 8b 4d 08 03 4d d8 0f b6 11 03 d0 8b 45 08 03 45 d8 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_IMF_2147847300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.IMF!MTB"
        threat_id = "2147847300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e2 06 0b ca 88 4d ?? 0f b6 45 ?? 83 c0 48 88 45 ?? 0f b6 4d ?? c1 f9 02 0f b6 55 ?? c1 e2 06 0b ca 88 4d ?? 0f b6 45 ?? 2d ?? 00 00 00 88 45 ?? 0f b6 4d ?? f7 d9 88 4d ?? 8b 55 e0 8a 45 ?? 88 44 15 e4 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SN_2147847384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SN!MTB"
        threat_id = "2147847384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 8d 64 ff ff ff 88 8d 63 ff ff ff 0f b6 95 63 ff ff ff f7 d2 88 95 63 ff ff ff 0f b6 85 63 ff ff ff f7 d8 88 85 63 ff ff ff 0f b6 8d 63 ff ff ff 2b 8d 64 ff ff ff 88 8d 63 ff ff ff 0f b6 95 63 ff ff ff c1 fa 07 0f b6 85 63 ff ff ff d1 e0 0b d0 88 95 63 ff ff ff 0f b6 8d 63 ff ff ff 33 8d 64 ff ff ff 88 8d 63 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CREU_2147847461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CREU!MTB"
        threat_id = "2147847461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 9d d4 fe ff ff 0f b6 8c 1d e8 fe ff ff 88 8c 3d e8 fe ff ff 88 94 1d e8 fe ff ff 0f b6 8c 3d e8 fe ff ff 03 ce 0f b6 c9 0f b6 8c 0d e8 fe ff ff 32 88 ?? ?? ?? ?? 88 88 ?? ?? ?? ?? c7 45 fc ?? ?? ?? ?? 40 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CRHX_2147847662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CRHX!MTB"
        threat_id = "2147847662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 d3 0f b6 4d d3 51 8d 4d e4 e8 ?? ?? ?? ?? 0f b6 10 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAT_2147847719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAT!MTB"
        threat_id = "2147847719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "takacawukisujeruvuwohupekaboyak" ascii //weight: 1
        $x_1_2 = "xapasofeyiwihusem" ascii //weight: 1
        $x_1_3 = "boyapegicuduholikexituzopeyeteva tel nigilefihokefejufevesiwafudinizi bucahaxunitujakitinitam" ascii //weight: 1
        $x_1_4 = "dezorokosacecubayuzesucada cubiso sokozixasexokaputukihegomenuw vigecudutotirehasaha" ascii //weight: 1
        $x_1_5 = "sureholegakunigefaw jegasoyixuzet gitonopuvekibugegaz buvirutomenefelenafusipa" ascii //weight: 1
        $x_1_6 = "mugefifuyuxovexecodakuzifec" ascii //weight: 1
        $x_1_7 = "fexujuzidus nipivifihalahel cutefugajuyihatoposiwujejajil" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAU_2147847733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAU!MTB"
        threat_id = "2147847733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 18 89 44 24 24 8b 44 24 2c 01 44 24 24 8b 4c 24 20 8b 54 24 18 d3 ea 8b 4c 24 3c 8d 44 24 30 c7 05 [0-4] ee 3d ea f4 89 54 24 30 e8 [0-4] 8b 44 24 24 31 44 24 14 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAV_2147847734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAV!MTB"
        threat_id = "2147847734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 4d d3 51 8d 4d e4 e8 [0-4] 0f b6 10 6b d2 ?? 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAW_2147847749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAW!MTB"
        threat_id = "2147847749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 45 d3 0f b6 4d d3 51 8d 4d e4 e8 [0-4] 0f b6 10 69 d2 [0-4] 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAX_2147847801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAX!MTB"
        threat_id = "2147847801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 44 24 28 56 8d 4c 24 14 89 44 24 18 c7 05 [0-4] fc 03 cf ff e8 [0-4] 8b 44 24 14 33 44 24 10 c7 05 [0-4] 00 00 00 00 2b f8 8b cf c1 e1 04 81 3d [0-4] 8c 07 00 00 89 44 24 14 89 4c 24 10 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJJ_2147847866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJJ!MTB"
        threat_id = "2147847866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 11 33 d0 a1 ?? ?? ?? ?? 03 85 88 f2 ff ff 88 10 e9 37 00 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CRHL_2147847946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CRHL!MTB"
        threat_id = "2147847946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 3d f8 fe ff ff 88 84 35 f8 fe ff ff 88 8c 3d f8 fe ff ff 0f b6 84 35 f8 fe ff ff 8b 8d 88 fc ff ff 03 c2 0f b6 c0 0f b6 84 05 f8 fe ff ff 30 81 ?? ?? ?? ?? 41 89 8d 88 fc ff ff 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WDS_2147848092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WDS!MTB"
        threat_id = "2147848092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 88 45 d3 0f b6 4d ?? 51 8d 4d ?? e8 ?? ?? ?? ?? 0f b6 10 81 e2 a3 11 00 00 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJL_2147848206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJL!MTB"
        threat_id = "2147848206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 55 cb 0f b6 45 cb 50 8d 4d e0 e8 ?? ?? ?? ?? 0f b6 08 8b 55 08 03 55 cc 0f b6 02 33 c1 8b 4d 08 03 4d cc 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAY_2147848277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAY!MTB"
        threat_id = "2147848277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f6 17 80 2f d6 47 e2}  //weight: 2, accuracy: High
        $x_1_2 = "thtsktnqpxjymlibrfelgtcxiizhphjwko" ascii //weight: 1
        $x_1_3 = "qtncfvtdsuxclmedihsfhlazlbhtvtrifdwdpjqjpmmgdfumfmmlkjllfrggswszuotthqlgwetic" ascii //weight: 1
        $x_1_4 = "efymzkdybciqvsowuamcllipkjlypnjizegjrhgldfvopitsfpjqkrvieerbaaqgynmgdxepkqfkghfklaxqfekzrccl" ascii //weight: 1
        $x_1_5 = "aniuhyutcvprocemyxdsamlxlxhwzlacogmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CAZ_2147848413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CAZ!MTB"
        threat_id = "2147848413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 8b ce c1 e9 05 8d 1c 37 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 4c 24 14 8b 44 24 24 01 44 24 14 81 3d [0-4] 79 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_VVI_2147848696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.VVI!MTB"
        threat_id = "2147848696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 54 24 ?? 8b 44 24 34 01 44 24 14 8b 44 24 24 31 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 57 57 57 ff 15 ?? ?? ?? ?? 8b 44 24 10 33 44 24 14 89 44 24 10 2b f0 8b 44 24 ?? 29 44 24 18 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_VIJ_2147848697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.VIJ!MTB"
        threat_id = "2147848697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 8b 4c 24 ?? 8d 44 24 28 89 54 24 28 e8 ?? ?? ?? ?? 8b 44 24 24 31 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 57 57 57 ff 15 ?? ?? ?? ?? 8b 44 24 10 33 44 24 28 89 44 24 10 2b f0 8b 44 24 ?? 29 44 24 14 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CRIT_2147848708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CRIT!MTB"
        threat_id = "2147848708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 17 80 2f a6 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CRIV_2147848709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CRIV!MTB"
        threat_id = "2147848709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 fe 0f b6 4d fe 8b 45 f8 33 d2 f7 75 10 0f b6 92 80 56 45 00 33 ca 88 4d ff 8b 45 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PZE_2147848746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PZE!MTB"
        threat_id = "2147848746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d 08 f6 17 80 2f b4 47 e2}  //weight: 1, accuracy: High
        $x_1_2 = {e2 d8 2b db d9 dc e4 d9 ea de 2b e8 ea dd dd dc d7 2b e9 e6 2b d9 d6 dd 2b e2 dd 2b 07 fc f8 2b de dc e7 e6 1d}  //weight: 1, accuracy: High
        $x_1_3 = {c2 b2 4e 58 4b 55 70 e2 9e 12 57 0e 0a a5 55 eb fd 71 51 b7 a0 a1 b1 aa fe fe a2 58 97 4c 15 bc 51 87 84 63 66 79 d1 55 44 d1 d7 9b ec 35 04 7d b7 e6 17 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAA_2147848827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAA!MTB"
        threat_id = "2147848827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oSLtLQSxtvpdBECUZBXkaeTPlwSdgL" ascii //weight: 1
        $x_1_2 = "KyIRdvBdBshDGzUqpGJheVbOBaEDHD" ascii //weight: 1
        $x_1_3 = "tXayXZyFAlwKXDyEwiabOU" ascii //weight: 1
        $x_1_4 = "ODjUoxBYLaxmfmKOlbcYgKkqC" ascii //weight: 1
        $x_1_5 = "eCpmMDlHVYHcgimrwmWHfTFHJbqczIo" ascii //weight: 1
        $x_1_6 = "QwtUQJbJxrouqGzBrmtXMErGvcUtEZu" ascii //weight: 1
        $x_1_7 = "lPCoMIRqeUfXOueXVtAxmxtUUuNpdg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAB_2147848862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAB!MTB"
        threat_id = "2147848862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {f6 17 80 2f ?? 47 e2}  //weight: 3, accuracy: Low
        $x_1_2 = "nlahJYlawUZifyTpOnwPnuMFXFeZcSSNWY" ascii //weight: 1
        $x_1_3 = "rzGbYCGvdsteKwKoWZibohASEowdBuIR" ascii //weight: 1
        $x_1_4 = "qrJuaZBbXMAAzUOojFZzWPvRSfFGwwzxmg" ascii //weight: 1
        $x_1_5 = "rhvEuYhOuwbeHSuieNwRszQiIqVTVIPAp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAC_2147848999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAC!MTB"
        threat_id = "2147848999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 80 2f ?? 47 e2}  //weight: 1, accuracy: Low
        $x_1_2 = "plzvoyfabwomofbliajxqmjrjlwmtuac" ascii //weight: 1
        $x_1_3 = "vstfjzrohnspkzbmvnfqrhkgaeglsmikamoezvr" ascii //weight: 1
        $x_1_4 = "mpozjatcytglgwgrotxoknawykkqzinqkhukushcwjmafvpcfonrtdcxucjymjhzpfjbcvdvdpaqfhcjhyj" ascii //weight: 1
        $x_1_5 = "wricpszllbhawcpycwflxrjztiszycjyuivvradqvxdaymvx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAD_2147849022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAD!MTB"
        threat_id = "2147849022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 80 2f ?? 47 e2}  //weight: 1, accuracy: Low
        $x_1_2 = "TxVWLwzVzlONzDnAwBKWLuOrmwhKw" ascii //weight: 1
        $x_1_3 = "FuHiCacUhwPxUDLDtgfuvSYoHvzOdLThv" ascii //weight: 1
        $x_1_4 = "TTMIcNkCipbiHcBPxxxNgiyzYxIYKvOkS" ascii //weight: 1
        $x_1_5 = "ySXuCSSmUBkRizacRVdihconRkPidGU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAE_2147849087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAE!MTB"
        threat_id = "2147849087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {f6 17 80 2f ?? 47 e2}  //weight: 3, accuracy: Low
        $x_1_2 = "hMEi7u4HipZ21Mm5rOGkDHmWU6wgRzX" ascii //weight: 1
        $x_1_3 = "nBpqGUCrkueKU2IzEKJmoXBh" ascii //weight: 1
        $x_1_4 = "ktlCYwx7ptdm61PxJbGw3IbkgMxw3n" ascii //weight: 1
        $x_1_5 = "fJ65O3tgW3uW02Mj5rLKF8XKue" ascii //weight: 1
        $x_1_6 = "BT0knT8oBCSZBRhSerFMhF5Z4GRmQj" ascii //weight: 1
        $x_1_7 = "G9Ja9RnRh8s9KQWaHRhFEugbweWcf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redline_DAF_2147849177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAF!MTB"
        threat_id = "2147849177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 80 2f ?? 47 e2}  //weight: 1, accuracy: Low
        $x_1_2 = "Gxmihhkqmfvtyxihkulajvqyutrxctbibdlhruo" ascii //weight: 1
        $x_1_3 = "frttfbokqplaawfvlxvekssvxwafozcpdygpvgxlfsrqovmfnhqsvzwfubjtot" ascii //weight: 1
        $x_1_4 = "lwiuwkismxxtwwwqzwldygjnnyxhjunycttcbudvasftezajiirsjwrmqnogduxxly" ascii //weight: 1
        $x_1_5 = "fvmluizknuscqpgdchhcphpokwmmbazpklnejv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAG_2147849188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAG!MTB"
        threat_id = "2147849188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 84 3c [0-4] 88 84 0c [0-4] 8a 44 24 1b 88 84 3c [0-4] 0f b6 84 0c [0-4] 03 44 24 14 0f b6 c0 0f b6 84 04 [0-4] 30 86 [0-4] 46 81 fe 00 22 02 00 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_FKI_2147849239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.FKI!MTB"
        threat_id = "2147849239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4c 24 10 8b 44 24 14 03 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c7 33 c1 2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 3c 33 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 14 8b 44 24 28 01 44 24 14 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 44 24 38 50 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 14 33 cf 31 4c 24 10 8b 44 24 10 29 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJX_2147849250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJX!MTB"
        threat_id = "2147849250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 2f a4 80 2f 67 47 e2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJX_2147849250_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJX!MTB"
        threat_id = "2147849250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 07 67 47 e2}  //weight: 10, accuracy: High
        $x_10_2 = {f7 d1 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 33 95 ?? ?? ?? ?? 88 95 ?? ?? ?? ?? 8b 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GJX_2147849250_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GJX!MTB"
        threat_id = "2147849250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b ca 88 4d ?? 0f b6 45 ?? 03 45 ?? 88 45 ?? 0f b6 4d ?? f7 d1 88 4d ?? 0f b6 55 ?? 33 55 ?? 88 55 ?? 8b 45 ?? 8a 4d ?? 88 4c 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CRIP_2147849268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CRIP!MTB"
        threat_id = "2147849268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 20 0f b6 84 3c ?? ?? ?? ?? 88 84 0c ?? ?? ?? ?? 8a 44 24 1b 88 84 3c ?? ?? ?? ?? 0f b6 84 0c ?? ?? ?? ?? 03 44 24 ?? 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CRTE_2147849344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CRTE!MTB"
        threat_id = "2147849344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 80 2f ?? 80 2f ?? 47 e2 f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKD_2147849484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKD!MTB"
        threat_id = "2147849484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 7d 08 80 37 ff 80 07 9e 47 e2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAH_2147849521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAH!MTB"
        threat_id = "2147849521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 84 3d ?? ?? ff ff 88 84 0d ?? ?? ff ff 8a 85 ?? ?? ff ff 88 84 3d ?? ?? ff ff 0f b6 84 0d ?? ?? ff ff 03 85 ?? ?? ff ff 0f b6 c0 0f b6 84 05 ?? ?? ff ff 30 86 [0-4] 46 81 fe [0-4] 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAI_2147849522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAI!MTB"
        threat_id = "2147849522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 84 0c [0-4] 88 84 14 [0-4] 8a 44 24 ?? 88 84 0c [0-4] 0f b6 84 14 [0-4] 03 44 24 10 0f b6 c0 0f b6 84 04 [0-4] 30 86 [0-4] 46 81 fe [0-4] 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAJ_2147849524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAJ!MTB"
        threat_id = "2147849524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 84 0d [0-4] 88 84 15 [0-4] 8a 85 [0-4] 88 84 0d [0-4] 0f b6 84 15 [0-4] 03 85 [0-4] 0f b6 c0 0f b6 84 05 [0-4] 30 86 [0-4] 46 81 fe [0-4] 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAK_2147849525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAK!MTB"
        threat_id = "2147849525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 84 1c [0-4] 88 84 0c [0-4] 8a 44 24 ?? 88 84 1c [0-4] 0f b6 84 0c [0-4] 03 44 24 1c 0f b6 c0 0f b6 84 04 [0-4] 30 86 [0-4] 46 81 fe [0-4] 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKI_2147849599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKI!MTB"
        threat_id = "2147849599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c7 33 c1 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b ce c1 e9 ?? 8d 3c 33 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAL_2147849615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAL!MTB"
        threat_id = "2147849615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 10 81 e2 [0-4] 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9}  //weight: 3, accuracy: Low
        $x_1_2 = "ngvfhkzovihorkujviwcgghbvmjsaljejuyyrm" ascii //weight: 1
        $x_1_3 = "tseskztgwiammjbragudelsrvgshdmhvmcykficbfwqhfcdlkioewpjajakulsfyrdujz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKJ_2147849669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKJ!MTB"
        threat_id = "2147849669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 07 5e fe 07 47 e2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAM_2147849759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAM!MTB"
        threat_id = "2147849759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 84 1c [0-4] 88 84 3c [0-4] 8a 44 24 13 88 84 1c [0-4] 0f b6 84 3c [0-4] 03 44 24 1c 0f b6 c0 0f b6 84 04 [0-4] 30 86 [0-4] 46 81 fe [0-4] 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKL_2147849800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKL!MTB"
        threat_id = "2147849800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 1c ?? ?? ?? ?? 88 84 3c ?? ?? ?? ?? 8a 44 24 ?? 88 84 1c ?? ?? ?? ?? 0f b6 84 3c ?? ?? ?? ?? 03 44 24 ?? 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GKZ_2147850001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GKZ!MTB"
        threat_id = "2147850001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 2f d4 fe 07 47 e2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KAO_2147850126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KAO!MTB"
        threat_id = "2147850126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 14 8b 44 24 28 01 44 24 14 8b 4c 24 14 8b 44 24 10 33 cb 33 c1 2b f8 8d 44 24 18 e8 ?? ?? ?? ?? ff 4c 24 1c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SSF_2147850240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SSF!MTB"
        threat_id = "2147850240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ce 89 4c 24 20 8b 4c 24 1c d3 ee 8b 4c 24 40 8d 44 24 14 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 74 24 14 e8 c4 fe ff ff 8b 44 24 20 31 44 24 10 81 3d ?? ?? ?? ?? e6 09 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAN_2147850602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAN!MTB"
        threat_id = "2147850602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e8 05 03 44 24 1c c7 05 [0-4] 00 00 00 00 33 c1 8d 0c 3b 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 14 89 54 24 10 8b 44 24 20 01 44 24 10 81 3d [0-4] be 01 00 00 8d 2c 33 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAO_2147850608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAO!MTB"
        threat_id = "2147850608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c8 0f b6 f1 ba [0-4] e8 [0-4] 50 e8 [0-4] 83 c4 04 0f b6 84 35 e8 fe ff ff 32 87 [0-4] 88 87 [0-4] 47 89 bd d4 fe ff ff 8b b5 d8 fe ff ff e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAP_2147850612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAP!MTB"
        threat_id = "2147850612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 7d 08 f6 17 80 07 29 80 2f 44 47 e2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAQ_2147850619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAQ!MTB"
        threat_id = "2147850619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 7d 08 f6 17 80 07 34 80 2f 66 47 e2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNA_2147850650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNA!MTB"
        threat_id = "2147850650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 07 ?? 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNA_2147850650_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNA!MTB"
        threat_id = "2147850650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 80 07 ?? 8b c3 33 c3 33 c0 33 c3 33 d8 8b de 33 c3 33 f6 8b f6 f6 2f 47 e2}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c3 33 de 80 07 ?? 8b c6 33 c0 8b db 8b c6 8b d8 33 c3 33 f6 33 de 33 c3 f6 2f 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_GNA_2147850650_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNA!MTB"
        threat_id = "2147850650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 da 88 55 ?? 0f b6 45 ?? f7 d0 88 45 ?? 0f b6 4d ?? f7 d9 88 4d ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 0f b6 45 ?? f7 d8 88 45 ?? 0f b6 4d ?? 2b 4d ?? 88 4d ?? 8b 55 ?? 8a 45 ?? 88 44 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNB_2147850651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNB!MTB"
        threat_id = "2147850651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 80 34 3e ?? 83 c4 28 46 3b 74 24 18 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNB_2147850651_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNB!MTB"
        threat_id = "2147850651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 e6 66 c1 df fa 66 81 ca cc 00 66 f7 e1 33 d8 81 ee ?? ?? ?? ?? 8b fe 66 0b db c1 e7 5a 03 d9 0f bf d2 8b c7 66 f7 e0 66 03 f0 42}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNB_2147850651_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNB!MTB"
        threat_id = "2147850651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e2 02 0b ca 88 4d ?? 0f b6 45 ?? f7 d0 88 45 ?? 0f b6 4d ?? 81 c1 ?? ?? ?? ?? 88 4d ?? 0f b6 55 ?? 83 f2 ?? 88 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNB_2147850651_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNB!MTB"
        threat_id = "2147850651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 83 e1 03 8a 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNC_2147850658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNC!MTB"
        threat_id = "2147850658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 08 50 e8 ?? ?? ?? ?? 83 c4 04 80 34 1f ?? 43 39 de 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNC_2147850658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNC!MTB"
        threat_id = "2147850658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c8 0f b6 f1 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 8a 84 35 ?? ?? ?? ?? 32 83 ?? ?? ?? ?? 88 83 ?? ?? ?? ?? 43 89 9d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNC_2147850658_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNC!MTB"
        threat_id = "2147850658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 14 10 03 ca 0f b6 45 ?? 03 c8 81 e1 ?? ?? ?? ?? 88 4d ?? 0f b6 4d ?? 03 4d ?? 51 0f b7 55 ?? 03 55 ?? 52 8b 4d ?? e8 ?? ?? ?? ?? 8a 45 ?? 04 ?? 88 45 ?? 0f b6 4d ?? 0f b7 55 ?? 3b ca}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNC_2147850658_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNC!MTB"
        threat_id = "2147850658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b d0 88 55 ?? 0f b6 4d ?? 83 c1 ?? 88 4d ?? 0f b6 55 ?? f7 d2 88 55 ?? 0f b6 45 ?? 83 c0 22 88 45 ?? 0f b6 4d ?? f7 d9 88 4d ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 0f b6 45 ?? f7 d8 88 45 ?? 0f b6 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GND_2147850661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GND!MTB"
        threat_id = "2147850661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 3c 06 33 d2 8b c6 f7 f5 68 ?? ?? ?? ?? 8a 9a ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 8b 44 24 ?? 83 c4 ?? 00 1c 06 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 28 3c 06 46 3b f7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GND_2147850661_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GND!MTB"
        threat_id = "2147850661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f7 d0 88 45 db 0f b6 4d db 2b 4d dc 88 4d db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db 83 e8 5e 88 45 db 0f b6 4d db f7 d1 88 4d db 0f b6 55 db 83 c2 20 88 55 db 8b 45 dc 8a 4d db 88 4c 05 e8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNE_2147850662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNE!MTB"
        threat_id = "2147850662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 07 ?? 80 2f ?? 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNE_2147850662_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNE!MTB"
        threat_id = "2147850662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 55 db 0f b6 4d ?? 03 4d dc 88 4d ?? 0f b6 55 ?? c1 fa ?? 0f b6 45 ?? c1 e0 ?? 0b d0 88 55 ?? 0f b6 4d ?? 03 4d ?? 88 4d ?? 8b 55 ?? 8a 45 ?? 88 44 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNE_2147850662_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNE!MTB"
        threat_id = "2147850662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 d2 88 55 ?? 0f b6 45 ?? 83 c0 ?? 88 45 ?? 0f b6 4d ?? f7 d1 88 4d ?? 0f b6 55 ?? d1 fa 0f b6 45 ?? c1 e0 ?? 0b d0 88 55 ?? 8b 4d ?? 8a 55 ?? 88 54 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNF_2147850665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNF!MTB"
        threat_id = "2147850665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 2f ?? 80 07 ?? 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNF_2147850665_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNF!MTB"
        threat_id = "2147850665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 83 f0 ?? 8b 4d 08 03 4d fc 88 01 6a 6f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNG_2147850668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNG!MTB"
        threat_id = "2147850668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 33 c0 f6 17 80 07 ?? 80 2f ?? 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNG_2147850668_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNG!MTB"
        threat_id = "2147850668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 08 8b c8 e8 ?? ?? ?? ?? 8b 55 08 03 55 fc 0f b6 02 83 f0 ?? 8b 4d 08 03 4d fc 88 01 68}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_IIL_2147850773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.IIL!MTB"
        threat_id = "2147850773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 14 8b 44 24 24 01 44 24 14 8b 4c 24 14 8b 44 24 10 33 cd 33 c1 2b f8 81 c3 47 86 c8 61 ff 4c 24 18 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CRI_2147850774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CRI!MTB"
        threat_id = "2147850774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8a 1c 0e 8b c6 f7 f5 6a 00 8a 82 ?? ?? ?? ?? 32 c3 02 c3 88 04 0e ff 15 ?? ?? ?? ?? 8b 4c 24 14 28 1c 0e 46 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ABH_2147850777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ABH!MTB"
        threat_id = "2147850777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ee 8b 4c 24 28 89 44 24 2c 8d 44 24 18 89 74 24 18 c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 e4 fe ff ff 8b 44 24 2c 31 44 24 14 81 3d ?? ?? ?? ?? e6 09 00 00 75 0c 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 14 31 4c 24 18 81 3d ?? ?? ?? ?? 13 02 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_SKE_2147850779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.SKE!MTB"
        threat_id = "2147850779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 8b 7c 24 10 33 d2 8a 1c 3e 8b c6 f7 74 24 18 6a 00 6a 00 8a 82 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e ff 15 ?? ?? ?? ?? 28 1c 3e 46 3b 74 24 14 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNH_2147851021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNH!MTB"
        threat_id = "2147851021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 35 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 6a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNH_2147851021_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNH!MTB"
        threat_id = "2147851021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 10 69 db ?? ?? ?? ?? 69 0c b8 ?? ?? ?? ?? 47 8b c1 c1 e8 18 33 c1 69 c8 ?? ?? ?? ?? 33 d9 3b fd 0f 8c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNH_2147851021_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNH!MTB"
        threat_id = "2147851021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 33 d3 ee 8b 4c 24 ?? 89 44 24 ?? 8d 44 24 ?? 89 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNI_2147851035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNI!MTB"
        threat_id = "2147851035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 33 c0 f6 17 80 2f ?? 80 07 ?? 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNI_2147851035_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNI!MTB"
        threat_id = "2147851035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 ff d6 80 04 2f ?? 68}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 00 ff d6 80 34 2f ?? 68}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNI_2147851035_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNI!MTB"
        threat_id = "2147851035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 c1 e8 ?? 03 44 24 ?? 03 cb 33 c2 33 c1 2b f0 8b d6 c1 e2 ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAS_2147851201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAS!MTB"
        threat_id = "2147851201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 7d 08 f6 17 80 37 43 47 e2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAT_2147851203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAT!MTB"
        threat_id = "2147851203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 20 83 44 24 14 64 29 44 24 14 83 6c 24 14 64 8b 44 24 14 8d 4c 24 10 e8 [0-4] 8b 44 24 34 01 44 24 10 8b 44 24 14 8b 4c 24 18 8d 14 07 31 54 24 10 d3 e8 03 c3 81 3d [0-4] 21 01 00 00 8b f0 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ZIN_2147851285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ZIN!MTB"
        threat_id = "2147851285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 05 03 44 24 2c 03 d5 33 c2 03 cb 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 18 c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 10 8b 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 18 8b 44 24 28 01 44 24 18 81 3d ?? ?? ?? ?? 79 09 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 18 33 cf 31 4c 24 10 8b 44 24 10 29 44 24 14 8b 3d ?? ?? ?? ?? 81 ff 93 00 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNL_2147851337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNL!MTB"
        threat_id = "2147851337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 10 8b c8 6a 01 ff 12 ff 74 24 ?? 8b cf e8 ?? ?? ?? ?? 8b cf e8 ?? ?? ?? ?? 8a 84 1c ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 8b 5c 24 ?? 8b 54 24 ?? 81 fe 00 b2 02 00 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BUM_2147851400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BUM!MTB"
        threat_id = "2147851400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d6 d3 ee 8b cb 8d 44 24 1c 89 54 24 2c 89 74 24 1c c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 e4 fe ff ff 8b 44 24 2c 31 44 24 0c 81 3d ?? ?? ?? ?? e6 09 00 00 75 0c 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 0c 31 44 24 1c 81 3d ?? ?? ?? ?? 13 02 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNM_2147851448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNM!MTB"
        threat_id = "2147851448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xrOQWJRVOQWOJRXZOJQWO" ascii //weight: 1
        $x_1_2 = "qyxkebfsclhu" ascii //weight: 1
        $x_1_3 = "txzycrzsornkygvgkcjdfrap" ascii //weight: 1
        $x_1_4 = "Sonorously hospitable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNN_2147851550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNN!MTB"
        threat_id = "2147851550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 33 c0 80 2f ?? 80 07 ?? 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_EXT_2147851555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.EXT!MTB"
        threat_id = "2147851555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ee 8b 4c 24 28 89 44 24 2c 8d 44 24 1c 89 74 24 1c c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 e7 fe ff ff 8b 44 24 2c 31 44 24 10 81 3d ?? ?? ?? ?? e6 09 00 00 75 0c 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 10 31 4c 24 1c 81 3d ?? ?? ?? ?? 13 02 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {29 44 24 14 83 6c 24 14 64 8b 44 24 14 8d 4c 24 10 e8 ?? ?? ?? ?? 8b 44 24 30 01 44 24 10 8b 44 24 14 8b 4c 24 18 8d 14 07 31 54 24 10 d3 e8 03 c3 81 3d ?? ?? ?? ?? 21 01 00 00 8b f0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_LIW_2147851634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.LIW!MTB"
        threat_id = "2147851634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 ea 8b 4c 24 24 8d 44 24 1c c7 05 ?? ?? ?? ?? ee 3d ea f4 89 54 24 1c e8 ?? ?? ?? ?? 8b 44 24 28 31 44 24 10 81 3d ?? ?? ?? ?? e6 09 00 00 75 0c 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 10 31 44 24 1c 81 3d ?? ?? ?? ?? 13 02 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {29 44 24 14 83 6c 24 14 64 8b 44 24 14 8d 4c 24 10 e8 ?? ?? ?? ?? 8b 44 24 2c 01 44 24 10 8b 44 24 14 8b 4c 24 18 8d 14 03 31 54 24 10 d3 e8 03 44 24 30 81 3d ?? ?? ?? ?? 21 01 00 00 8b f8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNQ_2147851726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNQ!MTB"
        threat_id = "2147851726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 88 9e ?? ?? ?? ?? 46 59 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNQ_2147851726_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNQ!MTB"
        threat_id = "2147851726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 80 34 1e ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 04 1e}  //weight: 10, accuracy: Low
        $x_10_2 = {ff 80 04 1e ?? 83 c4 30 46 3b f7 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNQ_2147851726_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNQ!MTB"
        threat_id = "2147851726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 ce 89 4c 24 ?? 8b 4c 24 ?? d3 ee 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 74 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? e6 09 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNR_2147851728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNR!MTB"
        threat_id = "2147851728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 06 83 c4 08 0f b6 0f 8b 74 24 10 03 c8 0f b6 c1 8a 84 04 ?? ?? ?? ?? 30 85 ?? ?? ?? ?? 45 81 fd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNR_2147851728_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNR!MTB"
        threat_id = "2147851728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 80 04 1f ?? 83 c4 ?? 47 3b fe 0f 82}  //weight: 10, accuracy: Low
        $x_10_2 = {ff 80 34 1f ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 04 1f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNR_2147851728_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNR!MTB"
        threat_id = "2147851728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c7 89 45 ?? 8b c7 d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNR_2147851728_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNR!MTB"
        threat_id = "2147851728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 37 d3 ee 8b 4c 24 ?? 89 44 24 ?? 8d 44 24 ?? 89 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? e6 09 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNS_2147851760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNS!MTB"
        threat_id = "2147851760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8a 1c 3e 8b c6 f7 74 24 1c 55 55 8a 82 ?? ?? ?? ?? 32 c3 fe c8 02 c3 88 04 3e ff 15 ?? ?? ?? ?? 28 1c 3e 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNS_2147851760_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNS!MTB"
        threat_id = "2147851760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d1 f9 0f b6 55 ?? c1 e2 ?? 0b ca 88 4d ?? 0f b6 45 ?? 2d ?? ?? ?? ?? 88 45 ?? 0f b6 4d ?? f7 d9 88 4d ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 8b 45 ?? 8a 4d ?? 88 4c 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAU_2147851785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAU!MTB"
        threat_id = "2147851785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 20 83 44 24 14 64 29 44 24 14 83 6c 24 14 64 8b 44 24 14 8d 4c 24 10 e8 ?? ?? ?? ?? 8b 44 24 30 01 44 24 10 8b 44 24 14 8b 4c 24 18 8d 14 07 31 54 24 10 d3 e8 03 c3 81 3d ?? ?? ?? ?? 21 01 00 00 8b f8 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 4c 24 18 8b c6 d3 e8 8d 14 37 8b cd 89 54 24 2c 89 44 24 20 8d 44 24 20 c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 2c 31 44 24 10 81 3d ?? ?? ?? ?? e6 09 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AAN_2147851958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AAN!MTB"
        threat_id = "2147851958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 33 d2 f7 75 10 8a 82 ?? ?? ?? ?? 32 c3 0f b6 1c 3e 8d 0c 18 88 0c 3e fe c9 88 0c 3e 6a 00 6a 00 ff 15 ?? ?? ?? ?? 28 1c 3e 6a 00 6a 00 ff 15 ?? ?? ?? ?? fe 04 3e 46 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAV_2147852016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAV!MTB"
        threat_id = "2147852016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 83 44 24 14 64 29 44 24 14 83 6c 24 14 64 8b 44 24 14 8d 4c 24 10 e8 [0-4] 8b 44 24 28 01 44 24 10 8b 44 24 14 8b 4c 24 18 8d 14 06 31 54 24 10 d3 e8 03 c3 81 3d [0-4] 21 01 00 00 8b f0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNT_2147852040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNT!MTB"
        threat_id = "2147852040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 33 c0 80 2f ?? 80 07 ?? f6 2f 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNT_2147852040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNT!MTB"
        threat_id = "2147852040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 4a 02 c1 e1 10 0f be 42 01 c1 e0 08 33 c8 0f be 02 33 c1 69 c0 ?? ?? ?? ?? 33 f8 8b c7 c1 e8 0d 33 c7 69 c0 ?? ?? ?? ?? 8b c8 c1 e9 0f 33 c8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNT_2147852040_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNT!MTB"
        threat_id = "2147852040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c7 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 89 5d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45 ?? 2b f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNU_2147852165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNU!MTB"
        threat_id = "2147852165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 06 59 59 0f b6 0f 03 c8 0f b6 c1 8b 4c 24 ?? 8a 84 04 ?? ?? ?? ?? 30 85 ?? ?? ?? ?? 45 81 fd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNU_2147852165_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNU!MTB"
        threat_id = "2147852165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 80 34 1f ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 04 1f ?? 83 c4 40 68}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNU_2147852165_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNU!MTB"
        threat_id = "2147852165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 f0 56 57 e8 ?? ?? ?? ?? 0f b6 06 83 c4 ?? 0f b6 0f 03 c8 0f b6 c1 8b 4c 24 ?? 8a 84 04 ?? ?? ?? ?? 30 85 ?? ?? ?? ?? 45 81 fd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAW_2147852452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAW!MTB"
        threat_id = "2147852452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 75 10 8a 82 ?? ?? ?? ?? 32 c3 0f b6 1c 3e 8d 0c 18 88 0c 3e fe c9 88 0c 3e 6a 00 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {59 28 1c 3e 6a 00 6a 00 ff 15 ?? ?? ?? ?? fe 04 3e 46 eb}  //weight: 1, accuracy: Low
        $x_1_3 = "vjxhUisa1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNV_2147852533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNV!MTB"
        threat_id = "2147852533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 0e 83 c4 ?? 0f b6 07 8b 74 24 ?? 03 c8 0f b6 c1 8a 84 04 ?? ?? ?? ?? 30 85 ?? ?? ?? ?? 45 81 fd ?? ?? ?? ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNV_2147852533_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNV!MTB"
        threat_id = "2147852533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f be 4d 02 c1 e1 10 0f be 45 01 c1 e0 08 33 c8 0f be 45 00 33 c1}  //weight: 10, accuracy: High
        $x_10_2 = {8b 44 24 24 8b 54 24 18 40 89 44 24 24 3b 44 24 3c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CBYZ_2147852539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CBYZ!MTB"
        threat_id = "2147852539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sAHUJIsgAYHUdgaeyuwef267" ascii //weight: 1
        $x_1_2 = "XSfrtuj6767" ascii //weight: 1
        $x_1_3 = "sIUHzuiABxr" ascii //weight: 1
        $x_1_4 = "6yrwerfgduyqwfdg3e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CBYA_2147852557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CBYA!MTB"
        threat_id = "2147852557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff b4 0e ?? ?? ?? ?? 8b 84 0e ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 8b 84 0e ?? ?? ?? ?? 03 c2 50 ff b5 9c fd ff ff ff 95 88 fd ff ff 0f b7 87 ?? ?? ?? ?? 8d 76 28 8b 95 94 fd ff ff 43 3b d8 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAX_2147852560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAX!MTB"
        threat_id = "2147852560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Helfrlo" ascii //weight: 1
        $x_1_2 = "Hwweello" ascii //weight: 1
        $x_1_3 = "Helfh6rlo" ascii //weight: 1
        $x_1_4 = "HwwzxAeello" ascii //weight: 1
        $x_1_5 = "Downloads\\Documents\\wroflmjk\\output.pdb" ascii //weight: 1
        $x_1_6 = "Downloads\\NewPublish\\kgawoh20p5v\\output.pdb" ascii //weight: 1
        $x_1_7 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c [0-32] 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_8 = ".UAZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Redline_GNW_2147852607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNW!MTB"
        threat_id = "2147852607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d7 80 b6 ?? ?? ?? ?? ?? 53 53 53 ff d7 80 86 ?? ?? ?? ?? ?? 53 53 53 ff d7 80 86 ?? ?? ?? ?? ?? 46 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNW_2147852607_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNW!MTB"
        threat_id = "2147852607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c1 8d 0c 2e 33 c1 2b f8 8b d7 c1 e2 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 89 54 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNX_2147852608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNX!MTB"
        threat_id = "2147852608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 80 07 ?? 80 2f ?? f6 2f 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAY_2147852792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAY!MTB"
        threat_id = "2147852792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 54 24 24 8b c1 c1 e8 05 03 44 24 20 03 cb 33 c2 33 c1 2b f0 8b d6 c1 e2 04 81 3d [0-4] 8c 07 00 00 89 44 24 14 c7 05 [0-4] 00 00 00 00 89 54 24 0c 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 14 33 c7 31 44 24 0c 8b 44 24 0c 29 44 24 10 81 3d [0-4] 93 00 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNZ_2147852818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNZ!MTB"
        threat_id = "2147852818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 33 c0 f6 17 80 37 ?? 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNZ_2147852818_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNZ!MTB"
        threat_id = "2147852818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 34 ?? ?? ?? ?? 8b 4c 24 10 03 c2 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 30 04 19 43 3b dd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BHA_2147852842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BHA!MTB"
        threat_id = "2147852842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 d3 e8 8b 4d e4 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f0 8d 45 f0 e8 ?? ?? ?? ?? 8b 45 e0 31 45 fc 81 3d ?? ?? ?? ?? e6 09 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 dc 01 45 fc 8b 55 f8 8b 4d f4 8b c2 d3 e8 8d 34 17 81 c7 ?? ?? ?? ?? 03 45 d8 33 c6 31 45 fc 2b 5d fc ff 4d ec 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DAZ_2147852869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DAZ!MTB"
        threat_id = "2147852869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 44 24 14 8b 44 24 20 01 44 24 14 81 3d [0-4] 79 09 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 14 33 d7 31 54 24 0c 8b 44 24 0c 29 44 24 10 81 3d [0-4] 93 00 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = "rofivunomotoyasoyilonaw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_JAN_2147852901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.JAN!MTB"
        threat_id = "2147852901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b c6 33 d2 f7 75 10 8a 82 ?? ?? ?? ?? 32 c3 8b 55 08 0f b6 1c 16 8d 0c 18 88 0c 16 fe c9 88 0c 16 6a 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_HOM_2147853013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.HOM!MTB"
        threat_id = "2147853013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f0 8b 45 f8 8b f7 d3 ee 03 c7 89 45 e0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 e4 8b 45 e0 31 45 fc 81 3d ?? ?? ?? ?? e6 09 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 dc 01 45 fc 8b 45 f4 8b 4d f8 8d 14 01 8b 4d f0 d3 e8 03 45 ?? 33 c2 31 45 fc 2b 7d fc 8b 45 d4 29 45 f8 ff 4d ec 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMA_2147853071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMA!MTB"
        threat_id = "2147853071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 06 83 c4 ?? 0f b6 0f 03 c8 0f b6 c1 8b 8d ?? ?? ?? ?? 8a 84 05 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 8d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 8b 8d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMA_2147853071_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMA!MTB"
        threat_id = "2147853071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 45 db 03 45 dc 88 45 db 0f b6 4d db c1 f9 06 0f b6 55 db c1 e2 02 0b ca 88 4d db 0f b6 45 db 05 ?? ?? ?? ?? 88 45 db 0f b6 4d db f7 d9 88 4d db}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CBYB_2147853078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CBYB!MTB"
        threat_id = "2147853078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 75 10 8a 82 ?? ?? ?? ?? 32 c3 8b 55 08 0f b6 1c 16 8d 0c 18 88 0c 16 fe c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMB_2147853087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMB!MTB"
        threat_id = "2147853087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 33 db f6 17 80 37 ?? 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMC_2147853116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMC!MTB"
        threat_id = "2147853116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 f6 17 8b c0 80 07 ?? 80 2f ?? f6 2f 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAA_2147853154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAA!MTB"
        threat_id = "2147853154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 33 c0 33 db f6 17 80 2f ?? 80 07 ?? f6 2f 47 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 08 33 c0 33 db f6 17 80 37 ?? 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CBYD_2147853402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CBYD!MTB"
        threat_id = "2147853402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 50 b8 ?? ?? ?? ?? 83 c0 21 b9 60 01 00 00 42 e2 fd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BHG_2147853495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BHG!MTB"
        threat_id = "2147853495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 54 24 20 03 c6 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d ?? ?? ?? ?? 8c 07 00 00 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 0c 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f3 31 74 24 0c 8b 44 24 0c 29 44 24 10 81 3d ?? ?? ?? ?? 93 00 00 00 75 10 68 58 40 40 00 8d 4c 24 74 51 ff 15 ?? ?? ?? ?? 8d 44 24 14 e8 ?? ?? ?? ?? ff 4c 24 18 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAB_2147888091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAB!MTB"
        threat_id = "2147888091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 03 c1 8b 4d 08 03 4d d0 88 01 8b 55 08 03 55 d0 8a 02 2c 01 8b 4d 08 03 4d d0 88 01}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 f7 75 10 0f b6 92 [0-4] 33 ca 88 4d cf}  //weight: 1, accuracy: Low
        $x_1_3 = "fjogSHgAsgSGHCvgevxweyudyue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YSF_2147888139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YSF!MTB"
        threat_id = "2147888139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 54 24 20 03 cd 33 d1 03 c6 33 d0 2b fa 8b cf c1 e1 04 81 3d ?? ?? ?? ?? 8c 07 00 00 c7 05 c8 48 2d 02 00 00 00 00 89 4c 24 10 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 81 3d ?? ?? ?? ?? 93 00 00 00 75 ?? 68 68 40 40 00 8d 44 24 74 50 ff 15 b8 10 40 00 8d 44 24 18 e8 ?? ?? ?? ?? ff 4c 24 1c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAC_2147888162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAC!MTB"
        threat_id = "2147888162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 81 3d [0-4] 93 00 00 00 75 10 68 [0-4] 8d 44 24 74 50 ff 15 [0-4] 8d 44 24 18 e8 [0-4] ff 4c 24 1c 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ea 05 03 54 24 20 03 cd 33 d1 03 c6 33 d0 2b fa 8b cf c1 e1 04 81 3d [0-4] 8c 07 00 00 c7 05 [0-4] 00 00 00 00 89 4c 24 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GME_2147888191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GME!MTB"
        threat_id = "2147888191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 08 8b c0 33 db f6 17 80 07 ?? 80 2f ?? f6 2f 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAD_2147888540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAD!MTB"
        threat_id = "2147888540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 ec 8b c6 8d 4d f8 e8 [0-4] 8b 45 cc 01 45 f8 8b 45 f4 8b 4d f0 03 c6 31 45 f8 d3 ee 03 75 dc 81 3d [0-4] 21 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ee 03 c7 89 45 d4 c7 05 [0-4] ee 3d ea f4 03 75 e0 8b 45 d4 31 45 f8 33 75 f8 81 3d [0-4] 13 02 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CBEA_2147888598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CBEA!MTB"
        threat_id = "2147888598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 80 07 ?? 80 2f ?? f6 2f 47 e2 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CBEB_2147888607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CBEB!MTB"
        threat_id = "2147888607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 4c 24 1c ?? ?? ?? ?? 83 c4 0c 69 db ?? ?? ?? ?? 83 c5 04 8b c1 c1 e8 18 33 c1 69 c0 ?? ?? ?? ?? 33 d8 89 44 24 10 83 ee 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAE_2147888661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAE!MTB"
        threat_id = "2147888661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 0f b6 84 1c 20 01 00 00 88 84 3c 20 01 00 00 88 8c 1c 20 01 00 00 0f b6 84 3c 20 01 00 00 03 c2 0f b6 c0 0f b6 84 04 20 01 00 00 30 86 [0-4] 46 81 fe [0-4] 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 8c 3c 20 01 00 00 0f b6 d1 03 da 81 e3 ff 00 00 80 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMG_2147888889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMG!MTB"
        threat_id = "2147888889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 f4 80 c9 7b 22 ff 80 cf 3a 0a ff c0 e7 1c 80 e4 5e 66 0b da b6 74 66 23 d0 66 c1 e2 34 80 e6 3d b5 0c 80 f4 68 c7 44 24 ?? ?? ?? ?? ?? 66 0b d8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMG_2147888889_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMG!MTB"
        threat_id = "2147888889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 d2 88 55 83 0f b6 45 83 05 ?? ?? ?? ?? 88 45 83 0f b6 4d 83 83 f1 5a 88 4d 83 0f b6 55 83 2b 55 84 88 55 83 0f b6 45 83 f7 d0 88 45 83 0f b6 4d 83 83 f1 67 88 4d 83}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMH_2147888999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMH!MTB"
        threat_id = "2147888999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 03 55 e4 8a 02 88 45 ee 0f b6 4d ee 8b 45 e4 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ef 68}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMH_2147888999_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMH!MTB"
        threat_id = "2147888999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 f3 33 db 8b f6 8b f3 f6 17 33 c6 8b de 8b c0 80 07 ?? 8b c6 8b c0 8b db 80 2f ?? 33 c6 33 c3 33 db f6 2f 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMH_2147888999_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMH!MTB"
        threat_id = "2147888999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Nomm" ascii //weight: 1
        $x_1_2 = "ZAtgrjtyujtyu" ascii //weight: 1
        $x_1_3 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c [0-32] 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAF_2147889088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAF!MTB"
        threat_id = "2147889088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 cd 33 d1 8b 4c 24 14 03 c8 33 d1 2b fa 8b d7 c1 e2 04 c7 05 [0-4] 00 00 00 00 89 54 24 10 8b 44 24 20 01 44 24 10 8b 5c 24 14 03 df 81 3d [0-4] be 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 18 8b 44 24 24 29 44 24 14 ff 4c 24 1c 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAG_2147889291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAG!MTB"
        threat_id = "2147889291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 33 d2 f7 75 10 0f b6 92 [0-4] 33 ca 88 4d ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 02 03 c1 8b 4d 08 03 4d f4 88 01 8b 55 08 03 55 f4 8a 02 2c 01 8b 4d 08 03 4d f4 88 01}  //weight: 1, accuracy: High
        $x_1_3 = "HJAGASYUIagUI8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WEB_2147889411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WEB!MTB"
        threat_id = "2147889411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f2 4b 88 55 87 0f b6 45 87 03 45 88 88 45 87 0f b6 4d 87 f7 d1 88 4d 87 0f b6 55 87 83 ea 2b 88 55 87 0f b6 45 87 33 45 88 88 45 87 8b 4d 88 8a 55 87 88 54 0d c8 e9 2e ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAH_2147889473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAH!MTB"
        threat_id = "2147889473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ximirohisaxikavibasuwesuc" ascii //weight: 1
        $x_1_2 = "jojuxaharucuzoyazuhobeto nizawaxagefawayagevopekekoze giraf" ascii //weight: 1
        $x_1_3 = "xikotuzazilug logac wavukejodukixuzeyemewocozoz" ascii //weight: 1
        $x_1_4 = "gusoluwurijekese" ascii //weight: 1
        $x_1_5 = "Yeyaket tafebova ximobudoragac" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_WEZ_2147889509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.WEZ!MTB"
        threat_id = "2147889509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f2 4b 88 55 a7 0f b6 45 a7 03 45 a8 88 45 a7 0f b6 4d a7 f7 d1 88 4d a7 0f b6 55 a7 83 ea 2b 88 55 a7 0f b6 45 a7 33 45 a8 88 45 a7 8b 4d a8 8a 55 a7 88 54 0d b8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMI_2147889513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMI!MTB"
        threat_id = "2147889513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 03 55 f4 8a 02 88 45 fe 0f b6 4d fe 8b 45 f4 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMI_2147889513_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMI!MTB"
        threat_id = "2147889513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 de 33 d8 2b fb 8b d7 c1 e2 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8d 1c 2f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAI_2147890039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAI!MTB"
        threat_id = "2147890039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xefucezipuki jorahisiz tit" wide //weight: 1
        $x_1_2 = "pulihawezafikopucugekuked" wide //weight: 1
        $x_1_3 = "7Kaxoja nenavepunece yidire vot jimedeyuy xivicaso hinas" wide //weight: 1
        $x_1_4 = "PDumakunox tag herawat lizuwu funubiluxovonin bunujecige bayatema jivavucijoluyel" wide //weight: 1
        $x_1_5 = "KXifafojux rod dagisuxuwayic hov gafaxuyet bubebaworeyasu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAJ_2147890042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAJ!MTB"
        threat_id = "2147890042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 d3 ee 89 45 ?? c7 05 [0-4] ee 3d ea f4 03 75 ?? 8b 45 ?? 31 45 ?? 33 75 ?? 81 3d [0-4] 13 02 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = "zuvebebucuzokonav pujetotanenovucivabokatek" ascii //weight: 1
        $x_1_3 = "fakiwamakibijabusocolobiledator" ascii //weight: 1
        $x_1_4 = "zwafibanabogucosowejusehifasi" wide //weight: 1
        $x_1_5 = "sunaruhubawuluyisapedodo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAK_2147890043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAK!MTB"
        threat_id = "2147890043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 33 b3 5a 42 e8}  //weight: 1, accuracy: High
        $x_1_2 = "dugiUsuAe" ascii //weight: 1
        $x_1_3 = {c1 d9 06 66 81 f3 3b 03 66 4f 66 bf aa 01 c1 e2 20 83 e6 73}  //weight: 1, accuracy: High
        $x_1_4 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c [0-32] 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAL_2147890045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAL!MTB"
        threat_id = "2147890045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 06 8b c6 f7 f3 8a 82 [0-4] 32 c1 8b 4d 08 88 04 0e e8 [0-4] 46 83 c4 08 3b f7 72}  //weight: 1, accuracy: Low
        $x_1_2 = "zaDFREHJTYU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AHSY_2147890051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AHSY!MTB"
        threat_id = "2147890051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c9 0b f4 d4 a0 91 8e 90 90 90 03 03 88 d3 a0 91 3f 05 fb f4 d4 a0 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCAR_2147890131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCAR!MTB"
        threat_id = "2147890131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 55 c7 c1 e2 ?? 0b ca 88 4d c7 0f b6 45 c7 33 45 c8 88 45 c7 0f b6 4d c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAM_2147890402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAM!MTB"
        threat_id = "2147890402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upynfwfsbfblnyrxzbkubetmxvfojtgxcubtqeahaujt" ascii //weight: 1
        $x_1_2 = "dpetkirqjywbkzueljqhlograqhdccuvrunxolwkuqkdqsgvzechesgbpglkxjqthg" ascii //weight: 1
        $x_1_3 = "ypmsfydivfriwzxwvraisoulxxncwdoxbdsvslhfvlfh" ascii //weight: 1
        $x_1_4 = "cuvmzzntxtjfqamdnifeodpktptmkchcqviqqctqaefkyfqighyjvnhqhawygyntiyta" ascii //weight: 1
        $x_1_5 = "docusbpdzqxqvaaeeffivgseacayejnqfdluquhb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAN_2147891255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAN!MTB"
        threat_id = "2147891255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe ff 50 e8 ?? ?? fe ff 80 34 1f}  //weight: 1, accuracy: Low
        $x_1_2 = {fe ff 50 e8 ?? ?? fe ff 80 04 1f ?? 83 c4 30 47 3b fe 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAO_2147891256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAO!MTB"
        threat_id = "2147891256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b c8 e8 ?? ?? 00 00 8b 55 08 03 55 fc 0f b6 02 83 c0 ?? 8b 4d 08 03 4d fc 88 01 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 03 55 fc 0f b6 02 35 ?? 00 00 00 8b 4d 08 03 4d fc 88 01 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAO_2147891256_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAO!MTB"
        threat_id = "2147891256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rewologiwexovavucobosoruzulahag" wide //weight: 1
        $x_1_2 = "yigewomoconagufofilej kemomohokebavedagelumezubowo nabojejusoyohecodez dol dulaku" wide //weight: 1
        $x_1_3 = "Ruluy xamujuhagofan ponizu wicupozigomazu hahusubakor" wide //weight: 1
        $x_1_4 = "vaguhesawi radaluxakeyih" wide //weight: 1
        $x_1_5 = "sutinisapaherikaxohegogepovov hiduwamiferuyahecemugiwaw wetekulol coginanijopizoloxuvadegacidawuxa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAP_2147891268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAP!MTB"
        threat_id = "2147891268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e1 06 0b c1 88 45 ee 0f b6 55 ee 81 ea 84 00 00 00 88 55 ee 0f b6 45 ee f7 d8 88 45 ee 0f b6 4d ee 03 4d e0 88 4d ee 8b 55 e0 8a 45 ee 88 44 15 b0 e9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 dc 83 c0 01 89 45 dc 81 7d dc 12 e3 f5 05 7d 0b 8b 4d d8 83 c1 01 89 4d d8 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCBD_2147891306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCBD!MTB"
        threat_id = "2147891306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 8b d8 33 de 80 2f ?? 8b db 33 f3 8b c3 80 07 ?? 8b f0 8b f0 33 de f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCBE_2147891307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCBE!MTB"
        threat_id = "2147891307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b de 33 f6 33 de 80 2f ?? 33 f6 33 d8 33 f3 80 07 ?? 33 f3 33 f0 33 c6 f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMJ_2147891356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMJ!MTB"
        threat_id = "2147891356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 2b f7 f7 e9 c1 ee de 66 c1 d8 35 66 f7 e8 81 f7 ed 02 00 00 66 c1 df 44 8b 75 c4 8b 4d dc 8b 55 d8 8b 46 24 8d 04 48 0f b7 0c 10 8b 46 1c 8d 04 88 8b 4d f8 8b 04 10 89 45 d4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMJ_2147891356_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMJ!MTB"
        threat_id = "2147891356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d1 e2 0b ca 88 8d ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 2d 98 00 00 00 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? f7 d1 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 81 c2 d8 00 00 00 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d0 88 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8a 95 ?? ?? ?? ?? 88 94 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CTI_2147891375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CTI!MTB"
        threat_id = "2147891375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e0 04 03 44 24 30 8d 34 0b c1 e9 05 83 3d ?? ?? ?? ?? 1b 89 44 24 14 8b e9 75 10 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 14 03 6c 24 28 c7 05 ?? ?? ?? ?? 00 00 00 00 33 ee 33 e8 2b fd 8b d7 c1 e2 04 89 54 24 14 8b 44 24 20 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 2c 3b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAQ_2147891376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAQ!MTB"
        threat_id = "2147891376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iifyrdfxrbuzddkpamcigksxhhyqmmvsuxanhingxbvintmzvbxbempphwqdfgptuyoiyfxj" ascii //weight: 1
        $x_1_2 = "seirgkxnxfxrtzunetozvhfbbpimyysxxpdvhwsdarbvcbzdhyxpuhyikqshwtaouwjdllecubiektjcjwmpp" ascii //weight: 1
        $x_1_3 = "monuhuxqoqetjrbyfzibxvmzbpeuwimujfvbzlddhhcylfgeuiet" ascii //weight: 1
        $x_1_4 = "cnufbvkymodzronslhlkyxiygzgmcwyciaxpcgiexyfuusgwbaq" ascii //weight: 1
        $x_1_5 = "furfrvlvbzeekqqfuevnzrstfitgatdjnzuhjauhrzjyksiyespld" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAR_2147891414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAR!MTB"
        threat_id = "2147891414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 fc 0f b6 02 35 ?? 00 00 00 8b 4d 08 03 4d fc 88 01 68}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 03 55 fc 0f b6 02 05 ?? 00 00 00 8b 4d 08 03 4d fc 88 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMF_2147891446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMF!MTB"
        threat_id = "2147891446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 d9 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d0 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? 83 f1 38 88 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 88 84 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAS_2147891461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAS!MTB"
        threat_id = "2147891461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b 4c 24 1c 8b c6 83 c4 08 f7 f5 8a 3c 0e 68}  //weight: 1, accuracy: High
        $x_1_2 = {32 c3 02 c7 88 04 0e e8}  //weight: 1, accuracy: High
        $x_1_3 = "fdiogiuAsdoiHYUAUAY87234" ascii //weight: 1
        $x_1_4 = "XScdyhjkujktyyt" ascii //weight: 1
        $x_1_5 = "uhgiyGAuyisua" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAT_2147891631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAT!MTB"
        threat_id = "2147891631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BuvuzitoVDices nar fusosihewah fitaxufarurode tudemenazasozo yada wijija rabunotaf kifidake yow" wide //weight: 1
        $x_1_2 = "Hidezimolaroti vobebebak" wide //weight: 1
        $x_1_3 = "Netesekom goronawe tepemoyizesenuz mipuxivopo lesot cokiretolu" wide //weight: 1
        $x_1_4 = "jWig bapinotalabaday vapum gegukeciruvopal rowowekoze kawotafozamemoc xihe sowukikidojo mikayamizatiz juzuc>Jevirozaveli" wide //weight: 1
        $x_1_5 = "VojiweeBacaculeborebix fupemav nunak yalabohepocudir jinuh jagevenuru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAU_2147891632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAU!MTB"
        threat_id = "2147891632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 80 b6 [0-5] 68}  //weight: 1, accuracy: Low
        $x_1_2 = "ujdishX*&ABh78373377" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_HUL_2147891685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.HUL!MTB"
        threat_id = "2147891685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 d3 ea 03 c3 89 45 f0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 d8 8b 45 f0 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 f0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c8 89 4d f0 8b 4d f4 d3 e8 03 45 d4 8b c8 8b 45 f0 31 45 fc 31 4d fc 2b 5d fc 8d 45 ec e8 ?? ?? ?? ?? ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GPAB_2147891694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GPAB!MTB"
        threat_id = "2147891694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb e8 ca 36 00 00 80 86 ?? ?? ?? ?? ?? 46 81 fe 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Soviet aristo baristo" ascii //weight: 1
        $x_1_3 = "uSGyuTYAStyA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAV_2147891781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAV!MTB"
        threat_id = "2147891781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 12 ff 74 24 ?? 8b cb e8 ?? ?? 00 00 8b cb e8 ?? ?? 00 00 80 b6}  //weight: 1, accuracy: Low
        $x_1_2 = "OnjhrebyuuXbhnAZuytt2vjchjsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAW_2147891784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAW!MTB"
        threat_id = "2147891784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d8 33 d8 8b c6 f6 17 8b db 33 c3 33 c6 80 07 ?? 33 c6 33 de 8b f6 80 2f ?? 8b f0 33 d8 33 f3 f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GPAC_2147891790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GPAC!MTB"
        threat_id = "2147891790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 fb 8a 1c 06 68}  //weight: 1, accuracy: High
        $x_1_2 = "fdiogiuAsdoiHYUAUAY87234" ascii //weight: 1
        $x_1_3 = "dijovhyuGSYYSyus" ascii //weight: 1
        $x_1_4 = "suih89Ah3" ascii //weight: 1
        $x_1_5 = "XScdyhjkujktyyt" ascii //weight: 1
        $x_1_6 = "sJBCsKJ2BJN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RG_2147891803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RG!MTB"
        threat_id = "2147891803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7c 24 3c 8d 5c 24 2c 8b f7 81 f6 6c 03 00 00 83 7c 24 40 10 0f 43 5c 24 2c 53 c1 ef 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RG_2147891803_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RG!MTB"
        threat_id = "2147891803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b 4d 08 8b c6 83 c4 08 f7 75 10 8a 3c 0e 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 32 c3 02 c7 88 04 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GPAD_2147891904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GPAD!MTB"
        threat_id = "2147891904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e8 ae 3b 00 00 80 b6 ?? ?? ?? ?? ?? e8 62 41 00 00 8b d8 8b 0b 8b 49 04 8b 4c 19 30 8b 79 04 8b cf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ARD_2147891941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ARD!MTB"
        threat_id = "2147891941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 44 d8 89 5d ec 8b 45 e8 83 c0 ff 89 45 e8 89 45 b0 8b 4d e4 83 d1 ff 89 4d e4 89 4d b4 8b 55 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ARD_2147891941_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ARD!MTB"
        threat_id = "2147891941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 c6 45 ?? 93 c6 45 ?? f4 c6 45 ?? 45 c6 45 ?? a5 c6 45 ?? b5 c6 45 ?? 44 c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 45 c6 45 ?? 15 c6 45 ?? a5 c6 45 ?? 84 c6 45 ?? 64 c6 45 ?? a5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GPAE_2147892028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GPAE!MTB"
        threat_id = "2147892028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2c 65 34 22 2c 73 34 2a 88 86}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GPAE_2147892028_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GPAE!MTB"
        threat_id = "2147892028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {18 00 00 80 b6 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b d8 8b 0b 8b 49 04}  //weight: 2, accuracy: Low
        $x_2_2 = {13 00 00 80 86 60 ?? ?? ?? ?? 46 81 fe 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMK_2147892081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMK!MTB"
        threat_id = "2147892081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 14 33 83 ff 0f ?? ?? 6a 00 ff d5 6a 2e 8d 44 24 10 6a 00 50 c7 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMK_2147892081_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMK!MTB"
        threat_id = "2147892081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 e2 89 c8 29 d0 d1 e8 01 d0 c1 e8 ?? 89 c2 c1 e2 ?? 29 c2 89 c8 29 d0 0f b6 84 05 ?? ?? ?? ?? 31 c3 89 da 8b 45 ?? 05 ?? ?? ?? ?? 88 10 83 45 ?? ?? 8b 45 ?? 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GML_2147892082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GML!MTB"
        threat_id = "2147892082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b ca 88 8d ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d0 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? f7 d2 88 95 ?? ?? ?? ?? 0f b6 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCBX_2147892153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCBX!MTB"
        threat_id = "2147892153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 33 c3 f6 2f 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMN_2147892230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMN!MTB"
        threat_id = "2147892230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 04 8d 44 24 20 55 50 e8 ?? ?? ?? ?? 69 4c 24 ?? 91 e9 d1 5b 83 c4 0c 69 db 91 e9 d1 5b 83 c5 04 8b c1 c1 e8 18 33 c1 69 c0 91 e9 d1 5b 33 d8 89 44 24 1c 83 ee}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMP_2147892244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMP!MTB"
        threat_id = "2147892244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d1 e2 0b ca 88 4d ?? 0f b6 45 ?? 33 45 ?? 88 45 ?? 0f b6 4d ?? 81 c1 ?? ?? ?? ?? 88 4d ?? 0f b6 55 ?? 83 f2 ?? 88 55 ?? 0f b6 45 ?? 03 45 ?? 88 45 ?? 0f b6 4d ?? f7 d1 88 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASAX_2147892277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASAX!MTB"
        threat_id = "2147892277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 80 ae [0-5] ff d7 80 86 [0-5] ff d7 80 b6 [0-5] ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d7 80 86 [0-5] ff d7 80 86 [0-5] ff d7 80 b6 [0-5] ff d7 80 86}  //weight: 1, accuracy: Low
        $x_4_3 = {ff d7 80 b6 [0-5] ff d7 80 86 [0-5] ff d7 80 86 [0-5] ff d7 80 86}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redline_CCCH_2147892559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCCH!MTB"
        threat_id = "2147892559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d3 80 04 3e ?? ff d3 80 34 3e ?? ff d3 80 04 3e ?? ff d3 80 34 3e ?? ff d3 80 04 3e ?? ff d3 80 34 3e ?? ff d3 80 04 3e ?? ff d3 80 34 3e ?? ff d3 80 04 3e ?? ff d3 80 04 3e ?? ff d3 80 04 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMQ_2147892744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMQ!MTB"
        threat_id = "2147892744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 34 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 34 2f ?? ff d6 80 04 2f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YAC_2147892762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YAC!MTB"
        threat_id = "2147892762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 64 a3 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff d7 80 b6 ?? ?? ?? ?? ?? ff d7 80 86 ?? ?? ?? ?? ?? ff d7 80 b6 ?? ?? ?? ?? ?? ff d7 80 86 ?? ?? ?? ?? ?? ff d7 80 86 ?? ?? ?? ?? ?? ff d7 80 86 ?? ?? ?? ?? ?? 46 81 fe 00 76 03 00 0f 82 ?? ?? ?? ?? 5f 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBA_2147892966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBA!MTB"
        threat_id = "2147892966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c1 e9 18 33 4d f4 89 4d f4 69 55 f4 ?? ?? ?? ?? 89 55 f4 69 45 fc ?? ?? ?? ?? 89 45 fc 8b 4d fc 33 4d f4 89 4d fc eb}  //weight: 4, accuracy: Low
        $x_1_2 = "Burn in ugly FIRE!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBB_2147892967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBB!MTB"
        threat_id = "2147892967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fekuzumoworafoyexavumexi" ascii //weight: 1
        $x_1_2 = "duwuzefifamowexesavesoxuz" ascii //weight: 1
        $x_1_3 = "botilupinozozijasowurukusawado" ascii //weight: 1
        $x_1_4 = "rixefavapuxorolikacapayizifiv" ascii //weight: 1
        $x_1_5 = "mupeyimipobamaxekoyagejowu" ascii //weight: 1
        $x_1_6 = "faliletixidepuhopife yanudojamoc bin roticesuxelihekigepid" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMR_2147892969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMR!MTB"
        threat_id = "2147892969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 55 c7 c1 e2 03 0b ca 88 4d c7 0f b6 45 c7 05 ?? ?? ?? ?? 88 45 c7 0f b6 4d c7 f7 d9 88 4d c7 0f b6 55 c7 83 ea 71 88 55 c7 8b 45 c8 8a 4d c7 88 4c 05 d8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBC_2147893099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBC!MTB"
        threat_id = "2147893099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 7d f4 8b 4d f8 8d 04 3b 31 45 fc d3 ef 03 7d e0 81 3d ?? ?? ?? ?? 21 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = "sewomexikijalodedeleve soyugoloraci yamazid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMS_2147893124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMS!MTB"
        threat_id = "2147893124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c8 0f be 04 bb 33 c1 69 c0 ?? ?? ?? ?? 33 f0 8b c6 c1 e8 ?? 33 c6}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 00 ff d6 80 34 2f ?? 6a 00 ff d6 80 04 2f ?? 6a 00 ff d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMT_2147893155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMT!MTB"
        threat_id = "2147893155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 f0 8b c6 c1 e8 0d 33 c6 69 c8 ?? ?? ?? ?? 8b c1 c1 e8 0f 33 c1 3b 44 24 48 ?? ?? 8b 44 24 10 8b 4c 24 38 83 c0 04 89 44 24 10 83 f9 10 ?? ?? 8b 54 24 24 41 8b c2 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMU_2147893223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMU!MTB"
        threat_id = "2147893223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 80 34 03 ?? ff d7 6a 00 ff d6 8b 44 24 ?? 6a 00 80 34 03}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c1 c1 e8 ?? 33 c1 69 c8 ?? ?? ?? ?? 33 f1 3b d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMV_2147893224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMV!MTB"
        threat_id = "2147893224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f7 d8 88 45 d7 0f b6 4d d7 f7 d1 88 4d d7 0f b6 55 d7 f7 da 88 55 d7 0f b6 45 d7 03 45 d8 88 45 d7 0f b6 4d d7 f7 d9 88 4d d7 0f b6 55 d7 2b 55 d8 88 55 d7 8b 45 d8 8a 4d d7 88 4c 05 e8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMW_2147893225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMW!MTB"
        threat_id = "2147893225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 40 50 e8 ?? ?? ?? ?? fe 0c 3e c7 04 24}  //weight: 10, accuracy: Low
        $x_10_2 = {33 d2 8b c6 f7 74 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8a ba ?? ?? ?? ?? 32 fb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBD_2147893368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBD!MTB"
        threat_id = "2147893368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 80 34 2f ?? ff d6 80 04 2f ?? ff d6 fe 0c 2f ff d6 80 04 2f ?? 47 3b fb 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GPAH_2147893369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GPAH!MTB"
        threat_id = "2147893369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b de 8b c3 33 f6 33 f6 33 c0 33 d8 33 f0 8b d8 f6 17 33 c6 8b de 8b f3 33 db 8b f0 8b f0 33 d8 8b c6 8b c3 80 2f ?? 33 f6 8b c6 8b f3 8b f0 33 c0 33 c6 8b f0 33 c0 33 c6 80 07 ?? 33 c3 33 f0 8b c3 33 d8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMZ_2147893386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMZ!MTB"
        threat_id = "2147893386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 00 80 34 03 ?? ff d7 6a 00 ff d6 8b 44 24 ?? 6a 00 6a 00 80 34 03 ?? ff d7 6a 00 ff d6 8b 44 24 ?? 6a 00 6a 00 80 04 03}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMZ_2147893386_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMZ!MTB"
        threat_id = "2147893386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b c1 88 45 ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 0f b6 45 ?? f7 d8 88 45 ?? 0f b6 4d ?? c1 f9 ?? 0f b6 55 ?? c1 e2 ?? 0b ca 88 4d ?? 0f b6 45 ?? 03 45 ?? 88 45 ?? 8b 4d ?? 8a 55 ?? 88 54 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMY_2147893387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMY!MTB"
        threat_id = "2147893387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 d8 88 45 ?? 0f b6 4d ?? f7 d1 88 4d ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 0f b6 45 ?? f7 d0 88 45 ?? 0f b6 4d ?? 03 4d ?? 88 4d ?? 8b 55 ?? 8a 45 ?? 88 44 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCCU_2147893412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCCU!MTB"
        threat_id = "2147893412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d8 33 de 33 f6 8b c6 33 d8 33 db 8b f0 8b f3 8b c6 f6 2f 47 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBE_2147893520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBE!MTB"
        threat_id = "2147893520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 80 34 1e ?? 6a 6f 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 04 1e ?? 6a 6f 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 04 1e ?? 83 c4 ?? 46 3b f7 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 83 f0 ?? 8b 4d 08 03 4d fc 88 01 6a 6f 68}  //weight: 1, accuracy: Low
        $x_2_3 = "DSuygac" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redline_ASBE_2147893520_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBE!MTB"
        threat_id = "2147893520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 f8 03 70 0c 8d 85 [0-4] 89 34 24 89 54 24 04 89 4c 24 08 89 44 24 0c ff 15}  //weight: 4, accuracy: Low
        $x_1_2 = "uoywxpyrziluhnqwneyrvkdnlfrizubacdhxhahomckbvuhlbedpocqlxfxnkwdvndjowchfrdxoofwwtctnzuag" ascii //weight: 1
        $x_1_3 = "lowrmnlsjuvntfdtlpecvdkzuhyspukpdrhxdsjt" ascii //weight: 1
        $x_1_4 = "ilyjhiypratpaiyykfpgfhjojhvur" ascii //weight: 1
        $x_1_5 = "viqrjzankobmtdwuesbrwnjgghxcjlmuwfhkqqwkrpgzmjslgdnon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redline_ASBF_2147893521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBF!MTB"
        threat_id = "2147893521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f5 31 74 24 10 8b 44 24 10 29 44 24 14 c7 44 24 18 00 00 00 00 8b 44 24 38 01 44 24 18 2b 5c 24 18 ff 4c 24 20 0f}  //weight: 1, accuracy: High
        $x_1_2 = "hibubuwayamivukidaweyavam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_BIR_2147893564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.BIR!MTB"
        threat_id = "2147893564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 55 f4 8b 4d f8 8b c2 d3 e8 8d 3c 13 03 45 e0 33 c7 31 45 fc 8b 4d fc 8d 45 ec e8 ?? ?? ?? ?? 81 c3 47 86 c8 61 ff 4d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_JAH_2147893886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.JAH!MTB"
        threat_id = "2147893886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 0c 10 c1 e1 08 33 4d f8 89 4d f8 ba 01 00 00 00 6b c2 00 8b 4d e8 0f be 14 01 33 55 f8 89 55 f8 69 45 f8 ?? ?? ?? ?? 89 45 f8 8b 4d fc 33 4d f8 89 4d fc 8b 55 fc c1 ea 0d 33 55 fc 89 55 fc 69 45 fc ?? ?? ?? ?? 89 45 fc 8b 4d fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCDA_2147894272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCDA!MTB"
        threat_id = "2147894272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 33 de ?? c0 33 ?? 8b f6 ?? ?? ?? ?? 8b c3 f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBG_2147894278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBG!MTB"
        threat_id = "2147894278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 80 34 1e ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 04 1e ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 04 1e ?? 83 c4 30 46 3b f7 0f}  //weight: 1, accuracy: Low
        $x_1_2 = "Halloween Beasts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GNO_2147894342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GNO!MTB"
        threat_id = "2147894342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 d2 88 55 ?? 0f b6 45 ?? f7 d8 88 45 ?? 0f b6 4d ?? 83 e9 ?? 88 4d ?? 0f b6 55 ?? f7 da 88 55 ?? 8b 45 ?? 8a 4d ?? 88 4c 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DV_2147894576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DV!MTB"
        threat_id = "2147894576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d db 0f b6 55 db c1 fa 03 0f b6 45 db c1 e0 05 0b d0 88 55 db 8b 4d dc 8a 55 db 88 54 0d e8 e9 a8 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MBKO_2147894636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MBKO!MTB"
        threat_id = "2147894636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 80 34 1e ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ff 80 04 1e ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff fe 0c 1e 83 c4 30 46 3b f7 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "Protocol of Mind" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBH_2147894889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBH!MTB"
        threat_id = "2147894889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 c1 e0 04 89 45 fc 8b 45 e0 01 45 fc 8b 45 f4 8b 4d f8 8d 14 03 31 55 fc d3 e8 03 45 e4 81 3d [0-4] 21 01 00 00 8b f8 75}  //weight: 1, accuracy: Low
        $x_1_2 = "vepiterotatacerewerecebetiw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBI_2147894890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBI!MTB"
        threat_id = "2147894890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mbmekbonvdbzemsrioxqeamwikhuabpsfzifrriojmicydnimtwyyruoawqxwra" ascii //weight: 1
        $x_1_2 = "lqvoiktjjkkrmlloqmjrzercgfzjzpyvqdfpslbazsaeugkynwxapbzrkzhgvwzhcvfbbeiimutzyyrffmqg" ascii //weight: 1
        $x_1_3 = "frzudqbgfopbwnjteklcikzewdnfimcltru" ascii //weight: 1
        $x_1_4 = "ytwnoqahmmloxffuyinpgdicfuzgatipxilitlprjwimhgfvvjquauxnewskxmnlmue" ascii //weight: 1
        $x_1_5 = "ebhrvmbtifxnpdofjfculvgdzdbzofiyeiicauwpwmqfzgsfxficxhvyd" ascii //weight: 1
        $x_1_6 = "zunupekuxiyuxaxujimixuyuzayefuse" ascii //weight: 1
        $x_1_7 = "raxoxititupunosotuv cejazotukecimaroz" ascii //weight: 1
        $x_1_8 = "jilarujigexige catak wolumuviduhiwimosuginejoniseramu" ascii //weight: 1
        $x_1_9 = "wegefubojudeceji wuvewafimamivodabamefarokeferobo" ascii //weight: 1
        $x_1_10 = "zegekosaxumamireyisuwuxuhezexi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Redline_ASBJ_2147894891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBJ!MTB"
        threat_id = "2147894891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d8 8b c3 8b c3 8b d8 80 07 ?? 8b d8 33 d8 8b f6 33 c3 8b db 33 de 8b de 33 f3 8b c0 80 2f ?? 33 f6 8b d8 8b c0 33 db 33 f0 8b d8 8b de 8b f3 8b d8 f6 2f 47 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DG_2147895040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DG!MTB"
        threat_id = "2147895040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 db 0f b6 4d db f7 d9 88 4d db 0f b6 55 db d1 fa 0f b6 45 db c1 e0 07 0b d0 88 55 db 8b 4d dc 8a 55 db 88 54 0d e8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DG_2147895040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DG!MTB"
        threat_id = "2147895040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d db 0f b6 55 db f7 da 88 55 db 0f b6 45 db c1 f8 06 0f b6 4d db c1 e1 02 0b c1 88 45 db 0f b6 55 db f7 da 88 55 db 0f b6 45 db f7 d0 88 45 db 0f b6 4d db 83 e9 28 88 4d db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBK_2147895160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBK!MTB"
        threat_id = "2147895160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 de 33 f6 33 f3 8b d8 33 f0 8b c3 33 d8 8b f6 f6 2f 47 e2}  //weight: 1, accuracy: High
        $x_1_2 = "sohvyoptytweilwefekafnfsrqligpknwqwdagtuiurswgonzfpcureqw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBL_2147895216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBL!MTB"
        threat_id = "2147895216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 80 34 2f ?? ff d6 80 04 2f ?? ff d6 80 2c 2f ?? ff d6 80 04 2f ?? 47 3b fb 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "warning is the identify" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DH_2147895239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DH!MTB"
        threat_id = "2147895239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 db 0f b6 55 db f7 da 88 55 db 0f b6 45 db d1 f8 0f b6 4d db c1 e1 07 0b c1 88 45 db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db 83 c0 69 88 45 db 8b 4d dc 8a 55 db 88 54 0d e8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBM_2147895461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBM!MTB"
        threat_id = "2147895461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c3 33 d8 8b d8 8b c6 8b c3 8b c3 33 f3 80 07 ?? 33 de 8b de 8b db 8b c6 33 c6 33 de 8b de 33 db 33 c0 f6 2f 47 e2}  //weight: 5, accuracy: Low
        $x_5_2 = {33 d8 33 f6 8b db 8b de 8b de 8b db 8b f6 8b c6 80 07 ?? 33 f3 33 de 33 f6 33 f3 8b db 8b f3 8b f6 8b f6 8b c3 f6 2f 47 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_ASBM_2147895461_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBM!MTB"
        threat_id = "2147895461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hqxgqbsaffrgikvvtvadaqqbjabrcgsssaknhxyyzmvgnyws" ascii //weight: 1
        $x_1_2 = "rmipumsdjwxufuxtxdnpxtheqrlnbmjaifwqmzdnsjmtjwbnussrvdxuvdo" ascii //weight: 1
        $x_1_3 = "iinbvuztfrjaczkjjspxdvtagydfmbigjirpfhswsvoncnlyivucqlcibhbfvhwzicnsgypfxn" ascii //weight: 1
        $x_1_4 = "ymmmyqbvtlnxqtnrmludkohoodvxheagroabigztfhnvysuiemnwyapnomkcuunt" ascii //weight: 1
        $x_1_5 = "swiqzwjqkmnkeplskejvwsjzmswdzfrdyoirnsydnroqnhwbhaehqwoqeuulryte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DI_2147895613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DI!MTB"
        threat_id = "2147895613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 55 db 0f b6 45 db 83 c0 7c 88 45 db 0f b6 4d db c1 f9 03 0f b6 55 db c1 e2 05 0b ca 88 4d db 0f b6 45 db 05 cd 00 00 00 88 45 db 8b 4d dc 8a 55 db 88 54 0d e8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASBN_2147895628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBN!MTB"
        threat_id = "2147895628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 de 8b c6 8b d8 80 2f ?? 8b c3 8b de 8b f6 8b f0 33 de 33 f3 33 f6 33 c6 33 c6 80 07 ?? 8b d8 33 d8 33 f0 33 de 33 f6 8b f0 33 c6 8b f3 8b c6 f6 2f 47 e2}  //weight: 5, accuracy: Low
        $x_5_2 = {33 f3 8b f6 80 2f ?? 33 de 8b db 8b c0 33 d8 8b c0 33 de 33 db 33 f6 33 f3 80 07 ?? 8b c6 33 de 33 c0 8b d8 8b d8 33 d8 33 c6 33 c3 8b c0 f6 2f 47 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_ASBO_2147895709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASBO!MTB"
        threat_id = "2147895709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 45 f4 8b 4d f8 8d 14 07 d3 e8 03 c3 33 c2 31 45 fc 8b 45 fc 29 45 f0 81 c7 47 86 c8 61 ff 4d e8 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {81 00 e1 34 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMAB_2147895913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMAB!MTB"
        threat_id = "2147895913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 4d db c1 f9 05 0f b6 55 db c1 e2 03 0b ca 88 4d db 0f b6 45 db 03 45 dc 88 45 db 0f b6 4d db f7 d1 88 4d db 0f b6 55 db c1 fa 06 0f b6 45 db c1 e0 02 0b d0 88 55 db}  //weight: 1, accuracy: High
        $x_1_2 = {33 c6 f6 2f 47 e2 ab 5f 5e 5b 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YTB_2147895917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YTB!MTB"
        threat_id = "2147895917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 08 81 f2 9d 00 00 00 88 14 08 31 c0 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 04 8b 45 08 8b 4d fc 0f b6 14 08 81 f2 89 00 00 00 88 14 08 31 c0 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 04 8b 45 08 8b 4d fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBO_2147896110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBO!MTB"
        threat_id = "2147896110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a1 60 7b 58 00 80 34 38 8e 81 3d ?? ?? ?? ?? 1b 0e 00 00 8b 1d ?? ?? ?? ?? 75 ?? 8d 84 24 ?? ?? ?? ?? 50 56}  //weight: 10, accuracy: Low
        $x_1_2 = "GODECIKOJI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GBR_2147896111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GBR!MTB"
        threat_id = "2147896111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 31 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb}  //weight: 10, accuracy: High
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMAC_2147896240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMAC!MTB"
        threat_id = "2147896240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 db 0f b6 4d db 81 c1 ?? ?? ?? ?? 88 4d db 0f b6 55 db c1 fa 07 0f b6 45 db d1 e0 0b d0 88 55 db 0f b6 4d db f7 d9 88 4d db 0f b6 55 db 2b 55 dc 88 55 db 0f b6 45 db f7 d8 88 45 db 0f b6 4d db f7 d1 88 4d db 8b 55 dc 8a 45 db 88 44 15 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GPAF_2147896248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GPAF!MTB"
        threat_id = "2147896248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 df 33 d8 2b f3 8b d6 c1 e2 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GAT_2147896438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GAT!MTB"
        threat_id = "2147896438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 f0 33 f3 8b f6 33 f0 8b f6 8b de 8b de 33 f6 33 c6 80 07 87 8b c6 8b c0 8b db 8b f0 33 c0 8b f0 8b c0 8b c0 8b de 80 2f 54 8b de 33 db 8b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DY_2147896776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DY!MTB"
        threat_id = "2147896776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 55 db 0f b6 45 db c1 f8 03 0f b6 4d db c1 e1 05 0b c1 88 45 db 0f b6 55 db 81 ea a7 00 00 00 88 55 db 0f b6 45 db f7 d8 88 45 db 0f b6 4d db 81 e9 eb 00 00 00 88 4d db 8b 55 dc 8a 45 db 88 44 15 e8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MBFA_2147896895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MBFA!MTB"
        threat_id = "2147896895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 04 8b 45 08 8b 4d fc 0f b6 14 08 81 f2 ?? ?? ?? ?? 88 14 08 8d 0d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 0c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 67 00 00 64 6a 68 62 63 79 68 75 79 73 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GPAI_2147896898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GPAI!MTB"
        threat_id = "2147896898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 45 fc 33 55 fc 81 3d}  //weight: 2, accuracy: High
        $x_2_2 = "bexominayunaciyihogucutejefif" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GMX_2147896953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GMX!MTB"
        threat_id = "2147896953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 04 8b 45 08 8b 4d fc 0f b6 14 08 83 f2 ?? 88 14 08 8d 0d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 0c 24 89 44 24 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DC_2147897300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DC!MTB"
        threat_id = "2147897300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 80 b6 00 c0 ?? ?? ?? 6a 00 ff d7 80 86 00 c0 ?? ?? ?? 6a 00 ff d7 80 86 00 c0 ?? ?? ?? 6a 00 ff d7 80 b6 00 c0 ?? ?? ?? 6a 00 ff d7 80 86 00 c0 ?? ?? ?? 6a 00 ff d7 80 86 00 c0 ?? ?? ?? 6a 00 ff d7 80 86 00 c0 ?? ?? ?? 6a 00 ff d7 80 86 00 c0 ?? ?? ?? 6a 00 ff d7 80 b6 00 c0 ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72 94}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ANI_2147897503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ANI!MTB"
        threat_id = "2147897503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d2 88 55 a3 0f b6 45 a3 35 8d 00 00 00 88 45 a3 0f b6 4d a3 83 e9 58 88 4d a3 0f b6 55 a3 33 55 a4 88 55 a3 0f b6 45 a3 05 a7 00 00 00 88 45 a3 0f b6 4d a3 33 4d a4 88 4d a3 0f b6 55 a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCER_2147897693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCER!MTB"
        threat_id = "2147897693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 0f be 06 33 c1 69 c0 ?? ?? ?? ?? 33 f8 8b 6c 24 ?? 8b c7 c1 e8 ?? 33 c7 69 c0 ?? ?? ?? ?? 8b c8 c1 e9 0f 33 c8 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_DK_2147898307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.DK!MTB"
        threat_id = "2147898307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d db 0f b6 55 db f7 da 88 55 db 0f b6 45 db 2b 45 dc 88 45 db 0f b6 4d db c1 f9 06 0f b6 55 db c1 e2 02 0b ca 88 4d db 0f b6 45 db 2b 45 dc 88 45 db 8b 4d dc 8a 55 db 88 54 0d e8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GPAJ_2147898314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GPAJ!MTB"
        threat_id = "2147898314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {f7 d1 88 4d db 0f b6 55 db f7 da 88 55 db 0f b6 45 db 2b 45 dc 88 45 db 0f b6 4d db c1 f9 06}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCFG_2147898956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCFG!MTB"
        threat_id = "2147898956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fkwuuyikedqufurkblvaqbnxantrblgoeztsnfixwbjalmsrfcfvcjrhptsyjafjahmxd" ascii //weight: 1
        $x_1_2 = "wjvttmbacvemgiuuladucmeqcnjbatyhojwdiufruyjpgjydjajzphqd" ascii //weight: 1
        $x_1_3 = "hofgqlzyejghuujqcgkevocumvfniehlqojyjzjxscgwbtipxznc" ascii //weight: 1
        $x_1_4 = "vlwwfdzgtjojqwawcsrnfmijbeyibaegitarubcddiyvrf" ascii //weight: 1
        $x_1_5 = "uxhmqhmyyvguaahngwqwpulpjibechvvohsygbdqvdeifqtyoksnyztamtjdcdwrsg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCFI_2147899091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCFI!MTB"
        threat_id = "2147899091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 e8 61 c6 45 e9 43 c6 45 ea f8 c6 45 eb 19 c6 45 ec 37 c6 45 ed e2 c6 45 ee 0d c6 45 ef a0 c6 45 f0 39 c6 45 f1 2f c6 45 f2 2d c6 45 f3 53 c6 45 f4 f2 c6 45 f5 29 c6 45 f6 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_VD_2147899197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.VD!MTB"
        threat_id = "2147899197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 db 0f b6 4d db f7 d9 88 4d db 0f b6 55 db 83 ea 49 88 55 db 0f b6 45 db f7 d8 88 45 db 0f b6 4d db f7 d1 88 4d db 8b 55 dc 8a 45 db 88 44 15 e8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCFJ_2147899211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCFJ!MTB"
        threat_id = "2147899211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 ff 15 ?? ?? ?? 00 c7 45 fc ?? ?? ?? ?? 8b 45 fc 50 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 40 8b 0d ?? ?? ?? ?? 51 68 ?? ?? ?? ?? ff 55 ?? 89 45 ?? 8b 15 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GAF_2147899584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GAF!MTB"
        threat_id = "2147899584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 d8 88 45 ?? 0f b6 4d ?? 83 e9 ?? 88 4d ?? 0f b6 55 ?? f7 da 88 55 ?? 0f b6 45 ?? d1 f8 0f b6 4d ?? c1 e1 ?? 0b c1 88 45 ?? 0f b6 55 ?? 2b 55 ?? 88 55 ?? 8b 45 ?? 8a 4d ?? 88 4c 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RV_2147899620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RV!MTB"
        threat_id = "2147899620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 8b f7 d3 ee 8d 04 3b 89 45 f0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 d8 8b 45 f0 31 45 fc 81 3d ?? ?? ?? ?? e6 09 00 00 75 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_CCGA_2147900044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCGA!MTB"
        threat_id = "2147900044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f4 01 f6 d4 d0 cc 8a 04 33 32 c4 32 07 88 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASCB_2147900236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASCB!MTB"
        threat_id = "2147900236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 80 34 1e ?? 83 c4 ?? 46 3b f7 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 80 04 1e ?? 68 ?? ?? ?? 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_KAC_2147900310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.KAC!MTB"
        threat_id = "2147900310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c2 d3 e8 8b 4d ?? 03 45 ?? 33 45 ?? 33 c8 8d 45}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_RC_2147901065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.RC!MTB"
        threat_id = "2147901065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 e4 50 6a 40 8b 0d 0c 30 41 00 51 68 ?? 14 40 00 ff 55 f8 89 45 e0 5f 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MZ_2147901761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MZ!MTB"
        threat_id = "2147901761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 8b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2 ab}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 08 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_CCHF_2147901779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.CCHF!MTB"
        threat_id = "2147901779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 8b 85 ?? ff ff ff 8b 48 ?? 51 8b 95 ?? fe ff ff 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MY_2147901936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MY!MTB"
        threat_id = "2147901936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2 ab}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 08 89 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Redline_GZF_2147902536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GZF!MTB"
        threat_id = "2147902536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d7 8d 04 3b d3 ea 89 45 ?? 8b 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_NII_2147903211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.NII!MTB"
        threat_id = "2147903211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 03 45 d0 89 45 f4 8b 45 e4 31 45 ?? 8b 45 fc 33 45 f4 2b f8 89 45 fc 89 7d e8 8b 45 cc 29 45 f8 ff 4d e0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMBE_2147903482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMBE!MTB"
        threat_id = "2147903482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e8 8b 7d [0-21] f6 17 [0-25] 80 07 [0-15] 80 2f [0-21] f6 2f 47 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_TNM_2147903550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.TNM!MTB"
        threat_id = "2147903550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 f0 31 c0 80 2f ?? 31 f3 31 de 89 db 89 c0 31 f6 89 f0 80 07 ?? 89 de 89 c6 89 f6 31 d8 89 c6 31 c3 31 f0 89 f6 31 f0 f6 2f 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MJ_2147905282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MJ!MTB"
        threat_id = "2147905282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 80 2f ?? 80 07 ?? f6 2f 47 e2 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASCC_2147905862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASCC!MTB"
        threat_id = "2147905862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yyrgapdzcdexxwlftulkqqyjhrga" ascii //weight: 1
        $x_1_2 = "kfbtjgyjpniwhsaxuxtibidsqzqggajslombokafqmothnufxvbqtarudktzanzylozwol" ascii //weight: 1
        $x_1_3 = "cawqqwckzitymffzjezxti" ascii //weight: 1
        $x_1_4 = "vsqdxuzezfmxisgegjfeahoqgkbjhuf" ascii //weight: 1
        $x_1_5 = "fytmujljovalyiiofuqfplgxortqgbmwpiythmb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMMH_2147907976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMMH!MTB"
        threat_id = "2147907976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 59 8b 4c 24 ?? 0f b6 c0 8a 44 04 ?? 30 81 ?? ?? ?? ?? 41 89 4c 24 ?? 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MQW_2147909041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MQW!MTB"
        threat_id = "2147909041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 3c 44 03 c6 0f b6 c0 59 8a 44 04 40 30 85 ?? ?? ?? ?? 45 81 fd ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_YUB_2147909377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.YUB!MTB"
        threat_id = "2147909377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 8b 4c 24 10 03 c6 0f b6 c0 8a 44 04 ?? 30 04 29 45 3b ac 24 20 02 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GXN_2147909438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GXN!MTB"
        threat_id = "2147909438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 8b 7c 24 ?? 39 74 24 ?? ?? ?? 80 34 37 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8a 04 37 2c ?? 34 ?? 04 ?? 34 ?? 2c ?? 34 ?? 2c ?? 34 ?? 88 04 37 46 3b 74 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GXO_2147909535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GXO!MTB"
        threat_id = "2147909535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 78 38 42 45 ?? 29 45 ?? 4b 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_GXQ_2147909798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.GXQ!MTB"
        threat_id = "2147909798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 04 37 34 ?? 2c ?? 6a 00 88 04 37 ff 15 ?? ?? ?? ?? 8a 04 37 2c ?? 34 ?? 04 ?? 34 ?? 2c ?? 34 ?? 2c ?? 34 ?? 88 04 37 46 3b 74 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MQQ_2147909926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MQQ!MTB"
        threat_id = "2147909926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c0 59 8a 44 04 ?? 30 85 ?? ?? ?? ?? 45 81 fd ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMAE_2147910201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMAE!MTB"
        threat_id = "2147910201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 8d 4c 24 ?? 8a 44 04 ?? 30 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 74 24 ?? 45 81 fd ?? ?? ?? 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MQZ_2147910389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MQZ!MTB"
        threat_id = "2147910389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 c8 fd ff ff 8b 9d cc fd ff ff 8a 84 05 f8 fe ff ff 30 03 43 89 9d cc fd ff ff 81 fb ?? ?? ?? ?? 7d 11 8b 9d c4 fd ff ff 8b b5 c0 fd ff ff e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASCD_2147910584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASCD!MTB"
        threat_id = "2147910584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 84 15 ?? ?? ff ff 8b 4d 08 03 8d ?? ?? ff ff 0f b6 11 33 d0 8b 45 08 03 85 ?? ?? ff ff 88 10 e9}  //weight: 4, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 68 ac 04 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MQE_2147910710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MQE!MTB"
        threat_id = "2147910710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 8c 8b 4d 88 8b 7d 94 8a 84 05 ?? ?? ?? ?? 30 04 39 8b 4d d4 83 f9 0f 76}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MWE_2147910987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MWE!MTB"
        threat_id = "2147910987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 18 8d 4c 24 40 8a 44 04 58 30 87 ?? ?? ?? ?? e8 ?? ?? ?? ?? 47 81 ff ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MQA_2147911103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MQA!MTB"
        threat_id = "2147911103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 84 05 c0 00 00 00 30 04 39 47 89 7d ?? 3b bd ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMMG_2147911466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMMG!MTB"
        threat_id = "2147911466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 59 59 8b 4c 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 29 8d 4c 24 ?? e8 ?? ?? ?? ?? 45 3b ac 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MRA_2147911699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MRA!MTB"
        threat_id = "2147911699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 3c ?? 03 c6 59 59 8b 4c 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 29 45 3b ac 24 ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MRB_2147911793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MRB!MTB"
        threat_id = "2147911793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 2c ?? 03 c6 0f b6 c0 8a 44 04 ?? 30 87 ?? ?? ?? ?? 85 c9 74}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 47 81 ff ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MRC_2147911929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MRC!MTB"
        threat_id = "2147911929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 03 8d ?? ?? ?? ?? 0f b6 11 33 d0 8b 45 08 03 85 ?? ?? ?? ?? 88 10 8d 8d}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMMI_2147912073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMMI!MTB"
        threat_id = "2147912073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 2c ?? 03 c6 0f b6 c0 0f b6 44 04 ?? 30 04 3a 8b 54 24 ?? 85 d2 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MRD_2147912218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MRD!MTB"
        threat_id = "2147912218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 14 8a 44 14 ?? 88 44 0c ?? 88 5c 14 ?? 0f b6 44 0c ?? 8b 5c 24 ?? 03 c7 0f b6 c0 8a 44 04 ?? 30 83 ?? ?? ?? ?? 8b 44 24 ?? 2b c6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MRF_2147912691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MRF!MTB"
        threat_id = "2147912691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 2c ?? 83 c4 ?? 03 44 24 ?? 8b 4c 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 0f 8b 44 24 ?? 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MRG_2147912960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MRG!MTB"
        threat_id = "2147912960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 94 0d ?? ?? ff ff 8b 45 08 03 85 ?? ?? ff ff 0f b6 08 33 ca 8b 55 08 03 95 ?? ?? ff ff 88 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMAD_2147913216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMAD!MTB"
        threat_id = "2147913216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 14 ?? 03 44 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 0e 46 3b f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MZQ_2147913473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MZQ!MTB"
        threat_id = "2147913473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 3c ?? 03 c6 0f b6 c0 0f b6 44 04 ?? 30 85 ?? ?? ?? ?? 45 81 fd ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMAG_2147913548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMAG!MTB"
        threat_id = "2147913548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 3c ?? 83 c4 ?? 03 c6 0f b6 c0 0f b6 44 04 ?? 30 85 ?? ?? ?? ?? 45 81 fd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMAI_2147914354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMAI!MTB"
        threat_id = "2147914354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 86 0f b6 04 07 30 04 11 8b 4c 24 ?? 83 f9 0f 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MBV_2147915032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MBV!MTB"
        threat_id = "2147915032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 03 8b 0c 87 8a 04 06 30 81}  //weight: 1, accuracy: High
        $x_1_2 = {47 89 7c 24 14 81 ff ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMAJ_2147915533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMAJ!MTB"
        threat_id = "2147915533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 6a 03 8b 0c 81 8a 04 3b 30 04 11 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_IIB_2147915931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.IIB!MTB"
        threat_id = "2147915931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 4e 34 dc 59 88 86 ?? ?? ?? ?? e8 07 c0 f7 ff 50 e8 cf bf f7 ff 8a 86 ?? ?? ?? ?? 34 ac c7 04 24 ?? ?? ?? ?? 2c 65 34 22 2c 73 88 86 ?? ?? ?? ?? e8 a1 eb fc ff 30 86 ?? ?? ?? ?? 46 59 81 fe ac 04 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMAN_2147915968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMAN!MTB"
        threat_id = "2147915968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 98 8b 44 24 ?? 8b 48 ?? 8b 44 24 ?? 8a 04 01 8b 4c 24 ?? 30 04 0a 8d 4c 24 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_MAE_2147916276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.MAE!MTB"
        threat_id = "2147916276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 81 8b 44 24 ?? 8a 04 01 8d 4c ?? 24 30 06}  //weight: 1, accuracy: Low
        $x_1_2 = {47 89 7c 24 ?? 3b bc 24 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AMAS_2147916655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AMAS!MTB"
        threat_id = "2147916655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 56 89 74 24 ?? e8 ?? ?? ?? ?? 8d 4c 24 ?? ff 30 e8 ?? ?? ?? ?? 8d 4c 24 ?? 8a 00 30 07 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_ASCE_2147916972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.ASCE!MTB"
        threat_id = "2147916972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 04 01 8d 4c 24 ?? 30 04 2a e8 ?? ?? ?? ff 8d 4c 24 ?? e8 ?? ?? ?? ff 8d 4c 24 ?? e8 ?? ?? ?? ff 8d 4c 24 ?? e8 ?? ?? ?? ff 8b 7c 24 ?? 46 89 74 24 ?? 3b b4 24}  //weight: 4, accuracy: Low
        $x_1_2 = "Asucjhudaujsa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_FZ_2147920044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.FZ!MTB"
        threat_id = "2147920044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 d0 08 d4 08 c1 24 eb 08 c6 f6 d1 30 e6 b8 [0-4] 08 f1 88 0c 2f 3d [0-4] 0f 8e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_PARD_2147931477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.PARD!MTB"
        threat_id = "2147931477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f be bc 15 ?? ?? ?? ?? 99 f7 ff 0f af 45 ?? 2b f0 0f b6 44 35 ?? 33 c8 8b 55 ?? 03 55 ?? 88 0a eb}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redline_AC_2147945969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redline.AC!MTB"
        threat_id = "2147945969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 29 4a 5b cd 35 d5 84 17 f3 ?? 4c d1 44 ec a7 37 59 8a 68 a5 86 f0 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

