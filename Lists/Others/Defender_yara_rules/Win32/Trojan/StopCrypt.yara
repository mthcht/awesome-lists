rule Trojan_Win32_StopCrypt_AC_2147815582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.AC!MTB"
        threat_id = "2147815582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d a1 06 00 00 0f 84 [0-4] 83 f9 ?? 0f 84 [0-4] 40 3d 86 76 13 01 89 44 24 10 0f 8c}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_PAB_2147816402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.PAB!MTB"
        threat_id = "2147816402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 75 fc a1 ?? ?? ?? ?? 01 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 ?? ?? ?? ?? 88 0c 02 5e c9}  //weight: 2, accuracy: Low
        $x_1_2 = {55 8b ec 81 ec ?? ?? ?? ?? 56 33 f6 83 3d ?? ?? ?? ?? 37 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_StopCrypt_PAC_2147816409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.PAC!MTB"
        threat_id = "2147816409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 38 8b 0d ?? ?? ?? ?? 88 04 0f 83 3d ?? ?? ?? ?? 44 75 22}  //weight: 2, accuracy: Low
        $x_1_2 = {ee 3d ea f4 c7 85 ?? ?? ?? ?? 7e 1f 49 08 c7 85 ?? ?? ?? ?? 45 9e 40 23 c7 85 ?? ?? ?? ?? a8 84 66 54 c7 85 ?? ?? ?? ?? 90 8b 37 3f c7 85 ?? ?? ?? ?? dc 73 b8 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_StopCrypt_DB_2147818570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.DB!MTB"
        threat_id = "2147818570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 8c 06 3b 2d 0b 00 8b 15 [0-4] 88 0c 16 a1 [0-4] 83 f8 44 75 16}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 84 24 bc 01 00 00 e5 9a 40 22 c7 84 24 78 02 00 00 95 54 fe 1a c7 84 24 70 01 00 00 87 64 58 7c c7 84 24 48 01 00 00 47 cc 65 36 ff d7 81 fe aa dd 18 02 7f 0d 46 81 fe 76 24 ec 5a 0f 8c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_DX_2147819809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.DX!MTB"
        threat_id = "2147819809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c3 2b f8 89 7d e0 8b 45 d4 29 45 fc ff 4d e4 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 a4 2c 02 26 1e c7 45 6c fe 0b df 0e c7 45 ac b6 a9 2a 0e c7 45 e4 99 de 64 12 c7 45 08 31 08 38 76 c7 45 a8 13 56 26 0c}  //weight: 1, accuracy: High
        $x_1_3 = {81 fe aa b0 e7 00 7f 0d 46 81 fe 76 24 ec 5a 0f 8c}  //weight: 1, accuracy: High
        $x_1_4 = "worms.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_DY_2147820043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.DY!MTB"
        threat_id = "2147820043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b d8 89 5d e4 89 75 ec 8b 45 fc 01 45 ec 8b 45 e4 01 45 ec 8b 45 ec 89 45 f0 8b 4d e8 8b c3 d3 e8 89 45 f8 8b 45 d0 01 45 f8 8b f3 c1 e6 04 03 75 d8 33 75 f0 81 3d [0-8] 75 0b}  //weight: 2, accuracy: Low
        $x_1_2 = {81 84 24 94 02 00 00 e3 9b 81 29 81 ac 24 d8 00 00 00 90 97 0c 2e 81 84 24 64 01 00 00 6e 1d e0 05 81 84 24 40 02 00 00 8c a8 ce 53 81 84 24 8c 01 00 00 be d1 ac 2e 81 ac 24 64 01 00 00 62 46 5d 36 81 84 24 2c 02 00 00 e9 3a 71 34 81 84 24 d8 00 00 00 c6 08 dc 32 81 84 24 2c 02 00 00 17 62 f9 54}  //weight: 1, accuracy: High
        $x_1_3 = {81 ff aa b0 e7 00 7f 0d 47 81 ff 76 24 ec 5a 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_DC_2147821345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.DC!MTB"
        threat_id = "2147821345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f8 89 7c 24 2c c7 44 24 20 [0-4] 8b 44 24 10 01 44 24 20 8b 44 24 2c 01 44 24 20 8b 44 24 20 89 44 24 1c 8b 4c 24 24 8b d7 d3 ea 89 54 24 14 8b 44 24 3c 01 44 24 14 8b f7 c1 e6 04 03 74 24 40 33 74 24 1c 81 3d [0-8] 75}  //weight: 2, accuracy: Low
        $x_1_2 = {c7 44 24 48 a2 86 7a 5c c7 44 24 0c 6e b7 1b 45 c7 84 24 0c 01 00 00 af 55 a9 41 89 54 24 04 b8 [0-4] 01 44 24 04 8b 44 24 04 8a 04 30 88 04 0e 46 3b 35 [0-4] 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {81 fe 9d 94 30 00 7f 0d 46 81 fe 5a 5b 1b 02 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_DA_2147823176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.DA!MTB"
        threat_id = "2147823176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 6d d8 2f 62 16 14 81 45 e4 0f 07 b4 03 81 45 cc 93 b8 e8 1f 81 45 fc 58 6c e4 2f 81 45 c4 79 04 56 04 81 6d d4 26 88 9c 78 81 6d 98 98 5a a2 3b 81 45 b8 06 2f b1 78 81 45 cc 1c 73 a2 4a}  //weight: 2, accuracy: High
        $x_3_2 = {81 fb 91 25 00 00 74 0f 43 81 fb ce 94 3f 05 0f 8c}  //weight: 3, accuracy: High
        $x_3_3 = {81 ff 6e 27 87 01 7f 09 47 81 ff f6 ea 2b 33 7c a0}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_StopCrypt_RPT_2147823684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.RPT!MTB"
        threat_id = "2147823684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ce c1 e1 04 03 4d f0 8b c6 c1 e8 05 03 45 f4 8d 14 33 33 ca 33 c8 2b f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_RPS_2147828309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.RPS!MTB"
        threat_id = "2147828309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e2 33 f6 89 74 24 28 03 54 24 48 8b 44 24 10 01 44 24 28 8b 44 24 18 01 44 24 28 8b 44 24 28 89 44 24 1c 8b 44 24 18 8b 4c 24 20 d3 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_RH_2147828658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.RH!MTB"
        threat_id = "2147828658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 fc 02 00 00 00 83 45 fc 02 8b 4d fc 8b 45 0c d3 e0 8b 4d 08 89 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_AE_2147829589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.AE!MTB"
        threat_id = "2147829589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08}  //weight: 2, accuracy: High
        $x_2_2 = {c1 e1 04 03 4d e0 33 c1 33 45 fc 89 45 0c 8b 45 0c 01 05}  //weight: 2, accuracy: High
        $x_1_3 = {81 ff 6e 27 87 01 7f 0d 47 81 ff f6 ea 2b 33 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_PCA_2147831155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.PCA!MTB"
        threat_id = "2147831155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e8 05 03 45 e8 33 ce 33 c1 89 4d 08 89 45 f8 8b 45 f8 01 05 1c 55 8c 00 ff 75 f8 8d 45 f4 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = {01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_AF_2147831258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.AF!MTB"
        threat_id = "2147831258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 0c 37 c1 ee 05 03 75 ec 03 c3 33 c1 33 f0 89 45 0c 89 75 e8}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 0c 83 6d fc 04 90 01 45 fc 8b 45 08 8b 4d fc 31 08 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_RPL_2147832969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.RPL!MTB"
        threat_id = "2147832969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 e8 8b 45 e8 89 45 e0 8b 4d ec 8b c6 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 4d f8 33 4d e0 89 3d ?? ?? ?? ?? 31 4d f4 8b 45 f4 29 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_RPX_2147842323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.RPX!MTB"
        threat_id = "2147842323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d4 01 45 fc 89 5d f0 8b 45 e8 01 45 f0 8b 45 d0 90 01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b c7 d3 e8 03 45 cc 89 45 f8 8b 45 ec 31 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_RPX_2147842323_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.RPX!MTB"
        threat_id = "2147842323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 0c 8b 44 24 24 03 44 24 10 c7 05 ?? ?? ?? ?? 00 00 00 00 33 c6 33 c1 2b f8 89 44 24 10 8b c7 c1 e0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 28 01 44 24 0c 8b c7 c1 e8 05 8d 34 3b}  //weight: 1, accuracy: High
        $x_1_3 = {31 74 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StopCrypt_DLS_2147896908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StopCrypt.DLS!MTB"
        threat_id = "2147896908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 ea 8d 04 37 89 45 e8 c7 05 f8 b5 a9 02 ee 3d ea f4 03 55 d4 8b 45 e8 31 45 fc 33 55 fc 81 3d 60 c0 a9 02 13 02 00 00 89 55 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

