rule Trojan_Win32_RedlineStealer_RAP_2147794140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.RAP!MTB"
        threat_id = "2147794140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8b 4d d0 89 08 8b 55 08 8b 45 f4 89 42 04 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_XK_2147822236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.XK!MTB"
        threat_id = "2147822236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d0 0f b6 00 0f be d8 c7 44 24 ?? ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f af d8 89 da 8b 4d ?? 8b 45 ?? 01 c8 8b 5d ?? 8b 4d ?? 01 d9 0f b6 09 31 ca 88 10 83 45 f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_XP_2147823126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.XP!MTB"
        threat_id = "2147823126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 55 f8 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 33 85 ?? ?? ?? ?? b9 ?? ?? ?? ?? f7 e1 89 85 ?? ?? ?? ?? e9 ?? ?? ?? ?? ba ?? ?? ?? ?? 39 95}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_XS_2147823634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.XS!MTB"
        threat_id = "2147823634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8b c6 f7 75 ?? 8a 0c 1a 30 0c 3e 46 3b 75 14 ?? ?? 5b 8b c7 5f 5e 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_XU_2147823940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.XU!MTB"
        threat_id = "2147823940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 ca 89 4c 24 ?? 89 6c 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 5c 24 ?? 81 44 24 ?? ?? ?? ?? ?? ff 4c 24 ?? 89 2d ?? ?? ?? ?? 89 5c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_UA_2147824198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.UA!MTB"
        threat_id = "2147824198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4c 24 0c 30 04 31 81 ff ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
        $x_10_2 = {b1 6c b0 6d 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 67 88 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_CM_2147824447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.CM!MTB"
        threat_id = "2147824447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 31 c9 89 e5 53 8b 5d ?? 3b 4d ?? ?? ?? 89 c8 31 d2 f7 75 ?? 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 30 04 0b 41 ?? ?? 5b 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_UF_2147825092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.UF!MTB"
        threat_id = "2147825092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c8 f7 e6 89 c8 c1 ea ?? 6b d2 ?? 29 d0 0f be 80 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 83 c1 ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_UG_2147825117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.UG!MTB"
        threat_id = "2147825117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d0 0f b6 00 0f be d8 c7 44 24 ?? ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f af d8 89 d9 8b 55 ?? 8b 45 ?? 01 d0 0f b6 00 89 c2 89 c8 89 d1 31 c1 8b 55 ?? 8b 45 ?? 01 d0 89 ca 88 10 83 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_BH_2147825879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.BH!MTB"
        threat_id = "2147825879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 89 44 24 14 8b 44 24 44 01 44 24 14 8b 44 24 10 33 44 24 1c 89 7c 24 30 89 44 24 10 89 44 24 4c 8b 44 24 4c 89 44 24 30 8b 44 24 14 31 44 24 30 8b 4c 24 30 89 4c 24 10 89 3d [0-4] 8b 44 24 10 29 44 24 18 81 44 24 2c 47 86 c8 61 4b 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {89 44 24 14 8b 4c 24 10 33 4c 24 1c 8b 44 24 14 03 c5 33 c1 83 3d [0-4] 0c c7 05 [0-4] ee 3d ea f4 89 4c 24 10 89 44 24 14 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_PSA_2147827198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.PSA!MTB"
        threat_id = "2147827198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 83 0d ?? ?? ?? ?? ff c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 e4 01 45 0c 8b 45 0c 33 45 f8 33 c8 89 4d ec 8b 45 ec}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_PSA_2147827198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.PSA!MTB"
        threat_id = "2147827198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 ea 05 03 55 e8 c1 e0 04 03 45 e4 89 4d f8 33 d0 33 d1 89 55 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 c7 89 45 f4 8b 45 08 03 45 f0 89 45 f8 8b 45 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_PSB_2147827906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.PSB!MTB"
        threat_id = "2147827906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b f8 c1 ef 05 03 7d e4 c1 e0 04 03 45 e0 89 4d f4 33 f8 33 f9 89 7d 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 45 dc 89 45 f0 8b 45 08 03 45 ec 89 45 f4 8b 45 08}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_AMAA_2147891397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.AMAA!MTB"
        threat_id = "2147891397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c1 cf 41 66 25 c0 01 f7 ef c1 e9 ab 66 81 f3 88 01 66 c1 d1 d3 66 42 81 ce 97 00 00 00 81 f3 41 02 00 00 66 f7 e2 66 42 66 0b f0 66 c1 c6 3d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_AK1_2147894676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.AK1!MTB"
        threat_id = "2147894676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 83 c0 01 89 45 fc 81 7d fc b2 f2 f5 05 7d 0b 8b 4d f8 83 c1 01 89 4d f8 eb e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_RPX_2147895022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.RPX!MTB"
        threat_id = "2147895022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f3 33 d8 8b c6 f6 17 8b f0 8b c0 33 de 33 c0 8b c6 33 f3 8b f3 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_RPX_2147895022_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.RPX!MTB"
        threat_id = "2147895022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 91 a4 00 00 00 83 c2 08 8b 75 cc 8d 4d 80 31 ff 89 34 24 89 54 24 04 89 4c 24 08 c7 44 24 0c 04 00 00 00 c7 44 24 10 00 00 00 00 ff d0 83 ec 14 8b 85 64 ff ff ff 8b 4d e0 8b 49 50 8b 55 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_AMBC_2147896686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.AMBC!MTB"
        threat_id = "2147896686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 04 8b 45 08 8b 4d fc 0f b6 14 08 [0-6] 88 14 08 31 c0 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 04 8b 45 08 8b 4d fc 0f b6 14 08 81 f2 ?? 00 00 00 88 14 08 31 c0 c7 04 24 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_GPA_2147896696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.GPA!MTB"
        threat_id = "2147896696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {33 c6 33 c0 8b f3 8b c6 33 de 80 2f ?? 33 d8 33 de 8b c3 33 db 8b c3 8b c6 33 d8 8b de 33 db f6 2f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_AMBZ_2147897747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.AMBZ!MTB"
        threat_id = "2147897747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 d0 88 45 db 0f b6 4d db c1 f9 06 0f b6 55 db c1 e2 02 0b ca 88 4d db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_PACE_2147897753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.PACE!MTB"
        threat_id = "2147897753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 45 db f7 d8 88 45 db 0f b6 4d db 2b 4d dc 88 4d db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db 2b 45 dc 88 45 db 0f b6 4d db c1 f9 02 0f b6 55 db c1 e2 06 0b ca 88 4d db 0f b6 45 db 2d ac ?? ?? ?? 88 45 db 0f b6 4d db f7 d9 88 4d db 0f b6 55 db 83 ea 7c 88 55 db 0f b6 45 db f7 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {88 45 db 0f b6 4d db 03 4d dc 88 4d db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db 2d e2 ?? ?? ?? 88 45 db 0f b6 4d db f7 d1 88 4d db 0f b6 55 db 83 c2 4f 88 55 db 0f b6 45 db d1 f8 0f b6 4d db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_AMBH_2147898097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.AMBH!MTB"
        threat_id = "2147898097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 d8 88 45 db 0f b6 4d db 03 4d dc 88 4d db 0f b6 55 db f7 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_AMBH_2147898097_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.AMBH!MTB"
        threat_id = "2147898097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d fc 83 c1 02 8b 45 f8 01 c8 89 45 f8 8b 45 f8 b9 04 00 00 00 99 f7 f9 83 fa 00 0f 95 c0 34 ?? a8 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_AMCA_2147898622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.AMCA!MTB"
        threat_id = "2147898622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 d0 88 45 db 0f b6 4d db c1 f9 07 0f b6 55 db d1 e2 0b ca 88 4d db 0f b6 45 db 2b 45 dc 88 45 db}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedlineStealer_Z_2147938091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedlineStealer.Z!MTB"
        threat_id = "2147938091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#+3;CScs" wide //weight: 1
        $x_1_2 = {68 10 84 2d 2c 71 ea 7e 2c 71 ea 7e 2c 71 ea 7e 32 23 7f 7e 3f 71 ea 7e 0b b7 91 7e 2b 71 ea 7e 2c 71 eb 7e 5c 71 ea 7e 32 23 6e 7e 1c 71 ea 7e 32 23 69 7e a2 71 ea 7e 32 23 7b 7e 2d 71 ea 7e}  //weight: 1, accuracy: High
        $x_1_3 = {83 ec 38 53 b0 d7 88 44 24 2b 88 44 24 2f b0 c1 88 44 24 30 88 44 24 31 88 44 24 33 55 56 8b f1 b8 0c 00 fe ff 2b c6 89 44 24 14 b8 0d 00 fe ff 2b c6 89 44 24 1c b8 02 00 fe ff 2b c6 89 44 24}  //weight: 1, accuracy: High
        $x_1_4 = "delete[]" ascii //weight: 1
        $x_1_5 = "constructor or from DllMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

