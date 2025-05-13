rule Trojan_Win32_Glupteba_A_2147717567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.A"
        threat_id = "2147717567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "botnet_t@bot@" ascii //weight: 1
        $x_2_2 = {73 65 72 76 65 72 2d 25 73 2e [0-10] 2e 72 75 3a 33 30 2c 73 65 72 76 65 72 2d 25 73 2e [0-10] 2e 72 75 3a 33 30 2c 73 65 72 76 65 72 2d 25 73 2e}  //weight: 2, accuracy: Low
        $x_1_3 = "Send stat info to" ascii //weight: 1
        $x_1_4 = "uptime=%d&downlink=%d&uplink=%d&id=%s&statpass=%s&version=%d&features=%d&guid=%s&comment=%s&p=%d&s=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_D_2147734519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.D!bit"
        threat_id = "2147734519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Eternalblue" ascii //weight: 1
        $x_1_2 = "attackFunc" ascii //weight: 1
        $x_1_3 = "cloudnet.exe" ascii //weight: 1
        $x_1_4 = "nadequalif.club" ascii //weight: 1
        $x_1_5 = "okonewacon.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Glupteba_DSK_2147744127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSK!MTB"
        threat_id = "2147744127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 24 16 08 5c 24 14 8a c2 24 fc 33 db c0 e0 04 08 44 24 15 81 3d ?? ?? ?? ?? 38 13 00 00 89 1d ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GM_2147749867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GM!MTB"
        threat_id = "2147749867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 7c 24 60 89 5c 24 14 81 f3 07 eb dd 13 81 6c 24 14 ?? ?? ?? ?? b8 41 e5 64 03 81 6c 24 14 ?? ?? ?? ?? 81 44 24 14 ?? ?? ?? ?? 8b 4c 24 14 8b 44 24 10 03 44 24 60 8b f7 d3 e7 c1 ee ?? 03 74 24 ?? 03 7c 24 ?? 33 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GA_2147749971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GA!MTB"
        threat_id = "2147749971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 1e 46 3b f7 [0-16] 81 ff 69 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GB_2147750064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GB!MTB"
        threat_id = "2147750064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 29 45 ?? 89 75 ?? 81 f3 07 eb dd 13 81 6d 30 ?? ?? ?? ?? b8 41 e5 64 03 81 6d 30 ?? ?? ?? ?? 81 45 30 ?? ?? ?? ?? 8b 55 ?? 8b 4d ?? 8b c2 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DHD_2147750085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DHD!MTB"
        threat_id = "2147750085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f8 8b 45 ?? d1 6d ?? 29 45 ?? ff 4d ?? 0f 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 61 01 00 00 5b 8b 45 ?? 8b 4d ?? 89 48 ?? 8b 4d ?? 89 38 5f 33 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DHE_2147750086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DHE!MTB"
        threat_id = "2147750086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 85 ff 7e ?? 81 ff ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c df}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 50 56 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? c1 ee 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b c6 25 ?? ?? ?? ?? 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DHF_2147750093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DHF!MTB"
        threat_id = "2147750093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 0c 00 7c 26 8b 55 ?? 03 55 ?? 0f be 1a e8 ?? ?? ?? ?? 0f b6 c0 33 d8 8b 4d ?? 03 4d ?? 88 19 8b 55 0c 83 ea 01 89 55 0c eb d4}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 b9 00 01 00 00 f7 f1 89 15 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 21 06 00 00 75 1f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DHI_2147750126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DHI!MTB"
        threat_id = "2147750126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ff 69 04 00 00 e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c d9}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ee 10 81 3d ?? ?? ?? ?? cf 12 00 00 8b 8c 24 ?? ?? ?? ?? 8b c6 5e 33 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DHJ_2147750127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DHJ!MTB"
        threat_id = "2147750127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b fe 7c 0b e8 ?? ?? ?? ?? 30 04 1f 4f 79 f5 8b 4d fc 5f 5e 33 cd}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 cb 03 c1 8b 4d fc 5f 25 ff 00 00 00 8a 80 ?? ?? ?? ?? 5e 33 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GC_2147750133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GC!MTB"
        threat_id = "2147750133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ff 69 04 00 00 75 ?? ?? ?? ?? ?? ?? ?? ff d5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GC_2147750133_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GC!MTB"
        threat_id = "2147750133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 7c 8b 8d [0-32] 89 78 [0-32] 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cf c1 e9 ?? 03 8d [0-32] 03 85 [0-32] 89 35 [0-32] 33 c1 8b 8d [0-32] 03 cf 33 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GD_2147750204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GD!MTB"
        threat_id = "2147750204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e0 8b ce c1 e9 ?? 03 8d [0-16] 03 85 [0-16] 33 c1 8b 8d [0-16] 03 ce 33 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 7c 89 38 [0-16] 89 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GD_2147750204_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GD!MTB"
        threat_id = "2147750204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 2b f8 89 6c 24 ?? 81 f3 07 eb dd 13 81 6c 24 14 ?? ?? ?? ?? b8 ?? ?? ?? ?? 81 6c 24 14 ?? ?? ?? ?? 81 44 24 14 ?? ?? ?? ?? 8b 4c 24 ?? 8b 54 24 ?? 8b c7 d3 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_JFU_2147750381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.JFU!MTB"
        threat_id = "2147750381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 2b f8 89 7c 24 ?? 89 5c 24 ?? 81 f3 07 eb dd 13 81 6c 24 ?? 52 ef 6f 62 b8 41 e5 64 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KM_2147750382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KM!MTB"
        threat_id = "2147750382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8d 0c 37 31 4c 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KM_2147750382_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KM!MTB"
        threat_id = "2147750382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ee 05 89 74 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 94 24 ?? ?? ?? ?? 8d 34 17 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KM_2147750382_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KM!MTB"
        threat_id = "2147750382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 03 f1 8d 14 3b 33 f2 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KM_2147750382_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KM!MTB"
        threat_id = "2147750382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 8c 24 ?? ?? ?? ?? 03 f1 8d 14 2f 33 f2 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KM_2147750382_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KM!MTB"
        threat_id = "2147750382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 84 24 ?? ?? ?? ?? 03 f0 8d 0c 2f 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KM_2147750382_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KM!MTB"
        threat_id = "2147750382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 06 88 14 38 40 3b c1 72}  //weight: 1, accuracy: High
        $x_1_2 = {c1 ea 05 89 54 24 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 84 24 ?? ?? ?? ?? ?? 44 24 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KM_2147750382_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KM!MTB"
        threat_id = "2147750382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8d 4c 24 ?? 51 8d 54 24 ?? 52 50 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? ff d3 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 57 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 60 0e 00 00 75 0c ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 c7 08 83 ee 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KM_2147750382_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KM!MTB"
        threat_id = "2147750382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 94 24 ?? ?? ?? ?? 03 f2 8d 04 2f 33 f0 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e9 05 89 4d ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 03 f2 03 c7 33 f0 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_KM_2147750382_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KM!MTB"
        threat_id = "2147750382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 81 fe dc a8 29 00 7c ?? 33 c0 3b cd 76 ?? 8b 35 ?? ?? ?? ?? eb [0-21] 8a 94 06 f5 d0 00 00 8b 3d ?? ?? ?? ?? 88 14 07 40 3b c1 72}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ec 68 08 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 12 0f 00 00 56 75 ?? 6a 00 8d 44 24 08 50 6a 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 69 c9 fd 43 03 00 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DHK_2147750389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DHK!MTB"
        threat_id = "2147750389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d 0c 69 04 00 00 e8 ?? ?? ?? ?? 8b 4d 08 30 04 0e 46 3b 75 0c 7c ac}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DHL_2147751687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DHL!MTB"
        threat_id = "2147751687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 74 24 ?? 8a 99 ?? ?? ?? ?? 0f be 82 ?? ?? ?? ?? 0f b6 d3 03 c6 03 d0 81 e2 ff 00 00 00 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b f2 89 35 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 6d fc 01 39 5d fc 7d ea}  //weight: 1, accuracy: Low
        $x_1_3 = "wihakiwahisari" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Glupteba_CSK_2147752015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.CSK!MTB"
        threat_id = "2147752015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f3 07 eb dd 13 81 ad ?? ?? ?? ?? 52 ef 6f 62 b8 ?? ?? ?? ?? 81 ad ?? ?? ?? ?? 68 19 2a 14 81 85 ?? ?? ?? ?? be 08 9a 76 8b 8d ?? ?? ?? ?? 8b d7 d3 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RMN_2147752366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RMN!MTB"
        threat_id = "2147752366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f3 07 eb dd 13 [0-12] 52 ef 6f 62 [0-2] 41 e5 64 03 [0-12] 68 19 2a 14 [0-12] be 08 9a 76 [0-14] d3 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f3 07 eb dd 13 81 6d ?? ?? ?? ?? ?? 81 6d ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 8b 45 ?? 5b 8b e5}  //weight: 1, accuracy: Low
        $x_1_3 = {8b ce c1 e1 04 03 8d ?? ?? ?? ?? 8b c6 c1 e8 05 03 85 ?? ?? ?? ?? 8d 14 37 33 ca 81 3d f4 1b 6c 04 72 07 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_RDL_2147752420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RDL!MTB"
        threat_id = "2147752420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 03 8d ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 31 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RRS_2147752653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RRS!MTB"
        threat_id = "2147752653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 e9 05 03 4c 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? 72 07 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cb c1 e1 04 03 8d ?? ?? ?? ?? 8b c3 c1 e8 05 03 85 ?? ?? ?? ?? 03 d3 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df}  //weight: 1, accuracy: Low
        $x_1_3 = {8b cf c1 e1 04 03 8d ?? ?? ?? ?? 8b c7 c1 e8 05 03 85 ?? ?? ?? ?? 03 d7 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_KMG_2147752738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KMG!MTB"
        threat_id = "2147752738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? ?? 45 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KMG_2147752738_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KMG!MTB"
        threat_id = "2147752738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 44 24 ?? ?? 44 24 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KMG_2147752738_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KMG!MTB"
        threat_id = "2147752738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 84 24 ?? ?? ?? ?? ?? 44 24 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KMG_2147752738_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KMG!MTB"
        threat_id = "2147752738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? ?? 45 ?? 8b 45 ?? ?? f0 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KMG_2147752738_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KMG!MTB"
        threat_id = "2147752738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? ?? 45 fc 8b 45 ?? 8b df c1 e3 04 03 5d ?? ?? c7 33 d8 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KMG_2147752738_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KMG!MTB"
        threat_id = "2147752738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 10 8b 0d ?? ?? ?? ?? 40 3b c1 72}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? 01 45 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KMG_2147752738_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KMG!MTB"
        threat_id = "2147752738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 75 05 0f 00 8b 1d ?? ?? ?? ?? 01 45 ?? ?? 5d ?? 8b 45 ?? 8a 14 08 a1 ?? ?? ?? ?? 88 14 08}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 16 42 3b d7 7c 05 00 e8 6b ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KMG_2147752738_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KMG!MTB"
        threat_id = "2147752738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 03 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 33 45 ?? 33 c1 2b f0 8b de c1 e3 04 81 3d ?? ?? ?? ?? 8c 07 00 00 89 45 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e9 05 89 4d ?? 8b 45 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 33 45}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c1 2b f8 8b f7 c1 e6 04 81 3d ?? ?? ?? ?? 8c 07 00 00 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_PA_2147753132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PA!MTB"
        threat_id = "2147753132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 01 44 24 14 8b 44 24 14 33 c3 33 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 24 01 44 24 10 8b d6 c1 ea 05 03 54 24 28 8d 04 37}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PA_2147753132_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PA!MTB"
        threat_id = "2147753132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 31 33 c0 8d [0-3] 51 8d [0-3] 52 50 89 [0-3] 89 [0-3] 89 [0-3] 89 [0-3] 89 [0-3] ff d3 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 57 e8 [0-4] 81 3d [0-8] 75 0e 6a 00 ff 15 [0-4] ff 15 [0-4] 83 c7 08 83 ee 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PA_2147753132_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PA!MTB"
        threat_id = "2147753132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 8a 93 ?? ?? ?? 00 30 11 43 81 fb 10 00 00 00 75 02 33 db 41 3b 0d 2c 80 48 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 3b 05 ?? ?? ?? 00 74 2a 3b 05 ?? ?? ?? 00 74 15 8a 93 ?? ?? ?? 00 30 10 43 81 fb 10 00 00 00 75 0e 33 db eb 0a 03 05 ?? ?? ?? 00 33 db eb ?? 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PVS_2147753581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PVS!MTB"
        threat_id = "2147753581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c3 c1 e8 05 03 44 24 28 8d 14 1e 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 4c 24 10 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MX_2147754226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MX!MTB"
        threat_id = "2147754226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 34 03 e8 ?? ?? ?? ?? 30 06 b8 01 00 00 00 29 44 24 ?? 8b 44 24 ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MX_2147754226_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MX!MTB"
        threat_id = "2147754226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 03 89 c9 88 06 01 f9 81 c7 ?? ?? ?? ?? 46 81 e9 01 00 00 00 81 ef ?? ?? ?? ?? 81 c3 02 00 00 00 09 c9 29 f9 81 c1 7e 1a fc 72 39 d3 7e d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MX_2147754226_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MX!MTB"
        threat_id = "2147754226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 56 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f0 03 75 fc 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 [0-26] 8b 55 08 03 32 8b 45 08 89 30 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {89 02 5f 5d c3 29 00 33 d1 c7 05 [0-8] 8b c2 01 05 ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_DSA_2147759454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSA!MTB"
        threat_id = "2147759454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 7b 56 8b f2 89 44 24 04}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 04 8a 04 32 88 04 31 5e 81 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSA_2147759454_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSA!MTB"
        threat_id = "2147759454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 87 d5 7c 3a 81 44 24 ?? 8c eb 73 22 8b 4c 24 ?? 8b c7 d3 e0 8b cf c1 e9 05 03 4c 24 20 03 44 24 ?? 89 15 ?? ?? ?? ?? 33 c1 8b 4c 24 ?? 03 cf 33 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DA_2147759469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DA!MTB"
        threat_id = "2147759469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 c1 e8 05 89 45 74 c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? fe ff ff 01 45 74 8b 55 74 33 d1 33 d3 8d 8d ?? fe ff ff 89 55 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DA_2147759469_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DA!MTB"
        threat_id = "2147759469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 14 8b 54 24 10 8b c1 c1 e8 05 03 44 24 2c 03 d5 33 c2 03 cb 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 18 c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 10 8b 44 24 24 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSB_2147759753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSB!MTB"
        threat_id = "2147759753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 4d ?? 8b 45 ?? 8b df d3 e3 8b 0d ?? ?? ?? ?? 8b f7 c1 ee 05 03 5d ?? 03 75 ?? 03 c7 33 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSC_2147759754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSC!MTB"
        threat_id = "2147759754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 45 ?? 8b 4d ?? 8b d0 d3 e2 8b c8 c1 e9 05 03 8d [0-4] 03 95 [0-4] 89 3d ?? ?? ?? ?? 33 d1 8b 8d [0-4] 03 c8 33 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSD_2147760168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSD!MTB"
        threat_id = "2147760168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 45 ?? 8b 4d ?? 8b f0 d3 e6 8b c8 c1 e9 05 03 8d ?? ?? ?? ?? 03 b5 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 33 f1 8b 4d ?? 03 c8 33 f1}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 4d ?? 8b d7 d3 e2 8b cf c1 e9 05 03 8d ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 33 c0 33 d1 8b 8d ?? ?? ?? ?? 03 cf 33 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_DSE_2147760169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSE!MTB"
        threat_id = "2147760169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 45 ?? 8b 4d ?? 8b d0 d3 e2 8b c8 c1 e9 05 03 4d ?? 03 55 ?? 89 35 ?? ?? ?? ?? 33 d1 8b 4d ?? 03 c8 33 d1}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 87 d5 7c 3a 81 44 24 ?? 8c eb 73 22 8b 4c 24 ?? 8b c5 d3 e0 8b cd c1 e9 05 03 4c 24 ?? 03 44 24 ?? 89 3d ?? ?? ?? ?? 33 c1 8b 4c 24 ?? 03 cd 33 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_DSF_2147760749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSF!MTB"
        threat_id = "2147760749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e9 05 03 8d ?? ?? ff ff 03 ?? ?? ?? ff ff 89 ?? ?? ?? ?? ?? 33 ?? 8b 8d ?? ?? ff ff 03 ?? 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DEA_2147761045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DEA!MTB"
        threat_id = "2147761045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 e2 8b ce c1 e9 05 03 8d ?? fb ff ff 03 95 ?? fb ff ff 33 c0 33 d1 8b 8d ?? fb ff ff 03 ce 33 d1 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DEB_2147761110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DEB!MTB"
        threat_id = "2147761110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 8b bd ?? fd ff ff 8b d8 d3 e3 8b 8d ?? fd ff ff c1 ef 05 03 bd ?? fd ff ff 03 9d ?? fd ff ff 03 c8 33 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSG_2147761212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSG!MTB"
        threat_id = "2147761212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 03 f7 d3 e0 89 b5 ?? ?? ff ff 8b f7 c1 ee 05 03 85 ?? ?? ff ff 03 b5 ?? ?? ff ff 89 45 ?? 8b 85 ?? ?? ff ff 31 45 ?? 81 3d ?? ?? ?? ?? 3f 0b 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSH_2147761213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSH!MTB"
        threat_id = "2147761213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a d0 8a c8 24 f0 02 c0 02 c0 0a 07 80 e1 fc c0 e2 06 0a 57 02 c0 e1 04 0a 4f 01 88 04 1e 8b 45 10 46 88 0c 1e 46 88 14 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DEC_2147761613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DEC!MTB"
        threat_id = "2147761613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e0 03 85 ?? fd ff ff 89 45 f8 8b 85 ?? fd ff ff 03 c6 c1 ee 05 03 b5 ?? fd ff ff 89 85 ?? fd ff ff 8b 85 ?? fd ff ff 31 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RA_2147761785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RA!MTB"
        threat_id = "2147761785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f7 c1 ee 05 03 85 ?? ?? ?? ?? 03 b5 ?? ?? ?? ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 31 45 ?? 33 db 81 3d ?? ?? ?? ?? 3f 0b 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSI_2147762189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSI!MTB"
        threat_id = "2147762189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 9d ?? ?? ?? ?? 8b 4d ?? 8b c3 d3 e0 03 85 ?? ?? ?? ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 03 c3 c1 eb 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DB_2147763672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DB!MTB"
        threat_id = "2147763672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f4 8a 44 02 ff 88 43 ff 3b 4d f4 77 df}  //weight: 10, accuracy: High
        $x_10_2 = {8b 55 a0 8b 45 9c 8b 00 89 02 8b 55 a0 8b 45 9c 8b 40 04 89 42 04 83 45 a0 08 83 45 9c 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DB_2147763672_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DB!MTB"
        threat_id = "2147763672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 14 24 b8 d1 05 00 00 01 04 24 8b 04 24 8a 0c 30 8b 15 ?? ?? ?? ?? 88 0c 32 81 c4 10 08 00 00 06 00 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {89 04 24 b8 d1 05 00 00 01 04 24 8b 0c 24 8a 14 31 a1 ?? ?? ?? ?? 88 14 30 81 c4 10 0c 00 00 05 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_DB_2147763672_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DB!MTB"
        threat_id = "2147763672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 4c 8b f0 83 64 24 ?? ?? d3 e6 03 74 24 ?? 81 6c 24 ?? aa a0 5b 7e 81 44 24 ?? 62 7e e6 6f 81 44 24 ?? 4d 22 75 0e 8b 4c 24 ?? 8b d0 8b 5c 24 ?? 03 c3 d3 ea 03 54 24 ?? 33 d0 33 d6 2b fa 81 3d ?? ?? ?? ?? fd 13 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSJ_2147763676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSJ!MTB"
        threat_id = "2147763676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 45 ?? 8b 4d ?? 8b d0 d3 e2 03 f8 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 05 03 85 ?? fd ff ff 03 95 ?? fd ff ff 89 bd ?? fd ff ff 89 55 ?? 89 45 ?? 8b 85 ?? fd ff ff 31 45 ?? 81 3d ?? ?? ?? ?? 3f 0b 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_DSL_2147764123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSL!MTB"
        threat_id = "2147764123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a da d2 e3 8b 4c 24 ?? 46 46 80 e3 c0 0a d8 8a c2 d2 e0 88 5c 3e fe c0 e2 06 0a 54 24 ?? 24 c0 0a 44 24 ?? 83 c5 04 88 44 3e ff 8b 44 24 ?? 88 14 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSM_2147764496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSM!MTB"
        threat_id = "2147764496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 24 8b f3 c1 ee 05 03 74 24 20 03 f9 8d 14 2b 33 fa 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 84 24 34 04 00 00 8b 54 24 08 5d 89 18 89 50 04 5b 81 c4 28 04 00 00 c2 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSN_2147764713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSN!MTB"
        threat_id = "2147764713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 45 ?? 8b 4d ?? 8b d0 03 f0 d3 e0 c1 ea 05 03 55 ?? 56 03 45 ?? 89 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DSO_2147764925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSO!MTB"
        threat_id = "2147764925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d ec 8b 55 f4 8b f3 c1 ee 05 03 75 e4 03 f9 03 d3 33 fa 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 45 08 8b 4d fc 8b 55 f8 89 08 89 50 04 75}  //weight: 1, accuracy: High
        $x_2_3 = {8b f3 c1 ee 05 03 74 24 ?? 03 f9 8d 14 2b 33 fa 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 2, accuracy: Low
        $x_1_4 = {8b 4c 24 10 89 48 04 89 18 5f 5e 5d 5b 81 c4 38 04 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_DE_2147765001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DE!MTB"
        threat_id = "2147765001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bumufi hojivezudiz havomojutoz piradicox rapirilajoxizam" wide //weight: 1
        $x_1_2 = "Fokunawoparohal hefonacit digov" wide //weight: 1
        $x_1_3 = "Sax kawalagiwak yepehiluf jacotavogeko bivupucoge" wide //weight: 1
        $x_1_4 = "Livezaxapanuwa cinajuhe jisesekuhehusa muhobaximi vaxoke" wide //weight: 1
        $x_1_5 = "Titelanufu mafasereberiyuv riyajexu leduburab faleyatoser" ascii //weight: 1
        $x_1_6 = "Guhilituyagorul pajibuzif nene vogorefituyot" ascii //weight: 1
        $x_1_7 = "sepukefumenifesaleribehajat pisojupesuhezupehesotocunomeguzi kevatapobaxahiviji" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DK_2147765328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DK!MTB"
        threat_id = "2147765328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {39 db 74 01 ea 31 1f 21 d1 81 c2 30 90 71 65 81 c7 04 00 00 00 81 ee 37 11 bd 92 39 c7 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_G_2147765354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.G!MSR"
        threat_id = "2147765354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c2 89 44 24 28 89 2d c0 a4 7e 00 8b 44 24 28 29 44 24 14 81 3d e4 14 14 05 d5 01 00 00 75 27}  //weight: 1, accuracy: High
        $x_1_2 = {c1 ea 05 89 54 24 18 c7 05 88 33 0d 05 2e ce 50 91 8b 44 24 3c 01 44 24 18 81 3d e4 14 14 05 12 09 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_G_2147765354_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.G!MSR"
        threat_id = "2147765354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 94 01 3b 2d 0b 00 8b 0d [0-4] 00 88 14 01 c3 16 8b 0d [0-4] 00}  //weight: 1, accuracy: Low
        $x_3_2 = {40 00 8b 0d ?? ?? 40 00 8b 15 ?? ?? 40 00 a3 ?? ?? ?? 00 66 a1 ?? ?? 40 00 89 0d ?? ?? ?? 00 8a 0d ?? ?? 40 00 89 15 ?? ?? ?? 00 66 a3 ?? ?? ?? 00 88 0d ?? ?? ?? 00 c6 05 ?? ?? ?? 00 69 c6 05 ?? ?? ?? 00 72}  //weight: 3, accuracy: Low
        $x_3_3 = {40 00 8b 0d ?? ?? 40 00 8b 15 ?? ?? 40 00 a3 ?? ?? ?? 00 66 a1 ?? ?? 40 00 89 0d ?? ?? ?? 00 8a 0d ?? ?? 40 00 89 15 ?? ?? ?? 00 66 a3 ?? ?? ?? 00 88 0d ?? ?? ?? 00 66 c7 05 ?? ?? ?? 00 69 72}  //weight: 3, accuracy: Low
        $x_1_4 = "VebtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_MS_2147766636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MS!MTB"
        threat_id = "2147766636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4d dc 51 ff 15 ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? 33 c6 8b 75 ?? 2b f8 8b cf c1 e1 ?? 03 4d ?? 8b c7 c1 e8 ?? 03 45 ?? 03 f7 33 ce 33 c8 c7 05 [0-8] c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 2b d9 8b 45 ?? 29 45 [0-5] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RQ_2147766781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RQ!MSR"
        threat_id = "2147766781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 ea 05 03 94 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 89 54 24 ?? e8 ?? ?? ?? ?? 33 c2 89 84 24 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 8b 84 24 ?? ?? ?? ?? 29 44 24 ?? 81 3d ?? ?? ?? ?? d5 01 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {c1 ee 05 03 b4 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 89 74 24 ?? 8b c8 e8 ?? ?? ?? ?? 33 c6 89 84 24 ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 29 44 24 ?? 81 3d ?? ?? ?? ?? d5 01 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {c1 ee 05 03 74 24 ?? 03 44 24 ?? 89 74 24 ?? 8b c8 e8 ?? ?? ?? ?? 33 c6 2b e8 81 3d ?? ?? ?? ?? d5 01 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_2147766844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MT!MTB"
        threat_id = "2147766844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 8b ff 83 ff 2d 75 14}  //weight: 10, accuracy: Low
        $x_10_2 = {30 04 1e 81 ff 91 05 00 00 75 0e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MU_2147767087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MU!MTB"
        threat_id = "2147767087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 56 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f0 03 75 fc 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 8b 55 08 03 32 8b 45 08 89 30 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {89 02 5f 5d c3 32 00 31 0d ?? ?? ?? ?? c7 05 [0-8] a1 ?? ?? ?? ?? 01 05 [0-6] 8b 15 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_DSP_2147767179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DSP!MTB"
        threat_id = "2147767179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 24 8b 54 24 10 8b f3 c1 ee 05 03 74 24 20 03 f9 03 d3 33 fa 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9}  //weight: 1, accuracy: Low
        $x_1_2 = {89 68 04 5d 89 18 5b 81 c4 5c 08 00 00 c2 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MV_2147767262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MV!MTB"
        threat_id = "2147767262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 8d 14 28 d3 e0 c1 ee 05 03 b4 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 89 74 24 ?? 8b c8 e8 ?? ?? ?? ?? 33 c6 89 84 24 ?? ?? ?? ?? c7 05 [0-8] 8b 84 24 ?? ?? ?? ?? 29 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 33 c2 c3}  //weight: 1, accuracy: High
        $x_2_3 = {78 00 61 00 74 00 65 00 70 00 61 00 00 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 56 69 72 74 75 61 6c 50 72 61 74 65 63 74 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 6e 69 73 61 7a 65 6a 61 6a 65 67 75 73 69 74 69 6b 75 66 75 62 6f 6e 75 64 65 72 69 76 75 77 00 79 61 72 75 72 75 6c 69 67 6f 76 65 6d 75 64 65 77 20 64 6f 62 75 66 61 68 75 76 69 73 6f 66 6f 73 69 63 69 66 20 25 66 00 00 00 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 64}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_MW_2147767365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MW!MTB"
        threat_id = "2147767365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 18 2b 4c 24 38 89 54 24 30 8b 54 24 30 8a 5c 24 0b 80 e3 [0-2] 07 88 5c 24 37 8b 74 24 10 8a 1c 16 88 5c 24 27 89 4c 24 20 8b 4c 24 20 c7 44 24 ?? ?? ?? ?? ?? 39 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AC_2147767366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AC!MTB"
        threat_id = "2147767366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 c9 88 4d f7 33 d2 88 55 f6 33 c0 88 45 f5 8a 4d f7 88 4d b0 8a 55 f6 88 55 ac 8a 45 f5 88 45 a8}  //weight: 10, accuracy: High
        $x_10_2 = {b8 01 00 00 00 6b c8 06 c6 84 0d 6c ff ff ff 33 ba 01 00 00 00 c1 e2 00 c6 84 15 6c ff ff ff 65 b8 01 00 00 00 d1 e0 c6 84 05 6c ff ff ff 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MZ_2147767451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MZ!MTB"
        threat_id = "2147767451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 3c 28 c1 e8 05 89 44 24 14 c7 05 [0-8] 8b 44 24 38 01 44 24 14 81 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f7 31 74 24 14 8b 44 24 14 29 44 24 18 81 3d}  //weight: 1, accuracy: High
        $x_2_3 = {8b f0 8d 14 28 d3 e0 c1 ee 05 03 [0-6] 03 [0-6] 89 [0-6] 8b c8 e8 [0-4] 33 c6 89 [0-6] c7 05 [0-8] 8b [0-6] 29 [0-6] 81 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_MA_2147767464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MA!MTB"
        threat_id = "2147767464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e 49 55 8b 2d ?? ?? ?? ?? 8b ff 81 ff 85 02 00 00 75 14}  //weight: 10, accuracy: Low
        $x_10_2 = {30 04 1e 81 ff 91 05 00 00 75 0e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MA_2147767464_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MA!MTB"
        threat_id = "2147767464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 46 85 c0 74 1d bb [0-4] 8b d6 c7 45 [0-5] d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 8b c3 aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MB_2147767651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MB!MTB"
        threat_id = "2147767651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 ca 89 44 24 1c 89 4c 24 14 89 35 c4 94 b9 00 8b 44 24 1c 01 05 c4 94 b9 00 a1 c4 94 b9 00 89 44 24 30 89 74 24 1c 8b 44 24 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MB_2147767651_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MB!MTB"
        threat_id = "2147767651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 8b 55 e8 52 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 8b 45 f0 8b 4d fc 8d 94 01 ?? ?? ?? ?? 89 55 ec a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 4d ec 89 0d ?? ?? ?? ?? 8b 55 fc 83 c2 04 89 55 fc c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 85 c0 0f 85 11 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 15 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MD_2147767756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MD!MTB"
        threat_id = "2147767756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 f1 8b 4d f8 81 45 f8 ?? ?? ?? ?? 8b c7 c1 e8 05 03 45 e8 03 cf 33 f1 33 f0 2b de ff 4d f4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 fc 0f 85 ?? ?? ?? ?? 8b 45 08 89 78 04 5f 5e 89 18 5b c9 c2}  //weight: 3, accuracy: Low
        $x_1_2 = "ciraboda" wide //weight: 1
        $x_1_3 = "VirtualProtecd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_ME_2147768119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ME!MTB"
        threat_id = "2147768119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 14 31 8d 41 40 30 02 41 83 f9 20 72 f2}  //weight: 1, accuracy: High
        $x_1_2 = {8d 14 31 8d 41 40 30 02 41 83 f9 05 72 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ME_2147768119_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ME!MTB"
        threat_id = "2147768119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 a3 [0-9] e8 ?? ?? ?? ?? 83 c4 04 8b 55 e8 52 [0-5] e8 ?? ?? ?? ?? 83 c4 08 8b 45 f0 8b 4d fc 8d 94 01 ?? ?? ?? ?? 89 55 ec a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 4d ec 89 0d ?? ?? ?? ?? 8b 55 fc 83 c2 04 89 55 fc c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 85 c0 0f 85 14 00 e8 ?? ?? ?? ?? a3 [0-9] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MF_2147768444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MF!MTB"
        threat_id = "2147768444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 05 89 45 f8 8b 45 e8 01 45 f8 8b 45 f4 8b f1 c1 e6 04 03 75 d8 03 c1 33 f0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d ec 83 0d [0-5] 81 45 [0-5] 8b c7 c1 e8 05 03 45 e4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 45 dc 33 c6 2b c8 ff 4d f0 89 4d ec 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_MG_2147768459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MG!MTB"
        threat_id = "2147768459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 f8 8b 45 e8 01 45 f8 8b 45 f4 8b [0-1] c1 e6 04 03 75 d8 03 ?? 33 f0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 c1 e8 05 03 45 e4 c7 05 [0-8] 33 45 dc 33 [0-2] 2b [0-1] ff 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_MH_2147768535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MH!MTB"
        threat_id = "2147768535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b [0-1] c1 e6 04 03 75 ?? 03 ?? 33 f0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 c1 e8 05 03 45 ?? c7 05 [0-8] 33 45 ?? 33 [0-2] 2b [0-1] ff 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_MI_2147768903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MI!MTB"
        threat_id = "2147768903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b ?? c1 ?? 04 03 ?? ?? 03 c1 33 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MJ_2147769049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MJ!MTB"
        threat_id = "2147769049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 46 85 c0 74 ?? bb [0-31] d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 [0-18] aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MK_2147769164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MK!MTB"
        threat_id = "2147769164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 8d [0-3] 89 [0-5] e8 [0-4] 8b [0-3] 8d [0-3] e8 [0-4] 33 [0-3] 8d [0-3] 8b d0 89 [0-3] c7 05 [0-8] e8 [0-4] 81 [0-9] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ML_2147769326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ML!MTB"
        threat_id = "2147769326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 10 33 df 33 cb 8d 44 24 28 89 4c 24 10 29 08 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 74 24 20 8b 6c 24 14 8b c6 8d 4c 24 1c c1 e0 04 89 01 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MM_2147769411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MM!MTB"
        threat_id = "2147769411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d3 56 e8 ?? ?? ?? ?? 83 c6 08 83 ef 01 75 0c 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 10 33 c6 89 44 24 10 2b f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MN_2147769677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MN!MTB"
        threat_id = "2147769677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 e9 05 89 [0-3] 8b [0-10] 01 44 24 10 8b f7 c1 e6 04 03 b4 24 [0-4] 8d [0-3] 33 f2 81 3d [0-8] c7 05 [0-8] 31 [0-4] 81 [0-9] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MO_2147769842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MO!MTB"
        threat_id = "2147769842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 44 24 10 c7 05 [0-8] 8b c8 89 [0-3] 8d [0-6] e8 [0-4] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 89 70 04 5e 5d 89 10 5b 81 c4 [0-4] c2 0e 00 8b [0-6] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MP_2147769845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MP!MTB"
        threat_id = "2147769845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 44 24 10 c7 05 [0-8] 8b c8 89 [0-3] 8d [0-6] e8 [0-4] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 89 70 04 5e 5d 89 10 5b [0-6] c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MQ_2147769929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MQ!MTB"
        threat_id = "2147769929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 33 [0-3] 33 [0-3] 8b c8 89 [0-3] 8d [0-6] e8 [0-4] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 89 70 04 5e 5d 89 ?? 5b [0-6] c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NA_2147769941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NA!MTB"
        threat_id = "2147769941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 c1 ea 05 8d [0-6] 89 [0-6] 8b [0-6] 01 [0-6] 03 [0-6] 33 [0-6] 81 [0-9] c7 05 [0-8] 31 [0-3] 81 [0-9] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NB_2147769984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NB!MTB"
        threat_id = "2147769984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 c1 e2 04 03 [0-6] 33 [0-3] 33 [0-3] 2b [0-3] 81 3d [0-8] 8b [0-6] 29 [0-6] 83 [0-8] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NC_2147770161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NC!MTB"
        threat_id = "2147770161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 08 4f 75 f4 5f 5e c3 09 00 57 8b f8 56 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 5e 75 07 ?? ff 15 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 7c e4 e8 ?? ?? ?? ?? 6a 7b 5e 07 00 a1 ?? ?? ?? ?? 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ND_2147770245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ND!MTB"
        threat_id = "2147770245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb c1 e1 04 03 [0-6] 03 [0-3] 33 [0-3] 33 [0-3] 2b [0-3] 81 3d [0-8] 8d [0-6] e8 [0-4] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d3 c1 e2 04 03 [0-6] 03 [0-3] 33 [0-3] 33 [0-3] 2b [0-3] 81 3d [0-8] 8d [0-6] e8 [0-4] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_NE_2147770326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NE!MTB"
        threat_id = "2147770326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 a4 24 e8 00 00 00 8b 84 24 e8 00 00 00 81 [0-10] 8b 84 [0-5] 8a 94 06 [0-4] 88 14 01 5e 81 c4 [0-4] c2}  //weight: 1, accuracy: Low
        $x_1_2 = {46 81 fe a9 10 00 00 7c ea 0d 00 81 fe [0-4] 75 05 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NF_2147770343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NF!MTB"
        threat_id = "2147770343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 33 09 fa 09 ff 43 39 cb 75 27 00 be ?? ?? ?? ?? 47 e8 ?? ?? ?? ?? 81 ef}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NF_2147770343_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NF!MTB"
        threat_id = "2147770343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 8d [0-3] c7 05 [0-18] 89 [0-3] 8b [0-6] 01 [0-3] 03 [0-3] 33 [0-3] 33 [0-3] 2b [0-3] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NG_2147770406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NG!MTB"
        threat_id = "2147770406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 0f 81 ea ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 89 d6 89 da 39 c7 75 e5 c3 09 d6 ?? ?? 81 c2 ?? ?? ?? ?? 21 d2 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NG_2147770406_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NG!MTB"
        threat_id = "2147770406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 24 e0 bf eb 0b 26 3e 75 1e 35 ?? ?? ?? ?? d8 cc f3 63}  //weight: 3, accuracy: Low
        $x_3_2 = {71 1e d1 4c 72 ?? 4d 73 5b e0 5a bb ?? ?? ?? ?? 72 3a 4d d7}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NG_2147770406_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NG!MTB"
        threat_id = "2147770406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d1 31 55 ?? 8b 4d ?? 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 3d [0-4] 26 04 00 00 75}  //weight: 2, accuracy: Low
        $x_1_2 = {33 d1 31 55 ?? 8b 4d ?? 8d 85 ?? ?? ?? ?? 29 08 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c6 d3 e0 8b 8d ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_NH_2147770426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NH!MTB"
        threat_id = "2147770426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 e8 d3 e0 c1 [0-3] 03 [0-6] 55 03 [0-6] 89 [0-3] e8 [0-4] 33 [0-3] 89 [0-6] c7 05 [0-8] 8b [0-6] 29 [0-3] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NI_2147770477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NI!MTB"
        threat_id = "2147770477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8b 85 [0-4] 03 [0-3] 33 [0-3] 33 [0-3] 2b [0-3] 81 3d [0-4] 17 04 00 00 81 [0-9] ff [0-5] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NJ_2147770503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NJ!MTB"
        threat_id = "2147770503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8d 0c 2b 33 [0-3] 33 [0-3] 2b [0-3] 81 3d [0-8] 81 [0-5] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NK_2147771168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NK!MTB"
        threat_id = "2147771168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 03 [0-5] 03 [0-5] 03 [0-3] 33 [0-3] 81 3d [0-8] 89 [0-3] [0-10] 33 [0-3] 89 [0-5] 8b [0-5] 29 [0-3] 81 [0-10] ff [0-5] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NL_2147771179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NL!MTB"
        threat_id = "2147771179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 8b 45 ec 55 8b ec 33 45 08 5d c2}  //weight: 2, accuracy: Low
        $x_1_2 = {50 8b 45 ec e8 [0-4] 81 3d [0-8] 8b [0-3] 75}  //weight: 1, accuracy: Low
        $x_3_3 = {50 8b 45 ec e8 [0-4] 81 3d [0-8] 8b [0-3] 33 [0-3] 83 [0-6] 89 [0-3] 8b [0-3] 29}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_NM_2147771276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NM!MTB"
        threat_id = "2147771276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 74 24 10 33 f1 2b fe 81 3d [0-8] 75 [0-2] 6a 00 6a 00 ff 15 [0-4] 8b [0-6] 29 [0-3] 83 [0-8] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NN_2147771356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NN!MTB"
        threat_id = "2147771356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 cf 33 f1 81 3d [0-8] 89 [0-3] [0-8] 33 f0 89 b5 [0-4] 8b 85 [0-4] 29 45 [0-10] ff 8d [0-4] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NO_2147771357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NO!MTB"
        threat_id = "2147771357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 89 [0-3] 8d [0-3] e8 [0-4] 8d [0-3] 8b [0-3] e8 [0-4] 81 3d [0-8] 8b [0-3] [0-10] 33 [0-3] 83 [0-6] 89 [0-3] 8b [0-3] 29 [0-3] 81 [0-6] ff [0-6] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NP_2147771435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NP!MTB"
        threat_id = "2147771435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 31 81 ff [0-4] 46 3b f7 81 ff [0-4] e8 [0-4] 8b 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NQ_2147771476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NQ!MTB"
        threat_id = "2147771476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d1 31 55 ?? 8b [0-3] 8d [0-5] e8 [0-4] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 45 70 83 25 [0-8] 8b c8 89 45 [0-1] 8d [0-5] e8 [0-4] 81 [0-5] ff [0-5] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NR_2147771597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NR!MTB"
        threat_id = "2147771597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 [0-5] 03 [0-5] 03 [0-3] 33 [0-3] 33 [0-3] 89 [0-3] 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-3] 8b [0-5] 29 [0-3] ff [0-5] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NS_2147771685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NS!MTB"
        threat_id = "2147771685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 08 50 50 ff 15 [0-4] e8 [0-4] 30 [0-3] 33 [0-3] 3b [0-3] 81}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 51 56 33 f6 81 3d [0-8] a1 [0-4] 69 [0-5] 81 3d [0-8] [0-8] a3 [0-4] 89 [0-3] 81 [0-6] 8b [0-3] 01 [0-5] 0f [0-6] 25 [0-4] 5e c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_NT_2147771740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NT!MTB"
        threat_id = "2147771740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 [0-5] 03 [0-5] 03 [0-3] 33 [0-3] 33 [0-3] 89 [0-3] 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-3] 8b [0-5] 29 [0-5] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NU_2147771910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NU!MTB"
        threat_id = "2147771910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 c1 ee 05 03 [0-5] 81 3d [0-8] c7 05 [0-8] c7 05 [0-8] 33 [0-3] 81 [0-10] 33 [0-3] 2b [0-3] 83 [0-5] 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ee 05 03 [0-3] 81 3d [0-8] c7 05 [0-8] c7 05 [0-8] [0-8] 33 [0-3] 33 [0-12] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_NV_2147771944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NV!MTB"
        threat_id = "2147771944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d9 33 d8 89 [0-3] 89 [0-5] 8b [0-5] 29 [0-3] 8b [0-5] 29 [0-3] 4a 8b [0-3] 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d1 33 d0 89 45 f8 89 [0-5] 8b [0-5] 29 [0-3] 8b [0-5] 29 [0-8] 8b [0-3] 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {88 14 38 40 3b c1 8b [0-5] 8a [0-6] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Glupteba_NW_2147772032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NW!MTB"
        threat_id = "2147772032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 db 74 01 ea 31 0f 81 c7 04 00 00 00 39 df}  //weight: 1, accuracy: High
        $x_1_2 = {31 0f 81 c7 04 00 00 00 39 df 75 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NW_2147772032_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NW!MTB"
        threat_id = "2147772032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 df 03 ca 33 [0-3] 33 [0-3] 89 [0-3] 89 [0-5] 8b [0-5] 29 [0-3] 8b [0-5] 29 [0-3] ff [0-5] 8b [0-3] 0f [0-5] 5f 89 [0-3] 89 [0-5] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NX_2147772121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NX!MTB"
        threat_id = "2147772121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 04 33 81 ff [0-4] 75 ?? 6a 00 [0-13] ff 15 [0-4] 46 3b f7 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NY_2147772272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NY!MTB"
        threat_id = "2147772272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 33 81 ff [0-4] 75 ?? 6a 00 [0-13] ff 15 [0-13] 46 3b f7 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_NZ_2147772355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.NZ!MTB"
        threat_id = "2147772355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 16 42 3b d7 55 8b ec 51 a1 [0-4] 69 [0-5] a3 [0-4] c7 45 [0-5] 81 45 [0-5] 8b [0-5] 01 [0-5] 0f [0-6] 25 [0-4] 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OA_2147772418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OA!MTB"
        threat_id = "2147772418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 5e d3 e0 c1 ee 05 03 [0-6] 03 [0-6] 89 [0-3] 50 59 e8 [0-4] 33 ?? 89 [0-6] 89 [0-5] 8b [0-6] 29 [0-3] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OB_2147772460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OB!MTB"
        threat_id = "2147772460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 1e 81 ff ?? ?? ?? ?? 46 3b f7 51 a1 [0-4] 69 [0-5] a3 [0-4] c7 [0-6] 81 [0-26] 25 [0-5] c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 e8 [0-4] 46 3b ?? e8 [0-4] 30 04 ?? 81 ff [0-4] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_OC_2147773018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OC!MTB"
        threat_id = "2147773018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 03 [0-5] 03 [0-5] 03 ?? 33 ?? 33 ?? 81 [0-9] 89 [0-2] 33 ?? 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-2] 81 [0-9] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OD_2147773157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OD!MTB"
        threat_id = "2147773157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 c1 ea 05 8d [0-3] c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-5] c1 [0-5] 33 [0-3] 33 [0-3] 81 [0-9] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OE_2147773326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OE!MTB"
        threat_id = "2147773326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 c1 e2 04 03 ?? 33 [0-3] 33 ?? 2b ?? 81 [0-9] 8b [0-6] 29 [0-3] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d7 c1 ea ?? 8d [0-2] c7 [0-9] c7 [0-9] 89 [0-3] 8b [0-6] 01 [0-3] 8b ?? c1 ?? ?? 03 ?? 33 [0-3] 33 ?? 2b ?? 81 [0-9] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 85 c0 76 ?? 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 88 14 0e 3d 03 02 00 00 75 ?? 83 25 14 d9 ?? ?? ?? ?? 3b c8 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 8d 0c 30 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? c1 e6 04 03 f5 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 03 f0 8d 0c 2f 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 89 44 24 ?? 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8d 14 37 31 54 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f7 c1 e6 04 03 74 24 ?? 8d 0c 3b 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 8d 0c 38 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b f7 c1 e6 04 03 b4 24 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 0e 3d 03 02 00 00 75 ?? 89 3d ?? ?? ?? ?? 41 3b c8 72}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 37 83 fb 19 75 ?? 33 c0 50 8d 4c 24 ?? 51 50 50 50 50 ff 15 ?? ?? ?? ?? 46 3b f3 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 89 44 24 ?? 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? ?? 44 24 ?? 8b 44 24 ?? 8d 14 37 33 c2 31 44 24 ?? 83 3d ?? ?? ?? ?? 42 c7 05 ?? ?? ?? ?? 36 06 ea e9 89 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 54 24 ?? 03 f2 03 eb 33 f5 33 74 24 ?? 2b fe 81 3d ?? ?? ?? ?? 17 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 4c 24 ?? 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 44 24 ?? 8d 0c 37 33 c1 31 44 24 ?? 83 3d ?? ?? ?? ?? 42 c7 05 ?? ?? ?? ?? 36 06 ea e9 89 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b 45 ?? 81 05 ?? ?? ?? ?? 7e 32 ef 01 01 05 ?? ?? ?? ?? 8b 4d ?? 33 4d ?? 89 4d ?? 81 3d ?? ?? ?? ?? 83 05 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 33 cf 33 ce 2b d9 81 3d ?? ?? ?? ?? 17 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GKM_2147773397_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GKM!MTB"
        threat_id = "2147773397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 85 ?? ?? ?? ?? 03 c3 33 45 ?? 33 db 33 c1 81 3d ?? ?? ?? ?? e6 06 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 89 45 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ea 05 03 ce 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b c6 c1 e0 04 03 c5 33 44 24 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 33 c1 81 3d ?? ?? ?? ?? e6 06 00 00 89 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_OF_2147773463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OF!MTB"
        threat_id = "2147773463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8d [0-2] e8 [0-4] 30 ?? 83 [0-3] 47 3b [0-2] 81 [0-6] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OG_2147773580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OG!MTB"
        threat_id = "2147773580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8d [0-2] e8 [0-4] 30 ?? 83 [0-2] 46 3b ?? 81 [0-5] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OH_2147773662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OH!MTB"
        threat_id = "2147773662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 39 83 [0-2] 47 3b ?? 81 [0-5] 8b [0-5] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OI_2147773701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OI!MTB"
        threat_id = "2147773701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 c1 ea 05 8d [0-2] c7 [0-9] c7 [0-9] 89 [0-3] 8b [0-3] 01 [0-3] 8b ?? c1 [0-2] 03 [0-3] 33 [0-3] 33 ?? ?? ?? 81 [0-9] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cd c1 e9 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 8b [0-3] 33 [0-3] 33 [0-3] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_RY_2147773795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RY!MTB"
        threat_id = "2147773795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 ea 05 8d 0c 18 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b c3 c1 e0 04 03 84 24 ?? ?? ?? ?? 33 44 24 ?? 33 c1 2b f8 81 3d ?? ?? ?? ?? 17 04 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OJ_2147773834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OJ!MTB"
        threat_id = "2147773834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 08 8b e5 5d c3 2d 00 a1 ?? ?? ?? ?? ?? ?? 89 [0-2] 31 [0-2] c7 05 [0-10] 8b [0-2] 01 [0-5] a1 [0-4] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OK_2147774338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OK!MTB"
        threat_id = "2147774338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 e9 05 89 [0-3] 8b [0-3] 01 [0-3] 8b ?? c1 e6 ?? 03 [0-3] 8d [0-2] 33 ?? 81 [0-9] c7 [0-9] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OL_2147774368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OL!MTB"
        threat_id = "2147774368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-3] 01 [0-3] 8b [0-7] 33 ?? 33 [0-3] 68 [0-4] 8d [0-3] 51 2b ?? e8 [0-4] 83 [0-4] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RDV_2147775137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RDV!MTB"
        threat_id = "2147775137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 24 83 c4 04 81 c2 00 a8 6a 38 e8 ?? ?? ?? ?? 81 eb 29 d2 30 61 81 c2 c0 41 f4 c9 81 ea 01 00 00 00 31 0f 09 da 81 c2 64 93 88 9e 47 21 da 39 f7 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5a 81 c0 ae 69 2a df 09 db e8 ?? ?? ?? ?? 81 c3 48 e9 a8 c9 31 16 81 c3 7b 2d b5 54 01 c3 21 d8 81 c6 ?? ?? ?? ?? 81 eb df fb d1 45 01 c0 89 c0 39 fe 75}  //weight: 1, accuracy: Low
        $x_1_3 = {59 57 58 09 c7 e8 ?? ?? ?? ?? 29 f8 01 ff 68 ?? ?? ?? ?? 5f 31 0e 09 c0 46 81 ef 01 00 00 00 57 58 39 d6 75}  //weight: 1, accuracy: Low
        $x_1_4 = {21 c0 81 eb 01 00 00 00 e8 ?? ?? ?? ?? b8 c4 9c da 43 09 c0 31 3e 89 c3 89 c3 4b 81 c6 01 00 00 00 89 c0 29 db 39 ce 75}  //weight: 1, accuracy: Low
        $x_1_5 = {5f 01 d2 e8 ?? ?? ?? ?? 4a 81 e8 74 d8 a7 d7 31 3b 81 e8 c8 b3 4f 47 43 68 ?? ?? ?? ?? 58 29 c0 39 f3 75}  //weight: 1, accuracy: Low
        $x_1_6 = {be ec d5 b7 68 e8 ?? ?? ?? ?? 4e 29 c0 89 f0 31 3b 81 c6 63 40 72 ff 46 43 89 c6 21 f0 39 d3 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_OM_2147775149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OM!MTB"
        threat_id = "2147775149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 e9 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-3] 01 [0-3] 81 3d [0-8] 8b [0-3] 33 ?? 33 ?? 8d [0-3] e8 [0-4] 81 3d [0-8] 8b [0-3] 29 [0-3] 83 [0-4] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ON_2147775312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ON!MTB"
        threat_id = "2147775312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-3] 01 [0-3] 81 3d [0-8] 8b [0-3] 33 [0-3] 33 [0-3] 8d [0-3] e8 [0-4] 81 3d [0-8] 8d [0-3] e8 [0-4] 83 [0-4] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OO_2147775316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OO!MTB"
        threat_id = "2147775316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b cf c1 e9 05 89 [0-3] 8b [0-3] 01 [0-3] 8b [0-3] c1 [0-3] 03 [0-3] 8d [0-3] 33 [0-3] 81 3d [0-8] c7 05 [0-8] 31 [0-3] 81 3d [0-8] ff 15 [0-4] 8b [0-3] 8d [0-3] e8 [0-4] 81 3d [0-8] 75}  //weight: 2, accuracy: Low
        $x_1_2 = {75 04 6a 00 ff d3 81 3d [0-8] 75 04 6a 00 ff d5 56 e8 [0-4] 83 c6 08 83 ef 01 81 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {75 06 6a 00 6a 00 ff d7 e8 [0-4] a1 [0-4] 46 3b f0 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_OP_2147775378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OP!MTB"
        threat_id = "2147775378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f5 03 df 81 3d [0-8] [0-3] c1 [0-2] c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-3] 01 [0-3] 81 3d [0-8] 8b [0-3] 33 [0-3] 33 [0-3] 8d [0-3] e8 [0-4] 81 3d [0-8] 8d [0-3] e8 [0-4] 83 [0-4] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OQ_2147775738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OQ!MTB"
        threat_id = "2147775738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 c1 ea 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 8b [0-3] 33 ?? 33 ?? 8d [0-6] e8 [0-4] 8b [0-6] 29 [0-3] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OR_2147775768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OR!MTB"
        threat_id = "2147775768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c1 e6 ?? 81 [0-9] 03 [0-6] 81 [0-9] 8b [0-3] 8d [0-2] 8b ?? c1 ?? ?? c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 8b [0-3] 33 ?? 33 ?? 8d [0-6] e8 [0-4] 8b [0-6] 29 [0-3] 83 [0-7] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RH_2147775783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RH!MTB"
        threat_id = "2147775783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e9 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 4c 24 ?? 33 cb 33 ce 8d 84 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OT_2147776040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OT!MTB"
        threat_id = "2147776040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c1 e6 04 81 3d [0-8] 03 [0-6] 81 3d [0-8] 8d [0-2] 8b ?? c1 [0-2] c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 8b [0-3] 33 ?? 33 ?? 8d [0-6] e8 [0-4] 81 [0-5] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c7 08 83 [0-2] 81 3d [0-8] 81 3d [0-8] 81 3d [0-8] 57 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_RL_2147776206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RL!MTB"
        threat_id = "2147776206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 ea 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 4c 24 ?? 33 cf 33 ce}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OU_2147776212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OU!MTB"
        threat_id = "2147776212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 05 c7 05 [0-8] c7 05 [0-8] 89 [0-2] 8b [0-5] 01 [0-2] 8b [0-2] 33 ?? 33 ?? 8d [0-5] e8 [0-4] 81 [0-9] 83 [0-6] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OV_2147776324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OV!MTB"
        threat_id = "2147776324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c5 c1 e8 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 81 3d [0-8] 8b [0-3] 33 ?? 33 ?? 8d [0-6] e8 [0-4] 81 [0-5] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OW_2147776325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OW!MTB"
        threat_id = "2147776325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f5 c1 e6 04 81 3d [0-8] 03 [0-6] 81 [0-13] 8b ?? c1 [0-2] c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OX_2147776624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OX!MTB"
        threat_id = "2147776624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 81 3d [0-8] 8b [0-3] 33 ?? 33 ?? 8d [0-6] e8 [0-4] 8b [0-10] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OY_2147776771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OY!MTB"
        threat_id = "2147776771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c7 08 83 6c 24 10 01 81 3d [0-8] 81 3d [0-8] 57 e8 [0-4] 81 3d [0-8] 75 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OZ_2147776999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OZ!MTB"
        threat_id = "2147776999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 04 81 [0-9] 89 [0-3] 03 [0-6] 89 [0-3] 8b [0-1] c1 [0-2] 89 [0-3] 8b [0-6] 01 [0-3] 8d [0-2] 31 [0-3] 81 [0-9] c7 05 [0-8] 8b [0-3] 31 [0-3] 83 [0-6] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 c1 e8 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 81 3d [0-8] 8b [0-3] 8b [0-3] 33 ?? 33 ?? 8d [0-6] e8 [0-4] 8d [0-6] e8 [0-4] 83 [0-7] 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_PB_2147777177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PB!MTB"
        threat_id = "2147777177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff 15 [0-4] 8b [0-3] 8b [0-3] 33 ?? 33 ?? 8d [0-6] 89 [0-3] e8 [0-4] 8b [0-6] 29 [0-3] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PB_2147777177_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PB!MTB"
        threat_id = "2147777177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 c1 ea 05 03 d5 03 c6 31 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 2c 29 44 24 18 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RT_2147777319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RT!MTB"
        threat_id = "2147777319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 38 81 c0 04 00 00 00 89 d9 43 39 d0 75 ?? 09 f1 09 de c3 83 ec 04 ?? ?? ?? 2d 8b f0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RT_2147777319_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RT!MTB"
        threat_id = "2147777319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 39 81 c6 bd fb 42 88 21 d8 81 c1 04 00 00 00 81 c6 01 00 00 00 39 d1 75 ?? bb 24 d1 40 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RT_2147777319_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RT!MTB"
        threat_id = "2147777319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ee 05 89 74 24 ?? 8b 44 24 ?? 01 44 24 ?? 31 4c 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RF_2147777398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RF!MTB"
        threat_id = "2147777398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 86 72 18 5f 46 89 ff e8 ?? ?? ?? ?? 01 f7 47 31 02 81 ee 01 00 00 00 81 c2 01 00 00 00 81 ef 9a f8 1a ff 4e 39 da 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RF_2147777398_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RF!MTB"
        threat_id = "2147777398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 89 44 24 ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8d 14 37 31 54 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PG_2147777459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PG!MTB"
        threat_id = "2147777459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 81 3d [0-8] 8b [0-3] 8b [0-3] 33 ?? 33 ?? 8d [0-6] 89 [0-3] e8 [0-4] 8d [0-6] e8 [0-4] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PH_2147777460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PH!MTB"
        threat_id = "2147777460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 81 3d [0-8] 8b [0-3] 8b [0-3] 33 ?? 33 ?? 8d [0-6] 89 [0-3] e8 [0-4] 81 [0-5] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PJ_2147777462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PJ!MTB"
        threat_id = "2147777462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 10 8b [0-3] 33 ?? 33 ?? 8d [0-6] 89 [0-3] e8 [0-4] 81 [0-5] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PC_2147777766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PC!MTB"
        threat_id = "2147777766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 e1 04 03 [0-6] 8b ?? c1 [0-2] 89 [0-3] 89 [0-3] 8b [0-6] 01 [0-3] 8d [0-2] 31 [0-3] 81 [0-9] c7 [0-9] 8b [0-3] 31 [0-3] 83 [0-6] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PD_2147777767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PD!MTB"
        threat_id = "2147777767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c7 08 83 ed 01 81 3d [0-8] 81 3d [0-8] 57 e8 [0-4] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
        $x_1_2 = "SetPriorityClass" ascii //weight: 1
        $x_1_3 = "GetConsoleOutputCP" ascii //weight: 1
        $x_1_4 = "GetConsoleWindow" ascii //weight: 1
        $x_1_5 = "GetNamedPipeHandleStateA" ascii //weight: 1
        $x_1_6 = "CompareFileTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RW_2147777799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RW!MTB"
        threat_id = "2147777799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 39 54 24 ?? 7e ?? 8b 44 24 ?? 8d 0c 02 e8 ?? ?? ?? ?? 30 01 42 3b 54 24 ?? 7c ?? 81 7c 24 ?? 71 11 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PE_2147777862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PE!MTB"
        threat_id = "2147777862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 e1 04 03 [0-6] 8b ?? c1 [0-2] 89 [0-3] 89 [0-3] 8b [0-6] 01 [0-3] 8b [0-3] 8d [0-2] 33 ?? 31 [0-3] 83 [0-6] c7 [0-9] 89 [0-3] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PF_2147777877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PF!MTB"
        threat_id = "2147777877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 81 3d [0-8] 8b [0-3] 8b [0-3] 33 ?? 33 ?? 8d [0-6] 89 [0-3] e8 [0-4] 8d [0-6] e8 [0-4] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PK_2147778443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PK!MTB"
        threat_id = "2147778443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 e9 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 8b [0-3] 8b [0-3] 33 ?? 33 ?? 8d [0-6] e8 [0-4] 81 [0-5] 83 ed 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AV_2147778638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AV!MTB"
        threat_id = "2147778638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d cc 6b 84 00 75 06 81 c1 f5 94 08 00 40 3d 45 74 8d 00 7c eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AV_2147778638_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AV!MTB"
        threat_id = "2147778638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d cc 6b 84 00 75 03 83 c1 15 40 3d 45 74 8d 00 7c ee}  //weight: 1, accuracy: High
        $x_2_2 = {30 04 33 83 ff 19 75 2e 6a 00 8d 44 24 10 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AV_2147778638_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AV!MTB"
        threat_id = "2147778638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 10 8b 44 24 14 33 d7 33 c2 2b f0 81 c5 47 86 c8 61 83 ac 24 ac 02 00 00 01 0f 85 a7 e6 ff ff 8b 84 24 f8 06 00 00 5f 89 30 5e 5d 89 58 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AV_2147778638_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AV!MTB"
        threat_id = "2147778638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 83 c0 15 57 8b bc 24 f8 02 00 00 a3}  //weight: 1, accuracy: High
        $x_1_2 = {30 04 33 83 ff 19 75 2e 6a 00 8d 44 24 10}  //weight: 1, accuracy: High
        $x_1_3 = {8a 54 31 15 88 14 33 33 db 3d 03 02 00 00 75 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Glupteba_AV_2147778638_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AV!MTB"
        threat_id = "2147778638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 c3 9e 26 00 a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 1e 83 ff 19 75 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AV_2147778638_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AV!MTB"
        threat_id = "2147778638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 6c 75 0b b8 56 c4 08 00 01 05 ?? ?? ?? ?? 41 81 f9 0f 7e 49 00 7c e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AV_2147778638_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AV!MTB"
        threat_id = "2147778638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4c 2e 15 8b 15 ?? ?? ?? ?? 88 0c 32 3d 03 02 00 00 75 27}  //weight: 1, accuracy: Low
        $x_1_2 = {75 03 83 c1 15 40 3d 45 74 8d 00 7c ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PL_2147778651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PL!MTB"
        threat_id = "2147778651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 8b [0-3] 8b [0-3] 33 ?? 33 ?? 2b ?? 81 [0-5] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PM_2147778770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PM!MTB"
        threat_id = "2147778770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-6] 01 [0-3] 81 3d [0-8] 8b [0-3] 8b [0-3] 33 ?? 33 ?? 89 [0-3] 2b ?? 8b [0-6] 29 [0-3] 83 [0-7] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PN_2147779736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PN!MTB"
        threat_id = "2147779736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 33 45 f0 89 45 e4 8b 45 e4 33 45 ec 89 45 e4 8b 45 d0 2b 45 e4 89 45 d0 8b 45 e8 2b 45 d8 89 45 e8 e9 [0-4] 8b 45 08 8b 4d d0 89 08 8b 45 08 8b 4d f4 89 48 04 c9 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PO_2147779869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PO!MTB"
        threat_id = "2147779869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e4 33 4d f0 89 4d e4 8b 55 e4 33 55 ec 89 55 e4 8b 45 d0 2b 45 e4 89 45 d0 8b 4d e8 2b 4d d8 89 4d e8 e9 [0-4] 8b 55 08 8b 45 d0 89 02 8b 4d 08 8b 55 f4 89 51 04 8b e5 5d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PP_2147779916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PP!MTB"
        threat_id = "2147779916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 0d 8b 85 [0-4] 40 89 85 [0-4] 81 bd [0-8] 7d 10 83 bd [0-5] 75 05 e8 [0-4] eb d7 68 [0-4] ff 35 [0-4] ff 35 [0-4] e8 [0-4] e8 [0-4] 33 c0 5f 5e c9 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PQ_2147780076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PQ!MTB"
        threat_id = "2147780076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b e5 5d c2 3e 00 8b ?? ?? 33 ?? ?? 89 ?? ?? 8b ?? ?? 33 ?? ?? 89 ?? ?? 8b ?? ?? 2b ?? ?? 89 ?? ?? 8b ?? ?? 52 8d ?? ?? 50 e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b ?? ?? 8b ?? ?? 89 ?? 8b ?? ?? 8b ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PR_2147780147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PR!MTB"
        threat_id = "2147780147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b e5 5d c2 08 00 3e 00 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 8b [0-2] 51 8d [0-2] 52 e8 [0-4] e9 [0-4] 8b [0-2] 8b [0-2] 89 [0-1] 8b [0-2] 8b [0-2] 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PS_2147780256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PS!MTB"
        threat_id = "2147780256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c7 c1 e8 05 c7 05 [0-8] c7 05 [0-8] 89 [0-3] 8b [0-3] 01 [0-3] 81 3d [0-8] 8b [0-3] 33 ?? 33 ?? 8d [0-3] e8 [0-4] 81 3d [0-8] 81 [0-5] 83 [0-4] 0f 85}  //weight: 2, accuracy: Low
        $x_1_2 = {75 04 6a 00 ff d3 81 3d [0-8] 75 06 6a 00 6a 00 ff d5 56 e8 [0-4] 83 c6 08 83 ef 01 75 d0 0a 00 81 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 5e 5d 89 10 5b 81 [0-5] c2 0e 00 8b [0-6] 8b [0-3] 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_PT_2147780312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PT!MTB"
        threat_id = "2147780312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 [0-2] 8b [0-2] 01 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 8b [0-2] 29 [0-2] e9 [0-4] 8b [0-2] 8b [0-2] 89 ?? 8b [0-2] 8b [0-2] 89 [0-2] 8b e5 5d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PU_2147780325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PU!MTB"
        threat_id = "2147780325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 33 81 [0-5] 46 3b f7 81 [0-5] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EAN_2147780445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EAN!MTB"
        threat_id = "2147780445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 c4 08 00 88 ?? 8b e5 5d c2 04}  //weight: 10, accuracy: Low
        $x_5_2 = {c7 45 e8 20 37 ef c6 c7 45 d8 b9 79 37 9e 8b 4d 0c 8b 11 89 55 f8 8b 45 0c 8b 48 04}  //weight: 5, accuracy: High
        $x_5_3 = {55 8b ec 8b 45 08 8b 08 2b 4d 0c 8b 55 08 89 0a 5d c2 08 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_PV_2147780475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PV!MTB"
        threat_id = "2147780475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e4 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] e9 [0-4] 8b [0-2] 8b [0-2] 89 08 8b [0-2] 8b [0-2] 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PW_2147780541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PW!MTB"
        threat_id = "2147780541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 83 [0-2] 89 [0-2] 8b [0-2] 3b [0-2] 73 ?? 83 [0-6] 8b [0-2] 89 [0-2] 81 [0-9] 8b [0-2] d1 ?? 89 [0-2] 81 [0-9] 8b [0-2] 51 8b [0-2] 8b [0-2] 8d [0-2] 51 e8 [0-4] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PX_2147780670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PX!MTB"
        threat_id = "2147780670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 89 [0-2] 8b [0-2] 01 [0-2] 83 [0-6] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PY_2147780848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PY!MTB"
        threat_id = "2147780848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 89 [0-2] 8b [0-2] 01 [0-2] 83 [0-6] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 29 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PZ_2147781057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PZ!MTB"
        threat_id = "2147781057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d4 01 [0-2] 81 [0-9] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 29 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QA_2147781120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QA!MTB"
        threat_id = "2147781120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d4 01 [0-2] 83 [0-6] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 29 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KS_2147781172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KS!MTB"
        threat_id = "2147781172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 ec 1c 04 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 18 04 00 00 a1 ?? ?? ?? ?? 53 55 56 57 8b 3d ?? ?? ?? ?? 33 db a3 ?? ?? ?? ?? 33 f6 8d 64 24 00 81 3d ?? ?? ?? ?? c7 01 00 00 75 29}  //weight: 10, accuracy: Low
        $x_10_2 = {3d cb d9 0b 00 75 06 81 c1 00 00 00 00 40 3d 3d a6 15 00 7c eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_OS_2147781256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.OS!MTB"
        threat_id = "2147781256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c7 08 83 ed 01 81 3d [0-8] 81 3d [0-8] 81 3d [0-8] 57 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QB_2147781317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QB!MTB"
        threat_id = "2147781317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 ec 83 [0-6] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KT_2147781339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KT!MTB"
        threat_id = "2147781339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 83 ff 2d 75 1e}  //weight: 10, accuracy: Low
        $x_10_2 = {30 04 33 81 ff 91 05 00 00 75 31}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QC_2147781418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QC!MTB"
        threat_id = "2147781418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 ec 83 [0-6] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 81 [0-9] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QD_2147781598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QD!MTB"
        threat_id = "2147781598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 ec 81 3d [0-11] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 81 3d [0-8] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QE_2147781793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QE!MTB"
        threat_id = "2147781793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 ec 81 3d [0-8] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 8b [0-2] 51 8d [0-2] 52 e8 [0-4] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QF_2147781846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QF!MTB"
        threat_id = "2147781846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d4 01 [0-2] 81 3d [0-8] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 8b [0-2] 50 8d [0-2] 51 e8 [0-4] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EDS_2147782018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EDS!MTB"
        threat_id = "2147782018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 e8 20 37 ef c6 c7 45 d8 b9 79 37 9e 8b 4d 0c 8b 11 89 55 f8}  //weight: 10, accuracy: High
        $x_10_2 = {84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 8b ?? f4 c1 ?? 05 89 ?? ec 8b 45 d4 01 45 ec}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QG_2147782111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QG!MTB"
        threat_id = "2147782111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 ec 83 [0-6] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 8b [0-2] 50 8d [0-2] 51 e8 [0-4] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_KA_2147782138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.KA!MTB"
        threat_id = "2147782138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 ec 1c 04 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 18 04 00 00 a1 ?? ?? ?? ?? 53 55 56 57 8b 3d ?? ?? ?? ?? 33 db a3 ?? ?? ?? ?? 33 f6 8d 64 24 00 81 3d ?? ?? ?? ?? c7 01 00 00 75 29}  //weight: 10, accuracy: Low
        $x_10_2 = {81 fe cc 6b 84 00 75 0b b8 15 00 00 00 01 05 ?? ?? ?? ?? 46 81 fe c5 0a 26 01 7c af}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QH_2147782192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QH!MTB"
        threat_id = "2147782192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 ec 81 [0-9] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 8b [0-2] 50 8d [0-2] 51 e8 [0-4] e9}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 ec 81 [0-9] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] ff [0-2] 8d [0-2] 50 e8 [0-4] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_DM_2147782222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DM!MSR"
        threat_id = "2147782222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? c7 05 ?? ?? ?? ?? 82 cd 10 fe 8b 45 ?? 33 45 ?? 89 45 ?? 81 3d ?? ?? ?? ?? 91 05 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QI_2147782307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QI!MTB"
        threat_id = "2147782307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 ec 81 [0-9] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-10] e8 [0-4] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_E_2147782381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.E!MTB"
        threat_id = "2147782381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e4 33 45 f0 89 45 e4 8b 4d e4 33 4d ec 89 4d e4 8b 55 d0 2b 55 e4 89 55 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QJ_2147782473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QJ!MTB"
        threat_id = "2147782473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 ec 81 [0-9] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 81 [0-9] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QK_2147782508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QK!MTB"
        threat_id = "2147782508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] 81 3d [0-8] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QL_2147782656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QL!MTB"
        threat_id = "2147782656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ec 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 81 3d [0-8] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QM_2147782776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QM!MTB"
        threat_id = "2147782776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 51 c7 45 fc 00 00 00 00 8b 45 0c 01 45 fc 8b 45 08 8b 08 33 4d fc 8b 55 08 89 0a 8b e5 5d c2 08 00}  //weight: 10, accuracy: High
        $x_10_2 = {03 4d 08 8b 55 fc 03 55 08 8a 02 88 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QM_2147782776_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QM!MTB"
        threat_id = "2147782776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 81 3d [0-8] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QN_2147782833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QN!MTB"
        threat_id = "2147782833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 81 3d [0-8] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QO_2147782920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QO!MTB"
        threat_id = "2147782920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 51 8d [0-2] 52 e8 [0-4] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QP_2147782977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QP!MTB"
        threat_id = "2147782977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {be d8 85 40 00 09 c0 e8 ?? ?? ?? ?? 31 33 43 68 ?? ?? ?? ?? 58 48 39 d3 75 e6 48 21 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QP_2147782977_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QP!MTB"
        threat_id = "2147782977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 29 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EDV_2147783111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EDV!MTB"
        threat_id = "2147783111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 45 f0 04 8a c3 02 c0 f6 da 2a d0 00 55 ff 81 7d f0 10 08}  //weight: 10, accuracy: High
        $x_10_2 = {8a c1 02 45 e8 2c 38 88 45 ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QQ_2147783144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QQ!MTB"
        threat_id = "2147783144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 6b [0-2] 03 [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QR_2147783314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QR!MTB"
        threat_id = "2147783314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 6b [0-2] 03 [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 29 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_QS_2147783386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QS!MTB"
        threat_id = "2147783386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 6b [0-2] 03 [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QT_2147783495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QT!MTB"
        threat_id = "2147783495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 0f 21 d8 81 c7 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 39 d7 75 e7 81 c6 ?? ?? ?? ?? c3 81 c1 ?? ?? ?? ?? 39 c7 75 e3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QT_2147783495_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QT!MTB"
        threat_id = "2147783495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] c7 [0-6] 8b [0-2] 01 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ea 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 29 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_QU_2147783632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QU!MTB"
        threat_id = "2147783632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] c7 [0-6] 8b [0-2] 01 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QV_2147783756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QV!MTB"
        threat_id = "2147783756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 5d 74 89 [0-5] 89 [0-5] 8b [0-5] 29 [0-2] 81 3d [0-8] 8b [0-5] 29 [0-2] ff [0-5] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MZK_2147784119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MZK!MTB"
        threat_id = "2147784119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0d e4 6e 63 00 8a 8c 01 [0-4] 8b 15 [0-4] 88 0c 02 8b 15 [0-4] 40 3b c2 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 8d a8 fd ff ff 03 c8 c1 e8 05 89 45 [0-1] c7 05 [0-3] 00 [0-4] 8b 85 9c fd ff ff 01 45 00 81 3d [0-3] 00 [0-4] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MAK_2147784120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MAK!MTB"
        threat_id = "2147784120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8d a8 fd ff ff 03 c8 c1 e8 05 89 45 [0-1] c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 9c fd ff ff 01 45 00 81 3d [0-6] 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 5d 74 89 3d [0-4] 89 9d ac fd ff ff 8b 85 ac fd ff ff 29 45 [0-1] 81 3d [0-6] 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QW_2147784715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QW!MTB"
        threat_id = "2147784715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e0 04 89 01 c3 55 8b ec 51 83 65 fc 00 8b 45 08 01 45 fc 8b 45 fc 31 01 c9 c2 04 00 33 44 24 04 c2 04 00}  //weight: 10, accuracy: High
        $x_10_2 = {01 45 fc 8b 45 fc 8a 04 08 88 04 31 41}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_QW_2147784715_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.QW!MTB"
        threat_id = "2147784715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 [0-2] 8b [0-2] 03 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 50 8d [0-2] 51 e8 [0-4] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_SM_2147786468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.SM!MTB"
        threat_id = "2147786468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 45 70 81 3d ?? ?? ?? 00 b6 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c7 47 86 c8 61 ff 8d ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 8b 85 98 fd ff ff 8b 4d 70 5f 5e 89 58 04 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ADA_2147787517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ADA!MTB"
        threat_id = "2147787517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 0e 81 ea 01 00 00 00 81 c6 04 00 00 00 39 c6 75 e9}  //weight: 10, accuracy: High
        $x_10_2 = {8b 34 24 83 c4 04 81 ef 7c ad cf d2 81 ea ce 1e 34 72 58 89 d3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_B_2147787518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.B!MTB"
        threat_id = "2147787518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 34 24 83 c4 04 e8 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 31 30 ba ?? ?? ?? ?? 40 81 e9 ?? ?? ?? ?? 39 d8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_B_2147787518_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.B!MTB"
        threat_id = "2147787518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 10 43 81 fb 10 00 00 00 75 0e 33 db eb 0a}  //weight: 10, accuracy: High
        $x_10_2 = {49 83 f9 ff 74 74 bb 28 00 00 00 0f af d9 51 a1 ?? ?? ?? ?? 83 c0 10 0f b7 10 03 da}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AMQ_2147787713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AMQ!MTB"
        threat_id = "2147787713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rugoxazewojehararebac" ascii //weight: 3
        $x_3_2 = "kizanugukofuhidepupati" ascii //weight: 3
        $x_3_3 = "hilunujusafe" ascii //weight: 3
        $x_3_4 = "jixazavobutozixuhopa" ascii //weight: 3
        $x_3_5 = "ZombifyActCtx" ascii //weight: 3
        $x_3_6 = "GetProcessShutdownParameters" ascii //weight: 3
        $x_3_7 = "SetFirmwareEnvironmentVariableA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AB_2147788426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AB!MTB"
        threat_id = "2147788426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ripopenarenejamenomoto" ascii //weight: 3
        $x_3_2 = "kapepujasapivazujijowofako" ascii //weight: 3
        $x_3_3 = "morinurelenivayofufecumicaxufo" ascii //weight: 3
        $x_3_4 = "lubanaxuxicacuberetazofexidihil" ascii //weight: 3
        $x_3_5 = "lesebejawesamulu" ascii //weight: 3
        $x_3_6 = "musizunicatewiwoci" ascii //weight: 3
        $x_3_7 = "jujalojoxiju" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AS_2147789252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AS!MTB"
        threat_id = "2147789252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8b 5d 08 8d 0c 3e 8a 14 02 32 14 0b 46 88 11}  //weight: 10, accuracy: High
        $x_10_2 = {66 b8 b8 1a 66 bb bb 06 66 b9 b9 00 66 ba ba 01 66 be be ff 66 bf bf 32}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_SIB_2147794792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.SIB!MTB"
        threat_id = "2147794792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d6 8b 55 ?? 52 83 e2 00 0b 55 0c 83 e7 00 31 d7 5a 50 51 8b 4e ?? 89 4c e4 04 59 57 6a [0-4] 89 34 e4 31 f6 0b b3 ?? ?? ?? ?? 89 f1 5e 56 89 ce 81 c6 ?? ?? ?? ?? 89 f1 5e 51 50 8b 06 56 8f 45 ?? 01 45 05 ff 75 05 5e 58 a4 49 75 ?? 59 5f 52 2b 14 e4 31 fa 83 e6 00 09 d6 5a 53 0f b6 06 46 85 c0 74 4e 51 55 c7 04 e4 ?? ?? ?? ?? 59 bb 00 00 00 00 89 45 ?? 83 e0 00 09 f0 83 e2 00 09 c2 8b 45 0a 21 5d ?? 57 8b 7d 0c 81 c7 ?? ?? ?? ?? 89 7d 0c 5f d3 c0 8a fc 8a e6 d3 cb ff 4d 0c 75 ?? 59 89 55 ?? 2b 55 12 09 da 83 e0 00 09 d0 8b 55 12 aa 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ED_2147797782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ED!MTB"
        threat_id = "2147797782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 30 39 30 43 30 6c 30 c0 30 dc 30 1c 31 4c 31 63 31 6c 31 75 31 8f 31 ac 31 d8 31 e1 31 fc 31 28 32 01 33 1d 33 3e 33 a9 33 b4 33 d5 33 dc 33 d6 34 39 35 44 35 14 36 21 36 2f 36 39 36 4b 36 50 36 5d 36 6c 36 9b 36 2e 37 3a 37 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPA_2147807733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPA!MTB"
        threat_id = "2147807733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 3b 21 d0 81 c3 04 00 00 00 39 f3 75 f2 81 c1 ac 53 a9 f7 81 e9 01 00 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPA_2147807733_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPA!MTB"
        threat_id = "2147807733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 db 29 df 31 16 47 81 eb ?? ?? ?? ?? 46 47 39 ce 75 df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPC_2147807735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPC!MTB"
        threat_id = "2147807735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 10 4e 47 81 c0 01 00 00 00 01 f7 01 ff 39 d8 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPC_2147807735_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPC!MTB"
        threat_id = "2147807735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 d2 74 01 ea 31 0b ?? ?? ?? ?? 81 c3 04 00 00 00 39 f3 75 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPD_2147807782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPD!MTB"
        threat_id = "2147807782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 ff 74 01 ea 31 39 ?? ?? ?? ?? 81 c1 04 00 00 00 39 d1 75 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPD_2147807782_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPD!MTB"
        threat_id = "2147807782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4d 08 8b 55 fc f7 da 8b 45 08 8b 08 2b ca 8b 55 08 89 0a 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPE_2147807783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPE!MTB"
        threat_id = "2147807783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 ff 74 01 ea 31 19 ?? ?? ?? ?? 81 c1 04 00 00 00 47 39 c1 75 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPE_2147807783_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPE!MTB"
        threat_id = "2147807783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 c9 74 01 ea 31 08 21 d3 81 c0 04 00 00 00 29 df 68 ?? ?? ?? ?? 5a 39 f0 75 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPF_2147807784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPF!MTB"
        threat_id = "2147807784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 c9 74 01 ea 31 03 [0-16] 81 c3 04 00 00 00 39 d3 75 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPN_2147809872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPN!MTB"
        threat_id = "2147809872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 d8 85 40 00 83 ec 04 c7 04 24 f2 6d eb 01 5b 81 c2 3f 8f 8c e1 e8 1b 00 00 00 81 c3 91 fb 44 88 4a 31 01 41 21 da 01 d2 39 f1 75 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPN_2147809872_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPN!MTB"
        threat_id = "2147809872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 db 74 01 ea 31 17 [0-16] 81 c7 04 00 00 00 [0-16] 39 c7 75 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPO_2147809873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPO!MTB"
        threat_id = "2147809873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 d2 74 01 ea 31 18 [0-16] 81 c0 04 00 00 00 39 d0 75 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPP_2147809874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPP!MTB"
        threat_id = "2147809874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 f6 74 01 ea 31 07 [0-16] 81 c7 04 00 00 00 39 cf 75 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPQ_2147809875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPQ!MTB"
        threat_id = "2147809875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 0a 8b 09 81 e1 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {31 08 81 ee ?? ?? ?? ?? 89 fe 40 29 fe 4e 39 d8 75 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_RPU_2147810514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPU!MTB"
        threat_id = "2147810514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 11 4e 81 c1 01 00 00 00 39 d9 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = {8d 14 10 8b 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPB_2147810517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPB!MTB"
        threat_id = "2147810517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 16 41 4f 46 bf ?? ?? ?? ?? 39 de 75 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPB_2147810517_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPB!MTB"
        threat_id = "2147810517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 18 81 c2 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 81 c0 04 00 00 00 09 fa 39 f0 75 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {31 30 21 d1 81 c1 ?? ?? ?? ?? 81 c0 04 00 00 00 01 d1 39 f8 75 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_CE_2147811620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.CE!MTB"
        threat_id = "2147811620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 39 81 c3 [0-4] 81 c6 [0-4] 81 c1 04 00 00 00 09 de 81 ee [0-4] 39 d1 75 db}  //weight: 2, accuracy: Low
        $x_2_2 = {31 30 89 ca 29 d1 81 c0 04 00 00 00 4a 29 da 39 f8 75 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_G_2147813183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.G"
        threat_id = "2147813183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rss\\csrss.exe" wide //weight: 1
        $x_1_2 = "failed to write an injector file" ascii //weight: 1
        $x_1_3 = "application/resilience/blockchaincom.findLatestTransactionData" ascii //weight: 1
        $x_1_4 = "WinmonFS!WinmonFSInstanceSetup: Entered" ascii //weight: 1
        $x_1_5 = "bitcoin3nqy3db7c.onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GZK_2147814056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GZK!MTB"
        threat_id = "2147814056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {bf d8 85 40 00 21 c1 e8 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 48 31 3b 01 c8 43 39 f3 75 e4 41 c3 21 c9 8d 3c 17}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GT_2147814283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GT!MTB"
        threat_id = "2147814283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 0f 29 c0 21 d8 81 c7 04 00 00 00 39 f7 75 eb 42 81 c2 ?? ?? ?? ?? c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GT_2147814283_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GT!MTB"
        threat_id = "2147814283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 0e 01 da 81 c6 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 29 d0 39 fe 75 e5 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {31 0b 81 c2 ?? ?? ?? ?? 4e 81 c3 ?? ?? ?? ?? 4a bf ?? ?? ?? ?? 39 c3 75 e2 81 ee}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_GTM_2147814418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GTM!MTB"
        threat_id = "2147814418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 03 49 81 c7 ?? ?? ?? ?? 43 01 c9 39 d3}  //weight: 10, accuracy: Low
        $x_10_2 = {31 06 46 bf ?? ?? ?? ?? 47 39 ce ?? ?? c3 47 21 ff 8d 04 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_GTM_2147814418_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GTM!MTB"
        threat_id = "2147814418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {be d8 85 40 00 89 ff 81 ef 34 68 a4 a9 e8 ?? ?? ?? ?? 29 ff 81 eb 97 48 80 39 31 32 4f 89 ff 42 53 5f 39 c2 75 da 21 ff c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GY_2147814508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GY!MTB"
        threat_id = "2147814508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 f8 31 16 29 c0 b8 ?? ?? ?? ?? 46 21 c0 39 ce 75 dd 89 c7 89 f8 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GW_2147814678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GW!MTB"
        threat_id = "2147814678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 13 b8 68 cc 32 6c 81 c3 ?? ?? ?? ?? 81 ef 42 70 96 e3 21 c0 39 f3 75 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GV_2147814816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GV!MTB"
        threat_id = "2147814816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {42 e8 11 00 00 00 4a 31 33 09 c9 43 89 d1 21 ca 39 fb 75 e7 09 c9 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GI_2147815241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GI!MTB"
        threat_id = "2147815241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 df 31 10 47 29 db 81 c0 01 00 00 00 39 c8 75 e3 21 fb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_H_2147815459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.H!MTB"
        threat_id = "2147815459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 34 24 83 c4 04 e8 ?? ?? ?? ?? 31 01 29 db 41 43 39 d1 75 e0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_HM_2147815461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.HM!MTB"
        threat_id = "2147815461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 0a 21 ff 42 21 db bb 1f 0a 34 ab 39 f2 75 e5 81 ef 94 b7 01 e0 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_K_2147815549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.K!MTB"
        threat_id = "2147815549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5a 4f e8 18 00 00 00 89 ff 31 11 83 ec 04 89 1c 24 5f 47 41 39 f1 75 e3 29 db 47 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_P_2147815614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.P!MTB"
        threat_id = "2147815614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 c9 21 ff e8 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 49 31 02 81 e9 ?? ?? ?? ?? 41 42 09 c9 39 f2 75 db 51 59 29 ff c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPG_2147816000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPG!MTB"
        threat_id = "2147816000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 f6 31 17 81 ee ?? ?? ?? ?? 29 c0 47 39 df [0-16] 8d 14 0a 8b 12 81 e2 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 81 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPH_2147816001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPH!MTB"
        threat_id = "2147816001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 13 81 c3 04 00 00 00 39 cb 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPH_2147816001_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPH!MTB"
        threat_id = "2147816001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 3e 46 40 39 de 75 [0-16] 29 d0 8d 3c 39 01 c0 21 d0 8b 3f 01 c0 81 e7 ff 00 00 00 41 81 f9 f4 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AD_2147816062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AD!MTB"
        threat_id = "2147816062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 3a 42 39 da 75 ec c3 8d 3c 37 8b 3f 40 09 c9 81 e7 ?? ?? ?? ?? 29 c0 81 c6 ?? ?? ?? ?? 40 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AN_2147816063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AN!MTB"
        threat_id = "2147816063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 d7 ba 06 bc 76 9d 31 0b 81 ea ?? ?? ?? ?? 43 57 5a 39 f3 75 e0 57 5f 68 ?? ?? ?? ?? 8b 14 24 83 c4 04 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GE_2147816291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GE!MTB"
        threat_id = "2147816291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {29 c9 31 3a 41 81 c2 01 00 00 00 41 39 da 75 e4 01 c0 c3 29 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GJ_2147816382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GJ!MTB"
        threat_id = "2147816382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d2 83 ec 04 c7 04 24 ?? ?? ?? ?? 8b 14 24 83 c4 04 e8 ?? ?? ?? ?? 29 fa 31 0e 46 39 c6 75 db c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_BX_2147816724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.BX!MTB"
        threat_id = "2147816724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 83 c4 04 e8 ?? ?? ?? ?? 09 d8 4b 31 16 48 43 46 21 d8 89 c3 39 ce 75 db}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_BZ_2147816790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.BZ!MTB"
        threat_id = "2147816790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 21 db 49 e8 ?? ?? ?? ?? 21 cb 29 c9 31 17 09 db 68 ?? ?? ?? ?? 8b 0c 24 83 c4 04 81 c7 ?? ?? ?? ?? 01 c9 39 c7 75 d3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_BZ_2147816790_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.BZ!MTB"
        threat_id = "2147816790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 d8 85 40 00 81 eb ?? ?? ?? ?? e8 ?? ?? ?? ?? 31 07 bb a7 16 e9 ba 47 81 e9 ?? ?? ?? ?? 39 d7 75 de 09 cb bb 36 c6 8a dd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_BA_2147817205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.BA!MTB"
        threat_id = "2147817205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 32 68 98 50 18 6c 5b 81 c2 ?? ?? ?? ?? 29 d8 39 fa 75 e7 01 c3 81 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AE_2147817312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AE!MTB"
        threat_id = "2147817312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 13 09 fe 81 c3 04 00 00 00 56 59 56 5f 39 c3 75 e9}  //weight: 2, accuracy: High
        $x_2_2 = {31 11 81 e8 [0-4] 21 db 81 c1 04 00 00 00 43 39 f1 75 e6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_AFX_2147817950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AFX!MTB"
        threat_id = "2147817950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 10 4e 89 ce 81 c0 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 39 f8 75 e6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_FBX_2147817952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.FBX!MTB"
        threat_id = "2147817952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 df b8 d8 85 40 00 09 ff e8 ?? ?? ?? ?? 09 fb 31 01 81 c1 01 00 00 00 39 d1 75 e6 09 db c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_FK_2147817983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.FK!MTB"
        threat_id = "2147817983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {81 c3 01 00 00 00 b8 d8 85 40 00 4f 29 df e8 10 00 00 00 31 01 81 c1 01 00 00 00 21 db 39 d1 75 e5 4b c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_FL_2147818114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.FL!MTB"
        threat_id = "2147818114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 3e 48 81 c6 04 00 00 00 39 ce 75 ee 01 c0 43 c3 00 39 d7 75 e7 81 c6 ?? ?? ?? ?? c3 81 c1 ?? ?? ?? ?? 39 c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_FQ_2147818259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.FQ!MTB"
        threat_id = "2147818259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 d8 85 40 00 58 09 fe 81 ef ?? ?? ?? ?? e8 ?? ?? ?? ?? 01 f6 46 31 01 29 f7 47 41 39 d9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_BC_2147818446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.BC!MTB"
        threat_id = "2147818446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 1a 81 c7 79 19 cb 16 81 c2 04 00 00 00 21 f9 41 39 f2 75 e6}  //weight: 1, accuracy: High
        $x_1_2 = {01 d2 81 ea 01 00 00 00 81 c1 01 00 00 00 29 d6 81 f9 1f be 00 01 75 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPJ_2147818469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPJ!MTB"
        threat_id = "2147818469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 1e 01 f9 89 c9 46 81 c1 ?? ?? ?? ?? 57 5f 39 d6 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPJ_2147818469_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPJ!MTB"
        threat_id = "2147818469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 db 74 01 ea 31 17 01 c0 81 c7 04 00 00 00 01 c3 39 cf 75 eb}  //weight: 1, accuracy: High
        $x_1_2 = {39 d2 74 01 ea 31 32 81 c2 04 00 00 00 09 c3 39 fa 75 ed}  //weight: 1, accuracy: High
        $x_1_3 = {39 c9 74 01 ea 31 0e 81 ea 04 1f 06 30 81 c6 04 00 00 00 29 fa 89 df 39 c6 75 e5}  //weight: 1, accuracy: High
        $x_1_4 = {39 c9 74 01 ea 31 18 81 c0 04 00 00 00 49 39 f0 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_FU_2147818529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.FU!MTB"
        threat_id = "2147818529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 dd 57 41 ac 5a 21 c0 31 39 21 c0 41 39 f1 75 de 50 8b 14 24 83 c4 04 4a c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_VZ_2147820013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.VZ!MTB"
        threat_id = "2147820013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 39 d2 74 01 ea 31 1e 81 c6 04 00 00 00 47 39 c6 75 ee 47 51 8b 0c 24 83 c4 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_XG_2147821502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.XG!MTB"
        threat_id = "2147821502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 fb 39 c6 ?? ?? 68 ?? ?? ?? ?? 59 09 ff c3 27 00 31 16 b9 ?? ?? ?? ?? 81 c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_XM_2147821923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.XM!MTB"
        threat_id = "2147821923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4a 39 c3 75 ?? 83 ec ?? 89 0c 24 8b 3c 24 83 c4 ?? c3 30 00 31 33 ba ?? ?? ?? ?? 81 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_XL_2147821943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.XL!MTB"
        threat_id = "2147821943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 16 09 d9 81 c6 ?? ?? ?? ?? 01 c9 41 39 fe 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_XK_2147822416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.XK!MTB"
        threat_id = "2147822416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 1a 81 c2 04 00 00 00 39 c2 ?? ?? b9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_XO_2147822949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.XO!MTB"
        threat_id = "2147822949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 ea 31 0f 81 ea ?? ?? ?? ?? be ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 09 d2 39 c7 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_XS_2147823606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.XS!MTB"
        threat_id = "2147823606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 3b 89 c6 81 ee ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 39 cb ?? ?? 09 c0 81 c2 ?? ?? ?? ?? c3 21 c2 40 81 c6 ?? ?? ?? ?? 39 fe 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_UJ_2147825922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.UJ!MTB"
        threat_id = "2147825922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 db 09 cb 31 17 43 81 c3 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 89 cb 29 db 39 f7 75 ?? 21 db c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_UM_2147826287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.UM!MTB"
        threat_id = "2147826287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 14 24 83 c4 ?? 53 5b e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 5b 31 17 be ?? ?? ?? ?? 01 de 47 39 c7 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AZ_2147826338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AZ!MTB"
        threat_id = "2147826338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 83 c4 ?? 21 db 89 f6 e8 ?? ?? ?? ?? 01 f3 46 31 02 42 81 c3 ?? ?? ?? ?? 01 f3 39 ca 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_UI_2147827154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.UI!MTB"
        threat_id = "2147827154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 74 01 ea 31 1e b9 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 4a 39 c6 75 ?? 81 c1 ?? ?? ?? ?? 81 ef}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_UL_2147827155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.UL!MTB"
        threat_id = "2147827155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {42 01 d7 01 ea 31 33 81 c3 ?? ?? ?? ?? b9 ?? ?? ?? ?? 39 c3 75 ea c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPX_2147828540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPX!MTB"
        threat_id = "2147828540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 ff be c6 ae cd 97 31 03 21 f6 43 39 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPX_2147828540_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPX!MTB"
        threat_id = "2147828540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 01 f6 31 0f 47 39 df 75 ea c3 52 8b 34 24 83 c4 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPX_2147828540_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPX!MTB"
        threat_id = "2147828540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5e e8 21 00 00 00 31 32 b9 ?? ?? ?? ?? 81 c2 01 00 00 00 81 c1 ?? ?? ?? ?? 83 ec 04 89 1c 24 59 39 fa 75 d2 89 c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPZ_2147831133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPZ!MTB"
        threat_id = "2147831133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 d2 74 01 ea 31 03 81 c3 04 00 00 00 39 f3 75 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPZ_2147831133_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPZ!MTB"
        threat_id = "2147831133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 31 19 41 89 f2 39 c1 75 e8 c3 81 c2 ?? ?? ?? ?? 46 8d 1c 3b 8b 1b 81 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPZ_2147831133_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPZ!MTB"
        threat_id = "2147831133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 df 31 32 47 42 43 39 c2 75 e0 81 c3 01 00 00 00 c3 81 eb 01 00 00 00 8d 34 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_SRP_2147835408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.SRP!MTB"
        threat_id = "2147835408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 d4 83 c2 01 89 55 d4 8b 45 d4 3b 45 10 73 63 6a 00 ff 15 00 10 41 00 8b 4d d4 81 e1 03 00 00 80 79 05 49 83 c9 fc 41 8b 55 08 0f be 04 0a 8b 4d 0c 03 4d d4 0f be 11 33 c2 88 45 d2 8b 45 0c 03 45 d4 8a 08 88 4d d3 0f be 55 d2 0f be 45 d3 03 d0 8b 4d 0c 03 4d d4 88 11 0f be 55 d3 8b 45 0c 03 45 d4 0f be 08 2b ca 8b 55 0c 03 55 d4 88 0a eb 8c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GTB_2147835752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GTB!MTB"
        threat_id = "2147835752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 83 c4 04 89 f6 68 ?? ?? ?? ?? 8b 3c 24 83 c4 04 e8 ?? ?? ?? ?? 31 01 21 f7 41 01 f7 21 ff 39 d9 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GAF_2147836441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GAF!MTB"
        threat_id = "2147836441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d8 85 40 00 81 c7 ?? ?? ?? ?? e8 ?? ?? ?? ?? 21 ff 01 db 31 06 01 df 81 c6 ?? ?? ?? ?? 39 ce 75}  //weight: 10, accuracy: Low
        $x_10_2 = {d8 85 40 00 68 ?? ?? ?? ?? 8b 34 24 83 c4 04 29 c6 e8 ?? ?? ?? ?? 81 ee ?? ?? ?? ?? 46 31 3a 42 40 81 e8 ?? ?? ?? ?? 39 da 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_DM_2147836469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DM!MTB"
        threat_id = "2147836469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {be d8 85 40 00 b9 56 fe 4b 02 01 ca e8 [0-4] 31 30 40 39 d8 75 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {29 c1 b9 a7 22 ea f9 5f 21 c9 42 48 48 81 fa 6b b1 00 01 75 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DN_2147836848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DN!MTB"
        threat_id = "2147836848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 de 29 f3 e8 [0-4] 09 db 31 17 bb da a8 70 80 81 eb 58 7a ec e7 81 c7 01 00 00 00 39 c7 75}  //weight: 2, accuracy: Low
        $x_2_2 = {59 56 5b 81 c3 01 00 00 00 29 f6 81 c2 01 00 00 00 81 c3 01 00 00 00 81 fa 78 ee 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DO_2147837103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DO!MTB"
        threat_id = "2147837103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {21 ca 57 29 ca 5e 81 e9 e8 53 9f 3a 43 81 e9 21 2a e5 23 41 81 c2 8b 9e 80 ab 81 fb f3 e4 00 01 75}  //weight: 2, accuracy: High
        $x_2_2 = {31 1a 42 21 cf 29 ff 39 c2 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPM_2147838376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPM!MTB"
        threat_id = "2147838376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 3e 81 c6 04 00 00 00 39 de 75 ef 09 c9 c3}  //weight: 1, accuracy: High
        $x_1_2 = {31 3b 01 c9 81 c3 04 00 00 00 81 e9 01 00 00 00 39 d3 75 e7 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PPC_2147843555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PPC!MTB"
        threat_id = "2147843555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 44 24 18 8b 44 24 18 89 44 24 1c 8b 54 24 1c 31 54 24 ?? 8b f3 c1 ee 05 03 74 24 34 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 06 ff 15 ?? ?? ?? ?? 8b 44 24 14 33 c6 89 44 24 14 50 8b c7 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EH_2147843691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EH!MTB"
        threat_id = "2147843691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {21 d0 31 3e 29 d2 21 d0 46 01 c0 48 39 ce}  //weight: 5, accuracy: High
        $x_5_2 = {31 37 21 c2 47 40 39 df 75 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_GHC_2147843784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GHC!MTB"
        threat_id = "2147843784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 08 81 c0 ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 4e 39 d0 75 ?? 21 fe c3 c3 04 00}  //weight: 10, accuracy: Low
        $x_10_2 = {31 06 81 c1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 39 d6 75 ?? 83 ec 04 89 3c 24 5f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_EM_2147843919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EM!MTB"
        threat_id = "2147843919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4b 81 eb 01 00 00 00 31 32 42 09 df 68 0f dd 4e 8c 5f 39 c2 75 dd}  //weight: 5, accuracy: High
        $x_5_2 = {8d 04 18 81 e9 01 00 00 00 41 8b 00 29 cf 57 59 81 e0 ff 00 00 00 51 5f 09 f9 43 89 ff 81 fb f4 01 00 00 75 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_GHJ_2147844182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GHJ!MTB"
        threat_id = "2147844182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 03 09 c9 81 e9 ?? ?? ?? ?? 81 c3 04 00 00 00 47 01 f9 39 f3 75 e4 21 cf 01 d2 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GHK_2147844264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GHK!MTB"
        threat_id = "2147844264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5f 81 c6 01 00 00 00 e8 ?? ?? ?? ?? 29 f2 31 3b 81 ee ?? ?? ?? ?? 43 81 ea ?? ?? ?? ?? 39 cb 75 da 09 f2 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GHM_2147844419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GHM!MTB"
        threat_id = "2147844419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 ff 89 d7 bb ?? ?? ?? ?? 09 d7 89 d7 e8 ?? ?? ?? ?? 31 1e 46 39 c6 75 ?? c3 09 d7 47 8d 1c 0b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PPD_2147845750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PPD!MTB"
        threat_id = "2147845750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 00 00 00 00 8b 44 24 ?? 89 04 24 8b ?? 24 44 31 04 24 8b 04 24 8b 4c 24 40 89 01 83 c4 3c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 10 29 44 24 14 81 44 24 24 47 86 c8 61 83 ed 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GHX_2147845767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GHX!MTB"
        threat_id = "2147845767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 1c 24 83 c4 04 01 f2 68 ?? ?? ?? ?? 5a e8 ?? ?? ?? ?? 21 f2 21 f6 31 18 40 29 f2 39 c8 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GIC_2147845954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GIC!MTB"
        threat_id = "2147845954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 04 24 83 c4 04 e8 ?? ?? ?? ?? 29 ff 81 c7 ?? ?? ?? ?? 31 02 42 39 f2 75 e1 21 cf}  //weight: 10, accuracy: Low
        $x_10_2 = {5b 29 f6 29 d2 e8 ?? ?? ?? ?? 31 1f 47 21 f6 39 cf 75 ?? c3 21 d2 8d 1c 18 46 21 d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_GID_2147846260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GID!MTB"
        threat_id = "2147846260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 3e 21 db 29 d9 81 c6 04 00 00 00 39 c6 75 ?? 89 ca 21 d3 c3 81 c3 ?? ?? ?? ?? 89 d6 7f}  //weight: 10, accuracy: Low
        $x_10_2 = {31 38 81 c0 04 00 00 00 39 f0 75 ?? 01 d3 c3 ba ?? ?? ?? ?? 29 ca e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_MKV_2147846618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MKV!MTB"
        threat_id = "2147846618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ee 03 74 24 ?? 8b 44 24 ?? 31 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 53 53 53 ff 15 ?? ?? ?? ?? 8b 44 24 10 33 c6 89 44 24 10 2b f8 8b 44 24 38 29 44 24 14 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MKV_2147846618_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MKV!MTB"
        threat_id = "2147846618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 8b cb 8d 44 24 ?? 89 54 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 50 51 8d 54 24 ?? 52 e8 ?? ?? ?? ?? 8b 44 24 ?? 50 8b c6 e8 ?? ?? ?? ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 8b f0 89 74 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PIA_2147846830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PIA!MTB"
        threat_id = "2147846830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 2c 01 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? d3 ea 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 28 e8 ?? ?? ?? ?? 8b 44 24 20 31 44 24 10 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PIB_2147846831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PIB!MTB"
        threat_id = "2147846831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10 8b 44 24 24 01 44 24 10 03 de 31 5c 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PIC_2147846832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PIC!MTB"
        threat_id = "2147846832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 44 24 20 8b 4c 24 1c 8b 54 24 14 d3 ea 8b 4c 24 40 8d 44 24 28 c7 05 ?? ?? ?? ?? 89 54 24 28 e8 ?? ?? ?? ?? 8b 44 24 20 31 44 24 10 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPY_2147846849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPY!MTB"
        threat_id = "2147846849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 17 09 db 89 f3 47 4e 39 cf 75 e3 c3 81 eb 01 00 00 00 09 db 8d 14 02 8b 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPY_2147846849_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPY!MTB"
        threat_id = "2147846849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 ff 75 d4 8b 45 fc ff 50 18 8b 55 fc 89 42 28 8d 45 d8 50 8b 45 fc ff 50 1c 8b 45 fc 8b 55 dc 89 50 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPY_2147846849_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPY!MTB"
        threat_id = "2147846849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 57 8b 34 24 83 c4 04 31 0b 43 81 ee ?? ?? ?? ?? 01 f6 39 d3 75 df 56 5f 47 c3 8d 0c 01 81 c7 01 00 00 00 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RPY_2147846849_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RPY!MTB"
        threat_id = "2147846849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c7 33 c1 2b f0 89 44 24 10 8b c6 c1 e0 04}  //weight: 1, accuracy: High
        $x_1_2 = {89 44 24 10 8b 44 24 24 01 44 24 10 03 de 31 5c 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_PID_2147847120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PID!MTB"
        threat_id = "2147847120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 00 00 00 00 8b 44 24 ?? 89 04 24 8b 44 24 44 31 04 24 8b 04 24 8b 4c 24 40 89 01 83 c4 3c c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DS_2147848032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DS!MTB"
        threat_id = "2147848032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {29 db 09 db 31 10 09 ff 81 eb a4 1b 7d cd 40 81 eb 01 00 00 00 39 f0 75}  //weight: 3, accuracy: High
        $x_3_2 = {b9 c0 59 50 3f 81 c0 57 2c 06 57 31 3b 09 c8 b9 4f fc ce 7f 81 c3 01 00 00 00 01 c9 29 c8 39 d3 75}  //weight: 3, accuracy: High
        $x_2_3 = {57 81 c1 6d 5a 24 91 5b 09 d1 41 40 4a 29 d2 81 f8 2e f3 00 01 75}  //weight: 2, accuracy: High
        $x_2_4 = {53 29 d2 5f 81 c0 9d dd 4a 1a 81 c1 01 00 00 00 40 01 c2 81 f9 d5 88 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Glupteba_PAI_2147848441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.PAI!MTB"
        threat_id = "2147848441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 33 44 24 24 89 44 24 10 2b f0 8d 44 24 28 e8 ?? ?? ?? ?? 83 6c 24 30 01 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 10 31 4c 24 24 8b 44 24 24 83 44 24 14 ?? 29 44 24 14 83 6c 24 14 ?? 8b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_YAD_2147851167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.YAD!MTB"
        threat_id = "2147851167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 05 03 44 24 ?? 03 ?? 33 c2 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 14 c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 0c 8b 44 24 28 01 44 24 0c 81 3d ?? ?? ?? ?? be 01 00 00 8d 3c 33}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 c1 e8 05 03 44 24 ?? 03 d5 33 c2 03 cb 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 ?? c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 ?? 8b 44 24 28 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 3c 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_YAE_2147852349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.YAE!MTB"
        threat_id = "2147852349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e0 01 45 fc 8b 45 f8 8b 4d f0 8d 14 01 8b 4d f4 31 55 fc ff 75 fc d3 e8 03 c3 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_YAF_2147852581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.YAF!MTB"
        threat_id = "2147852581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 44 24 24 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c1 8d 0c 33 33 c1 2b f8 8b d7 c1 e2 04 81 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 14 8b 44 24 10 33 d5 33 c2 2b f0 81 c3 ?? ?? ?? ?? ff 4c 24 18 89 44 24 10 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_YAG_2147853426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.YAG!MTB"
        threat_id = "2147853426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d7 d3 ea 03 c7 03 55 e0 33 d0 31 55 f8 8b 45 f8 29 45 ec ff 4d e4 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EA_2147888211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EA!MTB"
        threat_id = "2147888211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d f0 8b 45 f4 8b d3 d3 ea 03 c3 03 55 d8 33 d0 31 55 f8 2b 7d f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EA_2147888211_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EA!MTB"
        threat_id = "2147888211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d7 33 d6 c7 05 ?? ?? ?? ?? ff ff ff ff 2b da 8b 44 24 1c 29 44 24 10 83 6c 24 14 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_DAX_2147888474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.DAX!MTB"
        threat_id = "2147888474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 db 74 01 ea 31 0f 81 c7 04 00 00 00 89 db 39 c7 75}  //weight: 1, accuracy: High
        $x_1_2 = {29 cb 01 db 57 01 cb 5a 09 d9 81 c6 01 00 00 00 83 ec 04 c7 04 24 f8 bd ae dc 5b 81 fe 3e d8 00 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GMF_2147888609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GMF!MTB"
        threat_id = "2147888609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 ea 31 0a 81 c2 04 00 00 00 39 fa ?? ?? c3 81 ee ?? ?? ?? ?? 89 f3 39 db}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GMH_2147888924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GMH!MTB"
        threat_id = "2147888924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 ff 01 ea 31 38 89 db 01 c9 81 c0 04 00 00 00 bb ?? ?? ?? ?? 39 d0 75 ?? 89 ce c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GME_2147890554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GME!MTB"
        threat_id = "2147890554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 0e 09 ff 81 c6 ?? ?? ?? ?? 89 c7 21 c0 39 d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GMP_2147892440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GMP!MTB"
        threat_id = "2147892440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 19 47 81 c1 04 00 00 00 39 f1 75 ?? c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GMQ_2147892569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GMQ!MTB"
        threat_id = "2147892569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 02 81 c7 ?? ?? ?? ?? 81 c2 04 00 00 00 39 f2 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ASB_2147893083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASB!MTB"
        threat_id = "2147893083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 fc 8b 55 f8 8b 4d f4 8b c2 d3 e8 03 fa 03 45 d4 33 c7 31 45 fc ff 75 fc 8b c3}  //weight: 1, accuracy: High
        $x_1_2 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MBJV_2147893154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MBJV!MTB"
        threat_id = "2147893154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a1 dc 4a fa 02 8a 84 30 4b 13 01 00 8b 0d 2c 3a fa 02 88 04 31 75}  //weight: 2, accuracy: High
        $x_1_2 = "lahanekucofijajiwaw" ascii //weight: 1
        $x_1_3 = "sewomexikijalodedeleve soyugoloraci yamazid" ascii //weight: 1
        $x_1_4 = "rujehulayafaligubovotodeho" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MBKI_2147893590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MBKI!MTB"
        threat_id = "2147893590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 00 6f 00 64 00 65 00 68 00 6f 00 6c 00 6f 00 66 00 61 00 66 00 75 00 79 00 00 00 7a 75 62 61 73 6f 00 00 6b 65 67 75 64 69 74 61 78 75}  //weight: 1, accuracy: High
        $x_1_2 = {65 00 62 00 6f 00 7a 00 75 00 62 00 6f 00 64 00 00 00 6e 00 69 00 67 00 6f 00 63}  //weight: 1, accuracy: High
        $x_1_3 = "gixamohesobubodeholofafuy" ascii //weight: 1
        $x_1_4 = "vayehizepovifi" ascii //weight: 1
        $x_1_5 = "juyojewipihehiyoxiyenexegitom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ASC_2147893954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASC!MTB"
        threat_id = "2147893954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 d3 ea 8d 04 3b 89 45 f0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 d8 8b 45 f0 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 f0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7c 24 14 d5 74 50 78 75 09 43 81 fb 1b 1c 00 00 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ASD_2147893955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASD!MTB"
        threat_id = "2147893955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gedevufiyilirowixujagedurobolujisayisadayahori" ascii //weight: 1
        $x_1_2 = "Tidevefofogoxa cozivuduy xavexixegukure" ascii //weight: 1
        $x_1_3 = "Notoreta bejopebodeluk loxirohirubeve nebawicameh" ascii //weight: 1
        $x_1_4 = "Tilucuk vejotesevidag munarijaraxe" ascii //weight: 1
        $x_1_5 = "Taj dan yivowiro gujokel" wide //weight: 1
        $x_1_6 = "wurohetapoderikib xupin mahewog" ascii //weight: 1
        $x_1_7 = "posinokizuvuvonegezumubejox darovuzevohagimuwurimoponifag gedaguwepidizewedajakovociwogome" ascii //weight: 1
        $x_1_8 = "muribupululomezojinovaditumalaw cafuvitirehifoxicoxuneceveyevoto hetet" ascii //weight: 1
        $x_1_9 = "makovakatujihemo xiwuvicawifenufezoperomewipiw wiroviyihuderewukefavibinixukatu segirisamamogodapamapupivulacus" ascii //weight: 1
        $x_1_10 = "tuhorubebisayosajinicehujabev" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Glupteba_ASE_2147893967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASE!MTB"
        threat_id = "2147893967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 8d 04 3b d3 ef 89 45 f0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d ?? 8b 45 f0 31 45 fc 33 7d fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 7d f0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 8d 3c 13 03 45 e0 33 c7 31 45 fc 8b 4d fc 8d 45 ec e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ASF_2147893968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASF!MTB"
        threat_id = "2147893968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "funeyohudonupabihasaxakisen" wide //weight: 1
        $x_1_2 = "cfuhixojuwedejefopoyajafewi" wide //weight: 1
        $x_1_3 = "Yitekoj kusugexe wifuhitohininoy bowoce madolaluxij" wide //weight: 1
        $x_1_4 = "luzeyajowunikapopoxumakideyip" wide //weight: 1
        $x_1_5 = "wupugemoj jig zugeyizexajukabibalocohadixixuzi" wide //weight: 1
        $x_1_6 = "xupudujotekilaguf zilomesatayebiralitici cacizuyawewutiduyu" wide //weight: 1
        $x_1_7 = "onukixarok pesumamusuyobirubamuhixojewawu deyahofivihucihi" wide //weight: 1
        $x_1_8 = "jiyufigeviwotayap kukavuhu muhojoxiwalayokuyey kogani nuxolilenud" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Glupteba_ASG_2147894288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASG!MTB"
        threat_id = "2147894288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 10 8b 44 24 28 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 2c 3b 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f5 31 74 24 10 8b 44 24 10 29 44 24 14 81 c3 ?? ?? ?? ?? ff 4c 24 1c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MBKO_2147894421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MBKO!MTB"
        threat_id = "2147894421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 45 f4 01 8b 45 fc 8b 55 f4 8d 1c 10 ba 0c a0 40 00 8b 45 f4 8a 44 02 ff 88 43 ff 3b 4d f4 77 df 6a 40 68 00 30 00 00 68 01 00 06 00 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ASH_2147894623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASH!MTB"
        threat_id = "2147894623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nemiwapubixokevajuzanupeh tifij fufesuwupatamuyuve" ascii //weight: 1
        $x_1_2 = "pubabot pivaneniguyoko biwozenixufefer gudajohazokozisujoc dukefozatuvihoni" ascii //weight: 1
        $x_1_3 = "yogoripajoruxurepinedafa" ascii //weight: 1
        $x_1_4 = "zujapijovowasekuheyaditusa" ascii //weight: 1
        $x_1_5 = "cuxabugazen muzomexulasewuticobaj zoxupefu benaxoniyokokid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RAZ_2147894967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RAZ!MTB"
        threat_id = "2147894967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 8b cf c1 e1 04 03 4c 24 2c 8b c7 c1 e8 05 03 44 24 38 8d 14 3b 33 ca 89 44 24 1c 89 4c 24 14 89 35 ?? ?? ?? ?? 8b 44 24 1c 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 30 89 74 24 1c 8b 44 24 30 01 44 24 1c 8b 44 24 14 33 44 24 1c 89 44 24 1c 8b 4c 24 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f5 33 c6 2b f8 81 c3 47 86 c8 61 ff 4c 24 24 89 44 24 14 0f 85 fd fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GNT_2147895320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GNT!MTB"
        threat_id = "2147895320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 1f 01 f1 81 c7 04 00 00 00 29 d6 21 f1 39 c7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GNW_2147895500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GNW!MTB"
        threat_id = "2147895500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 08 81 c6 ?? ?? ?? ?? 81 c0 04 00 00 00 89 da 01 d6 39 f8 ?? ?? 29 f6 c3 31 30 b9 ?? ?? ?? ?? 81 c0 04 00 00 00 39 d8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RAP_2147895646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RAP!MTB"
        threat_id = "2147895646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 d5 8b c8 c1 e1 04 89 54 24 20 03 cb 8d 14 06 33 ca 89 4c 24 10 89 3d ?? ?? ?? ?? 8b 44 24 20 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 38 89 7c 24 20}  //weight: 1, accuracy: Low
        $x_1_2 = {31 7c 24 10 8b 44 24 20 31 44 24 10 8b 44 24 10 29 44 24 1c c7 44 24 18 ?? ?? ?? ?? 8b 44 24 34 01 44 24 18 2b 74 24 18 ff 4c 24 2c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_SPDR_2147895652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.SPDR!MTB"
        threat_id = "2147895652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba d8 85 40 00 41 89 c8 e8 ?? ?? ?? ?? 31 13 09 c1 81 c3 ?? ?? ?? ?? 21 c0 29 c1 39 f3 75 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_SPDL_2147895845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.SPDL!MTB"
        threat_id = "2147895845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 31 09 d3 81 c1 04 00 00 00 01 d3 39 c1 75 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MBEU_2147896158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MBEU!MTB"
        threat_id = "2147896158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kerurofatevotocuyofosaw" ascii //weight: 1
        $x_1_2 = "wimifemudaleputox" ascii //weight: 1
        $x_1_3 = "dalinuzowufuwiwa" ascii //weight: 1
        $x_1_4 = "cukaneledo huvalifupives fatawodinomokun" ascii //weight: 1
        $x_1_5 = "gegetehijayevufoduyumasiyanujut natenayuyizuponefanunofalaxacu laruwuwubutumivoxoxid vazoguyujabozufoc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GNF_2147896320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GNF!MTB"
        threat_id = "2147896320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 3b 81 e8 ?? ?? ?? ?? 01 c8 81 c3 04 00 00 00 29 c9 39 f3 ?? ?? 29 c2 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_YAH_2147897791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.YAH!MTB"
        threat_id = "2147897791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 13 d3 ea 89 45 dc c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 e0 8b 45 dc 31 45 fc 33 55 fc 89 55 dc 8b 45 dc 83 45 f8 64 29 45 f8 83 6d f8 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AMBG_2147897795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AMBG!MTB"
        threat_id = "2147897795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8d 3c 13 81 c3 ?? ?? ?? ?? 03 45 dc 33 c7 31 45 fc 8b 45 fc 29 45 f0 ff 4d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GAA_2147898249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GAA!MTB"
        threat_id = "2147898249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 11 81 c1 ?? ?? ?? ?? 29 c7 81 c6 ?? ?? ?? ?? 39 d9 ?? ?? c3 01 fe 29 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MZZ_2147898277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MZZ!MTB"
        threat_id = "2147898277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 d8 8b 45 f0 31 45 fc 33 55 fc 89 55 f0 8b 45 f0 83 45 f4 64 29 45 f4 83 6d f4 64 83 3d ?? ?? ?? ?? 0c 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 d3 e8 8b 4d fc 8d 34 13 81 c3 ?? ?? ?? ?? 03 45 e0 33 c6 33 c8 2b f9 83 6d ?? 01 89 4d fc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MYL_2147898415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MYL!MTB"
        threat_id = "2147898415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 89 74 24 18 89 3d ?? ?? ?? ?? 8b 44 24 18 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 28 89 7c 24 18 8b 44 24 28 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 4c 24 18}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c6 89 44 24 10 8b 44 24 18 31 44 24 10 a1 ?? ?? ?? ?? 2b 5c 24 10 3d 93 00 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EAB_2147898671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EAB!MTB"
        threat_id = "2147898671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 e0 8b 45 f0 31 45 fc 33 55 fc 89 55 f0 8b 45 f0 83 45 f4 64 29 45 f4 83 6d f4 64 8b 45 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c6 2b f8 81 c3 47 86 c8 61 83 6d ec ?? 89 45 fc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GMZ_2147900604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GMZ!MTB"
        threat_id = "2147900604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 06 89 d2 81 c6 01 00 00 00 39 de 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GMZ_2147900604_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GMZ!MTB"
        threat_id = "2147900604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 07 51 5b 81 c7 04 00 00 00 39 f7 ?? ?? 21 da c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GMZ_2147900604_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GMZ!MTB"
        threat_id = "2147900604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 ca 31 3e 29 c2 40 f7 d2 46 21 c9 29 c8 48 43 21 d0 48 81 fe}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GMX_2147901511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GMX!MTB"
        threat_id = "2147901511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 1f 81 c6 ?? ?? ?? ?? 81 c7 04 00 00 00 39 d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GLA_2147901594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GLA!MTB"
        threat_id = "2147901594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d0 89 45 fc 89 55 f0 8b 45 f0 83 45 f8 ?? 29 45 f8 83 6d f8}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 03 45 dc 8b c8 8b 45 f0 31 45 fc 31 4d fc 2b 7d fc 81 c6 ?? ?? ?? ?? ff 4d e4 89 7d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_LAD_2147901643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.LAD!MTB"
        threat_id = "2147901643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 45 ?? 8b c8 8b 45 ?? 31 45 fc 31 ?? fc 2b 5d fc 81 c6 ?? ?? ?? ?? ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_SHG_2147902215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.SHG!MTB"
        threat_id = "2147902215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c2 2b f0 8b c6 c1 e0 ?? 89 75 f0 89 45 fc 8b 45 d4 01 45 fc 8b 4d f8 03 fe d3 ee 89 7d ?? 03 75 d8 8b 45 e4 31 45 fc 81 3d 74 d6 81 00 03 0b 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {31 75 fc 8b 45 fc 29 45 ec 81 45 f4 ?? ?? ?? ?? ff 4d e0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GZF_2147902806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GZF!MTB"
        threat_id = "2147902806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 de 81 ee ?? ?? ?? ?? 31 01 41 01 f6 81 c3 ?? ?? ?? ?? 39 d1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GXZ_2147903380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GXZ!MTB"
        threat_id = "2147903380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 c0 31 1a 40 42 39 fa 75 ?? 48 81 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AMMA_2147903608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AMMA!MTB"
        threat_id = "2147903608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 ec 08 08 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 04 08 00 00 a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 81 3d ?? ?? ?? ?? 9e 13 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GNS_2147904359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GNS!MTB"
        threat_id = "2147904359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 c2 21 d0 31 37 81 c7 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 39 df}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ICAA_2147905414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ICAA!MTB"
        threat_id = "2147905414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 08 30 04 0e 83 ff 0f 75 24 6a 00 6a 00 6a 00 ff d3 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_SPD_2147905626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.SPD!MTB"
        threat_id = "2147905626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 45 ec 33 45 e4 31 45 fc 8b 45 fc 29 45 f4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_Z_2147905720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.Z!MTB"
        threat_id = "2147905720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 54 24 14 8b 4c 24 ?? 30 04 0a 83 bc}  //weight: 2, accuracy: Low
        $x_2_2 = {41 89 4c 24 ?? 3b 8c}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 14 31 a1 ?? ?? ?? ?? 88 14 30}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_CCHZ_2147905793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.CCHZ!MTB"
        threat_id = "2147905793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d0 8b 45 ?? 33 c2 8b 55 ?? 2b f8 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ASI_2147905979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASI!MTB"
        threat_id = "2147905979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {81 fe c3 e6 12 00 75 05 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? dc 03 00 00 c7 05 ?? ?? ?? ?? f0 a6 46 8e 75 13 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? ff d7 46 81 fe a5 19 15 00 7c}  //weight: 4, accuracy: Low
        $x_1_2 = "rolawijejojomomadiyoc linomizocohu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GZZ_2147906106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GZZ!MTB"
        threat_id = "2147906106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d9 09 c9 e8 ?? ?? ?? ?? 31 3a 53 5b 42 81 eb ?? ?? ?? ?? 29 cb 39 c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GZZ_2147906106_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GZZ!MTB"
        threat_id = "2147906106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 0f 81 c7 04 00 00 00 39 f7 ?? ?? 81 c0 ?? ?? ?? ?? 81 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {31 17 81 c7 04 00 00 00 09 d9 39 c7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_GZY_2147906968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GZY!MTB"
        threat_id = "2147906968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 44 c2 03 cf a3 ?? ?? ?? ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 55 ?? 8b 45 ?? 33 d1 03 45 ?? 33 c2 c7 05 ?? ?? ?? ?? ee 3d ea f4 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ?? 89 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AMMF_2147907125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AMMF!MTB"
        threat_id = "2147907125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 03 c2 89 4d ?? 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AMMH_2147907716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AMMH!MTB"
        threat_id = "2147907716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 14 33 83 ff 0f 75 ?? 33 c9 8d 54 24 08 52 51 33 c0 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ASJ_2147907844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASJ!MTB"
        threat_id = "2147907844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 0c 30 83 bc 24 ?? ?? 00 00 0f 75 51 6a 00 6a 00 6a 00 ff d7}  //weight: 2, accuracy: Low
        $x_2_2 = {ff d7 81 fe 1e a0 01 00 7e 08 81 fb d7 be f5 00 75 09 46 81 fe 52 7a ce 1e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_YAK_2147908354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.YAK!MTB"
        threat_id = "2147908354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f4 33 db 8b 45 f8 33 d1 03 45 e4 8b 0d ?? ?? ?? ?? 33 c2 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 55 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_SPHT_2147908498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.SPHT!MTB"
        threat_id = "2147908498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 1e 83 ff 0f 75 1b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ASK_2147909316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASK!MTB"
        threat_id = "2147909316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 14 30 83 ff 0f 75}  //weight: 2, accuracy: High
        $x_2_2 = {3d cb d9 0b 00 75 06 81 c1 00 00 00 00 40 3d 3d a6 15 00 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_SPGD_2147909705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.SPGD!MTB"
        threat_id = "2147909705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 45 f8 8b 45 dc 01 45 f8 8b 45 f8 33 45 f4 31 45 fc 8b 45 fc 29 45 e8 8b 4d d4 81 c3 ?? ?? ?? ?? 89 5d f0 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_ASL_2147909854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.ASL!MTB"
        threat_id = "2147909854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 0c 30 83 bc 24 ?? ?? 00 00 0f 75}  //weight: 2, accuracy: Low
        $x_2_2 = {51 53 ff 15 ?? ?? 40 00 53 53 e8 ?? ?? ff ff 53 53 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_MLAA_2147909974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.MLAA!MTB"
        threat_id = "2147909974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c0 64 89 44 24 10 83 6c 24 10 64 8a 4c 24 10 8b 44 24 ?? 30 0c 30 83 bc 24 ?? ?? ?? ?? 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_AAX_2147910743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.AAX!MTB"
        threat_id = "2147910743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 f8 8b 4d fc 8b 45 f8 33 4d f0 03 45 d8 33 c1 c7 05 ?? ?? ?? ?? ee 3d ea f4 81 3d ?? ?? ?? ?? 13 02 00 00 89 4d fc 89 45 f8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_RZE_2147911244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.RZE!MTB"
        threat_id = "2147911244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 45 f8 33 45 e4 31 45 fc 8b 45 fc 29 45 ec 8b 4d d0 81 c7 ?? ?? ?? ?? 89 7d f0 4e 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EEE_2147921039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EEE!MTB"
        threat_id = "2147921039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d0 03 f8 d3 e0 c1 ea 05 03 55 dc 57 03 45 d8 89 55 f8 e8 ?? ?? ?? ?? 33 c2 89 45 e8 89 35 d8 ?? 7e 00 8b 45 e8 29 45 f4 81 3d f4 38 f3 00 d5 01 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EATY_2147929308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EATY!MTB"
        threat_id = "2147929308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 18 8b 0d ?? ?? ?? ?? 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 8b 4c 24 14 30 14 0e 83 f8 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EAD_2147929664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EAD!MTB"
        threat_id = "2147929664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 e0 8b 45 fc 8b f3 c1 ee 05 03 75 e8 03 fa 03 c3 33 f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EAH_2147930128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EAH!MTB"
        threat_id = "2147930128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 f3 33 f7 29 75 f8 8b 45 dc 29 45 fc 83 6d f0 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EACY_2147932048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EACY!MTB"
        threat_id = "2147932048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 d0 d3 e0 c1 ee 05 03 b4 24 e0 02 00 00 03 84 24 d0 02 00 00 89 74 24 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EAHH_2147932049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EAHH!MTB"
        threat_id = "2147932049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c1 e8 05 03 f2 89 45 fc 8b 45 f4 01 45 fc 8b 5d f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EAHC_2147932050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EAHC!MTB"
        threat_id = "2147932050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d a4 24 00 00 00 00 8d 49 00 8b 15 ?? ?? ?? ?? 8a 8c 02 3b 2d 0b 00 8b 15 ?? ?? ?? ?? 88 0c 02 8b 15 ?? ?? ?? ?? 40 3b c2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EAVF_2147935746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EAVF!MTB"
        threat_id = "2147935746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 8a 8c 30 01 24 0a 00 88 0c 32 8b e5 5d c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_EAUP_2147939218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EAUP!MTB"
        threat_id = "2147939218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b ec 56 8b 31 8b 4d 08 8a 04 0a 88 04 31 5e 5d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Glupteba_GYZ_2147940201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.GYZ!MTB"
        threat_id = "2147940201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 f0 29 c0 31 13 89 c8 81 c3 ?? ?? ?? ?? 21 c9 81 e8 ?? ?? ?? ?? 39 f3}  //weight: 10, accuracy: Low
        $x_10_2 = {31 38 81 c0 ?? ?? ?? ?? 39 f0 ?? ?? ba ?? ?? ?? ?? c3 bb ?? ?? ?? ?? 00 21 c0 68 ?? ?? 40 00 c3 89 db}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Glupteba_EAS_2147941310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glupteba.EAS!MTB"
        threat_id = "2147941310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glupteba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b f3 d3 ee 03 c3 89 45 e4 03 75 dc 8b 45 e4 31 45 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

