rule Trojan_Win32_SystemBC_D_2147839759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.D!MTB"
        threat_id = "2147839759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 c0 19 73 1e 00 05 43 55 fb 3c c1 d8 10 03 c1 85 d2}  //weight: 1, accuracy: High
        $x_1_2 = "-WindowStyle Hidden -ep bypass -file" ascii //weight: 1
        $x_1_3 = "LdrLoadDll" ascii //weight: 1
        $x_1_4 = "unknowndll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_SA_2147839760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.SA"
        threat_id = "2147839760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 c0 19 73 1e 00 05 43 55 fb 3c c1 d8 10 03 c1 85 d2}  //weight: 10, accuracy: High
        $x_10_2 = {48 69 c0 19 73 1e 00 48 05 43 55 fb 3c 48 c1 d8 10 48 03 c1 48 85 d2}  //weight: 10, accuracy: High
        $x_1_3 = "BEGINDATA" ascii //weight: 1
        $x_1_4 = "HOST1:" ascii //weight: 1
        $x_1_5 = "PORT1:" ascii //weight: 1
        $x_1_6 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SystemBC_2147840833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyF!MTB"
        threat_id = "2147840833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyF: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {5e 89 f7 b9 00 ee 02 00 eb 32 8a 07 83 c7 01 3c 80 72 0a 3c 8f 77 06 80 7f fe 0f 74 06 2c e8 3c}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147840834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyG!MTB"
        threat_id = "2147840834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyG: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {0c 02 00 00 a1 24 7c 43 00 33 c4 89 84 24 08 56 33 c0 68 00 00 f0 58 06 50 8d 4c 24 0e 51 66 89 44 24 10 e8 8a 01 6c 4b 83 c4 0c c0 5c b8 16 68 04 01 8d 54 52 6a 00 40 77 98 05 ff 15 1c b2 42 04 6a 5c 50 e0 2e 20 b8 47 c3 8b f0 33 c9 0e 83 9e c5 a2 05 c6 02 6a 2e 56 33 d2 16 00 70 2f 10 10 8b d7 8b c6 2b d6 5e 8b ff 0f b7 08 04 00 79 89}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147840835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyH!MTB"
        threat_id = "2147840835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {0c 00 00 59 8b c7 5f 5e 5b 8b e5 5d c3 33 c0 50 50 50 50 50 e8 0a 17 00 00 cc 8b ff 55 8b ec 56}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147840836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyI!MTB"
        threat_id = "2147840836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyI: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {24 14 89 44 24 08 8b 44 24 08 85 c0 75 18 8d 4c 24 04 c7 84 24 3c 01 00 00 ff ff ff ff e8 54 1f}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147840837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyK!MTB"
        threat_id = "2147840837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyK: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {6a 01 ff 50 20 83 c6 04 3b 35 10 dd 46 00 72 ea ff 15 88 d1 45 00 6a 0c a3 28 e8 46 00 89 3d 2c}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147840839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyM!MTB"
        threat_id = "2147840839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyM: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {be 00 d0 40 00 8d be 00 40 ff ff 57 89 e5 8d 9c 24 80 c1 ff ff 31 c0 50 39 dc 75 fb 46 46 53 68 ba 86 02 00 57 83 c3 04 53 68 e6 df 01 00 56 83 c3 04 53 50 c7 03 03 00 02 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147841247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyD!MTB"
        threat_id = "2147841247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyD: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {45 ec 8b 45 e4 3b 45 f8 73 31 6a 00 8d 45 fc 50 ff 75 ec ff 75 f0 ff 75 e8 ff 15 00 c1 40 00 85 c0 75 04 eb 79 eb 77 8b 45 e4 03 45 fc 89 45 e4}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147841248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyJ!MTB"
        threat_id = "2147841248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyJ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8b 45 fc 8b 08 83 c1 01 8b 55 fc 89 0a 8b 45 fc 8b 88 8c 02 00 00 83 c1 01 8b 55 fc 89 8a 8c 02 00 00 8b 45 fc 83 38 04 73 5c 8b 45 fc 8b 4d fc 8b 90 8c 02 00 00 3b 51 08 73 4b 8b 45 fc 8b 88 90 02 00 00 8b 55 fc 8b 82 8c 02 00 00 0f b6 0c 01 8b 55 fc 8b 02 8b 55 fc 0f b6 44 02 4c 33 c8 8b 55 fc 8b 42 20 8b 55 fc 8b 92 8c 02 00 00 88 0c 10 8b 45 fc 83 b8 8c 02 00 00 02 75 03 ff 75 fc e9 7a ff ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147841249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyO!MTB"
        threat_id = "2147841249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyO: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {66 8b 08 83 c0 ?? 66 3b cf 75 f5 2b c2 57 d1 ?? 8d 44 00 02 50 53 56 ff 75 f8 ff 15 6c 20 42 00 85}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147841250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyP!MTB"
        threat_id = "2147841250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyP: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {57 ff 75 08 ff 75 fc 57 e8 61 78 ff ff 50 6a ?? ff 15 48 81 41 00 50 89 86 94}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147841251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyQ!MTB"
        threat_id = "2147841251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyQ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {04 1b 83 c0 03 24 fc e8 b4 d5 ff ff 89 65 e8 8b c4 89 45 dc 83 4d fc ff eb 13 6a 01 58 c3 8b 65 e8 33 ff 89 7d dc 83 ?? ?? ?? 8b 5d e4 39 7d dc 74 66 53 ff 75 dc ff 75 14 ff 75 10 6a 01 ff 75 20 ff 15 e8 81 41 00 85 c0 74 4d 57 57 53 ff 75}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147841252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyR!MTB"
        threat_id = "2147841252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyR: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {e2 89 85 30 fe ff ff 83 bd 30 fe ff ff ?? 7d 20 6a ?? 68 24 1b 40 00 ff b5 34 fe ff ff ff b5 30}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147841253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyT!MTB"
        threat_id = "2147841253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {b8 9c dd 53 00 50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 33 c0 89 08 50 45 43 6f 6d 70 61 63 74 32 00 13 5f ac 93 f6 da 0e 49 b8 ?? ?? ?? ?? 02 e4 d4 e7 a3 09 ec c0 98 a1 5c b1 a8 f6 e3 c3}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_2147841656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.psyW!MTB"
        threat_id = "2147841656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "psyW: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {83 c0 02 66 85 c9 75 ?? e8 95 ?? ?? ?? ?? c9 68 ?? ?? ?? 00 51 8d 54 24 ?? 52 66 89 4c 24 ?? e8 ?? ?? ?? 00 83 c4 ?? 8d 44 24}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_NV_2147845729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.NV!MTB"
        threat_id = "2147845729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 8a 3a f7 ff 8b 55 cc 03 55 ac 81 ea 67 2b 00 00 03 55 e8 2b d0 8b 45 d8 31 10 6a 00 e8 6d 3a f7 ff ba 04 00 00 00 2b d0 01 55 e8 6a 00 e8 5c 3a f7 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_MA_2147847986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.MA!MTB"
        threat_id = "2147847986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff cc 31 00 3f 08 f4 f5 14 50 05 81 42 b8 18 12 2e 35 ce 99 5a 0f f0 d8 68 ed 19 f7 42 a8 34 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_SPDT_2147896352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.SPDT!MTB"
        threat_id = "2147896352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ZYzlYH557y" ascii //weight: 2
        $x_2_2 = "HDXaC212" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_SB_2147897233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.SB"
        threat_id = "2147897233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 10 27 00 00 e8 ?? ?? ?? ?? 8d ?? 72 fe ff ff 50 68 02 02 00 00 e8 ?? ?? ?? ?? 85 c0 75 ?? c7 (80|2d|8f) ?? ?? ?? ?? ?? ?? ?? ?? 8d ?? 60 fe ff ff 50 6a ff 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d ?? 60 fe ff ff 50 e8 ?? ?? ?? ?? 89 (80|2d|8f) ?? ?? ?? ?? ff (b0|2d|bf) ?? ?? ?? ?? ff (b0|2d|bf) ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75 ?? 81 (b0|2d|bf) ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? c7 (80|2d|8f) ?? ?? ?? ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 81 c4 d0 fe ff ff 53 57 56 8d ?? f4 2b cc 51 8d ?? 10 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 04 14 24 34 44 54 64 74 84 94 a4 b4 c4 d4 e4 f4 10 50 e8 ?? ?? ?? ?? 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 (40|2d|4f) ?? 6a 04 ff (70|2d|7f) ?? 8d ?? fc 50 e8 ?? ?? ?? ?? c7 (80|2d|8f) ?? ?? ?? ?? 01 00 00 00 6a 04 8d ?? d4 fe ff ff 50 6a 01 6a 06 ff (70|2d|7f) ?? e8 ?? ?? ?? ?? 8d ?? d8 fe ff ff 50 6a ff ff (70|2d|7f) ?? e8 ?? ?? ?? ?? 6a 02 8d ?? d8 fe ff ff 50 e8 ?? ?? ?? ?? 89 (40|2d|4f) ?? 8b (40|2d|4f) ?? 3d 00 00 01 00 76 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SystemBC_KAA_2147912484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.KAA!MTB"
        threat_id = "2147912484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 8d 0c 2e f7 74 24 ?? 2b d3 8a 44 14 ?? 32 04 0f 46 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_CCJR_2147922655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.CCJR!MTB"
        threat_id = "2147922655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 1f 33 45 f0 89 04 1e e8 ?? ?? ?? ?? 3b 45 e0 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_CCIM_2147923822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.CCIM!MTB"
        threat_id = "2147923822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 32 69 f6 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 99 bf ?? ?? ?? ?? f7 ff 03 f0 03 ce 81 f1 ?? ?? ?? ?? 88 8d}  //weight: 2, accuracy: Low
        $x_1_2 = {33 d0 88 55 ?? 0f b6 45 ?? 6b c0 ?? 0f b6 4d ?? 0f b6 55 ?? 0b ca 33 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_AJS_2147924466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.AJS!MTB"
        threat_id = "2147924466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 7d e4 0f 8d 4d d0 8b c2 0f 47 4d d0 83 e0 0f 8a 80 b8 5a 68 00 32 04 11 88 04 3a 42 8b 4d e0 3b d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_YAH_2147926565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.YAH!MTB"
        threat_id = "2147926565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 40 e5 6d 00 89 44 24 ?? 8b ce e8 ?? ?? ?? ?? ba 40 84 75 03 89 44 24}  //weight: 1, accuracy: Low
        $x_10_2 = {8b 44 24 18 8a 4c 14 1c 32 8e ?? ?? ?? ?? 88 0c 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_ITR_2147934901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.ITR!MTB"
        threat_id = "2147934901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 32 1a 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemBC_BW_2147939904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBC.BW!MTB"
        threat_id = "2147939904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 4d f0 85 c9 0f 88 ?? ?? 00 00 39 c1 0f 86 ?? ?? 00 00 89 c1 83 e1 1f 0f b6 89 ?? ?? ?? ?? 8b 55 ec 30 0c 02 40 3d ?? ?? ?? ?? 72}  //weight: 4, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

