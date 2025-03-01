rule Ransom_Win32_Phobos_A_2147741436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.A"
        threat_id = "2147741436"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 33 c0 89 5d d4 8d 7d d8 ab ab 33 c0 89 5d c4 8d 7d c8 ab ab 33 c0 89 5d b8 8d 7d bc ab 8d b6 ?? ?? ?? ?? 89 5d f0 89 5d f4 89 5d e0 ab}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Phobos_A_2147741436_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.A"
        threat_id = "2147741436"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 96 3b 24 ee e6 1f 4c 43 6e 30 d5 5b 69 2b 9c f6 de 4a}  //weight: 1, accuracy: High
        $x_1_2 = {40 b5 d3 93 0e 11 c2 17 ab d7 29 37 40 e4 97 8f b0 7a 02}  //weight: 1, accuracy: High
        $x_2_3 = {8d 7d e0 ab ab ab ab 8d ?? ?? 8d ?? ?? 50 8d ?? ?? e8 ?? ?? ?? ?? ff ?? ?? 8b ?? ff ?? ?? 50 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Phobos_V_2147749980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.V!MTB"
        threat_id = "2147749980"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_3 = "netsh advfirewall set currentprofile state off" ascii //weight: 1
        $x_1_4 = "netsh firewall set opmode mode=disable" ascii //weight: 1
        $x_1_5 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_6 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Phobos_PA_2147750813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.PA!MTB"
        threat_id = "2147750813"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f b7 54 24 12 03 56 08 57 52 53 e8 ?? ?? ?? ff 83 c4 0c 8d 6e 0c 55 ff 15 ?? ?? ?? 00 e8 ?? ?? ?? ff 84 c0 74 ?? 8b 44 24 24 50 53 6a 00 6a 00 89 38 8b 46 04 6a 00 50 ff 15 ?? ?? ?? 00 85 c0 75}  //weight: 20, accuracy: Low
        $x_10_2 = {55 8b ec 51 8b 45 08 89 45 fc 8b 4d 10 8b 55 10 83 ea 01 89 55 10 85 c9 74 1e 8b 45 08 8b 4d 0c 8a 11 88 10 8b 45 08 83 c0 01 89 45 08 8b 4d 0c 83 c1 01 89 4d 0c eb d2 8b 45 fc 8b e5 5d c3}  //weight: 10, accuracy: High
        $x_7_3 = {b1 61 88 4c 24 07 88 4c 24 09 8d 4c 24 04 03 c6 51 c6 44 24 08 2e c6 44 24 09 6e c6 44 24 0a 64 c6 44 24 0c 74 c6 44 24 0e 00 e8}  //weight: 7, accuracy: High
        $x_5_4 = {0f b7 48 14 53 55 8b 6c 24 0c 56 0f b7 70 06 66 85 f6 57 8d 7c 01 18 74 29 8b 1d 5c 70 40 00 90 6a ff 55 6a ff 57 6a 01 68 00 08 00 00 81 c6 ff ff 00 00 ff d3 83 f8 02 74 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Phobos_PB_2147750888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.PB!MTB"
        threat_id = "2147750888"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "info.hta" wide //weight: 1
        $x_1_2 = ".id[ADE43D53-2301].[hanesworth.fabian@aol.com].banjo" wide //weight: 1
        $x_1_3 = "netsh firewall set opmode mode=disable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Phobos_PB_2147750888_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.PB!MTB"
        threat_id = "2147750888"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 2c 8d 44 24 24 6a 00 50 e8 ?? ?? ?? ff 6a 20 8d 4c 24 10 51 8d 54 24 40 52 66 c7 44 24 38 08 02 66 c7 44 24 3c 10 66 c6 44 24 40 20 e8 ?? ?? ?? ff 8b 16 83 c4 18 8d 46 04 50 6a 00 6a 00 6a 2c 8d 4c 24 30 51 52 ff 15 ?? ?? ?? 00 85 c0 75 15 ff 15 ?? ?? ?? 00 50 e8 ?? ?? ?? 00 83 c4 04 32 c0 83 c4 4c c3}  //weight: 10, accuracy: Low
        $x_5_2 = {0f b7 54 24 12 03 56 08 57 52 53 e8 ?? ?? ?? ff 83 c4 0c 8d 6e 0c 55 ff 15 ?? ?? ?? 00 e8 ?? ?? ?? ff 84 c0 74 ?? 8b 44 24 24 50 53 6a 00 6a 00 89 38 8b 46 04 6a 00 50 ff 15 ?? ?? ?? 00 85 c0 75}  //weight: 5, accuracy: Low
        $x_1_3 = {55 8b ec 51 8b 45 08 89 45 fc 8b 4d 10 8b 55 10 83 ea 01 89 55 10 85 c9 74 1e 8b 45 08 8b 4d 0c 8a 11 88 10 8b 45 08 83 c0 01 89 45 08 8b 4d 0c 83 c1 01 89 4d 0c eb d2 8b 45 fc 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Phobos_PC_2147753251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.PC!MTB"
        threat_id = "2147753251"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "phobos" wide //weight: 1
        $x_1_2 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_3 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Phobos_MK_2147756852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.MK!MSR"
        threat_id = "2147756852"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 88 28 92 41 00 66 89 88 ?? ?? ?? ?? 83 c0 02 66 3b ce 74 05 83 ea 01 75 e5}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 0e 33 c8 81 e1 ?? ?? ?? ?? c1 e8 08 33 44 8c 04 83 ea 01 83 c6 01 85 d2 75 e4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Phobos_PD_2147794868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.PD!MTB"
        threat_id = "2147794868"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OFLXLCLFLSMCVLRLX" ascii //weight: 1
        $x_4_2 = {c7 45 cc 00 00 00 00 81 7d cc [0-4] 0f 83 [0-4] 8b 45 ?? 8b 4d ?? 83 e1 ?? 0f be 04 08 8b 4d ?? 0f b6 14 0d [0-4] 31 c2 88 d3 88 1c 0d [0-4] 8b 45 ?? 83 c0 01 89 45 ?? e9}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Phobos_MAK_2147810333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.MAK!MTB"
        threat_id = "2147810333"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {0f b6 11 ff 4c 24 04 33 d0 81 e2 ff 00 00 00 c1 e8 08 33 04 95 00 b0 40 00 41 83 7c 24 04 00 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Phobos_PAG_2147850995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.PAG!MTB"
        threat_id = "2147850995"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 8d 4c 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 18 8b f2 d3 ee 8b 4c 24 10 03 cb 8d 04 17 33 c8 03 f5 81 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 14 37 d3 ee 8b 4c 24 ?? 8d 44 24 ?? 89 54 24 ?? 89 74 24 1c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 28 31 44 24 10 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Phobos_MKZ_2147934896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Phobos.MKZ!MTB"
        threat_id = "2147934896"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 7d 10 8d 58 ff c1 eb 04 43 8b 45 10 8b ce 2b c8 c7 45 ?? 10 00 00 00 8a 14 07 32 10 88 14 01 40 ff 4d fc 75 ?? 83 7d 0c 01 ff 75 08 8b c6 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

