rule Ransom_Win32_Gandcrab_C_2147726187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.C!bit"
        threat_id = "2147726187"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CRAB-DECRYPT.txt" wide //weight: 1
        $x_1_2 = "ransom_id=" wide //weight: 1
        $x_1_3 = {65 6e 63 72 79 70 74 69 6f 6e 2e 64 6c 6c 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_AW_2147728836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.AW!bit"
        threat_id = "2147728836"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec e8 00 00 00 00 3e 83 04 24 11 75 05 74 03 e9 28 14 58 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = "%s.KRAB" wide //weight: 1
        $x_1_3 = "KRAB-DECRYPT.txt" wide //weight: 1
        $x_1_4 = "%s%x%x%x%x.lock" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_2147729003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab!MTB"
        threat_id = "2147729003"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 30 80 f3 ?? f6 d3 80 f3 ?? 88 1c 30 90 90 50 58 90 84 c0 46 84 c0 90 81 fe ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 75 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_G_2147729696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.G!MTB"
        threat_id = "2147729696"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 8b 38 8a 44 0f 03 8a d8 80 e3 ?? c0 e3 04 0a 5c 0f 01 88 5d ff 8a d8 24 ?? c0 e0 02 0a 04 0f c0 e3 06 0a 5c 0f 02 88 04 16 8a 45 ff 46 88 04 16 8b 45 0c 46 88 1c 16 83 c1 04 46 3b 08 72 c3 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 14 8d ?? ?? e8 ?? ?? ff ff 30 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_G_2147729696_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.G!MTB"
        threat_id = "2147729696"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 4c cd 21 54 68 69 73 20 01 01 70 01 01 72 01 01 6f 01 01 67 01 01 72 01 01 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f9 85 db 7e 37 8d 49 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 84 37 00 fe ff ff 6a 00 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 6a 00 ff 15 ?? ?? ?? ?? 46 3b f3 7c cc}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 0c 50 6a 00 ff d7 8b 4d 08 a0 3e f4 b7 03 30 04 0e 46 3b f3 7c 92 5f 5e 5b 8b e5 5d c2 08 00}  //weight: 1, accuracy: High
        $x_1_4 = {cc 6a 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 6a 00 ff d7 69 05 3c f4 b7 03 fd 43 03 00 6a 00 6a 00 05 c3 9e 26 00 a3 3c f4 b7 03 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Gandcrab_PA_2147733943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.PA!MTB"
        threat_id = "2147733943"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 68 04 01 00 00 bf ?? ?? ?? 00 33 db 57 53 88 1d ?? ?? ?? 00 ff 15 ?? ?? ?? 00 8b 35 ?? ?? ?? 00 89 3d ?? ?? ?? 00 85 f6 74 04 38 1e 75 02 8b f7 8d 45 ?? 50 8d 45 ?? 50 53 53 56 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 40 68 00 30 01 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 85 c0 74 30 ff d7 85 c0 74 13 8d 4d ?? 51 6a 06 53 ff d0 f7 d8 1b c0 23 45 ?? 89 45 ?? 8d 45 ?? 50 ff 75 ?? 68 00 30 01 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 c7 45 ?? fe ff ff ff 8b 45 ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = "ReflectiveLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_A_2147734604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.A!MTB"
        threat_id = "2147734604"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CAFITEHUVU" wide //weight: 1
        $x_1_2 = "KIRIVAWOWOYITAMAPOHA" wide //weight: 1
        $x_1_3 = "MPPXL" wide //weight: 1
        $x_1_4 = "MUWELEZORO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_B_2147734763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.B!MTB"
        threat_id = "2147734763"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 ff 50 6a 00 ff d3 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ff ff 30 04 37 83 ee 01 79 db}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 f0 50 56 56 56 56 56 56 ff 15 ?? ?? ?? ?? e8 ?? ?? ff ff 30 04 3b 4f 79 dd}  //weight: 1, accuracy: Low
        $x_1_3 = {00 40 3d 00 01 00 00 75 f2}  //weight: 1, accuracy: High
        $x_1_4 = {8d 45 f8 50 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 41 88 9a ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 81 f9 00 01 00 00 0f 85 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 45 f4 50 56 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 41 88 98 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 81 f9 00 01 00 00 0f 85 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Gandcrab_D_2147734927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.D!MTB"
        threat_id = "2147734927"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 4c cd 21 54 68 69 73 20 01 01 70 01 01 72 01 01 6f 01 01 67 01 01 72 01 01 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_2 = {7d 08 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 37 83 ee 01 79 ?? 5f 5e c2 04 00}  //weight: 1, accuracy: Low
        $x_1_3 = {0e 6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 37 83 ee 01 79 ?? 5f 5e c2 04 00}  //weight: 1, accuracy: Low
        $x_1_4 = {00 40 3d 00 01 00 00 75 f2 33 ff 33 f6 89 3d}  //weight: 1, accuracy: High
        $x_1_5 = {01 40 3d 00 01 00 00 75 f2 33 ff 33 f6 89 3d}  //weight: 1, accuracy: High
        $x_1_6 = {8b 4c 24 10 89 3d ?? ?? ?? ?? 8a 87 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 46 88 9f ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 81 fe 00 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Gandcrab_E_2147734962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.E!MTB"
        threat_id = "2147734962"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 4c cd 21 54 68 69 73 20 01 01 70 01 01 72 01 01 6f 01 01 67 01 01 72 01 01 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 c0 8b 4d f8 03 4d fc 0f be 09 33 c8 8b 45 f8 03 45 fc 88 08 8b 45 fc 48 89 45 fc eb}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 c0 8b 4d 08 03 4d 0c 0f be 09 33 c8 8b 45 08 03 45 0c 88 08 8b 45 0c 48 89 45 0c eb}  //weight: 1, accuracy: High
        $x_1_4 = {33 d2 b9 00 01 00 00 f7 f1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 88 45 ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 89 ?? ?? ?? ?? 88 88 [0-48] a1 ?? ?? ?? ?? 8a 4d ff 88 88 ?? ?? ?? ?? e9 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {00 01 00 00 74 13 a1 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 88 88 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Gandcrab_F_2147735000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.F!MTB"
        threat_id = "2147735000"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 06 8d 9b 00 00 00 00 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 8b d1 c1 ea 10 30 14 30 40 3b c7 7c e7 89 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 2c 00 00 00 8b 08 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 c7 41 04 01 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 94 0e ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 14 06 8b 0d ?? ?? ?? ?? 46 3b f1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_C_2147735021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.C!MTB"
        threat_id = "2147735021"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff ff eb 08 e8 ?? ?? ?? ?? 30 04 37 83 ee 01 79 f3 5f 5e c2 04 00}  //weight: 2, accuracy: Low
        $x_2_2 = {00 40 3d 00 01 00 00 75 f2 33 ff 33 f6 89 3d}  //weight: 2, accuracy: High
        $x_1_3 = "cannot be run in DOS mode." ascii //weight: 1
        $n_1_4 = "!This program" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Gandcrab_BH_2147735533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.BH!bit"
        threat_id = "2147735533"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 85 c5 0a 00 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 51 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {73 54 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {88 08 8b 55 ?? 83 c2 01 89 55 09 00 8b 45 ?? 03 45 ?? 8a 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_BL_2147735575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.BL!bit"
        threat_id = "2147735575"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 b2 6c 56 33 c9 57 88 15 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6b 88 15 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 6f b2 6c 88 1d ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 54 c6 05 ?? ?? ?? ?? 53 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 73 88 1d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 33 88 15}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33}  //weight: 1, accuracy: Low
        $x_1_4 = {51 52 50 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_H_2147735685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.H!MTB"
        threat_id = "2147735685"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 4c cd 21 54 68 69 73 20 01 01 70 01 01 72 01 01 6f 01 01 67 01 01 72 01 01 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8d 34 07 e8 75 ff ff ff 30 06 47 3b 7d 0c 7c ed}  //weight: 1, accuracy: High
        $x_1_3 = {00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 4d 08 a0 ?? ?? ?? ?? 30 04 0e 46 3b f7 7c ?? 5b 5f 5e 5d c2 08 00}  //weight: 1, accuracy: Low
        $x_1_4 = {00 6a 00 81 c1 ?? ?? ?? ?? 6a 00 89 0d ?? ?? ?? ?? ff d3 8a 15 ?? ?? ?? ?? 30 14 3e 46 3b 75 0c 7c ?? 5f 5b 5e 8b e5 5d c2 08 00}  //weight: 1, accuracy: Low
        $x_1_5 = {33 c5 89 45 fc a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 3d fe 44 05 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 8d 85}  //weight: 1, accuracy: Low
        $x_1_6 = {42 00 33 d2 a3 ?? ?? ?? ?? 39 15 ?? ?? ?? ?? 76 ?? a1 ?? ?? ?? ?? 8a 8c 10 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 0c 10 42 3b 15 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_7 = {85 c0 74 32 8b 3d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 94 31 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 14 30 81 fe ?? ?? ?? ?? 7d 04 6a 00 ff d7 8b 0d ?? ?? ?? ?? 46 3b f1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Gandcrab_I_2147741059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.I!MTB"
        threat_id = "2147741059"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CRAB-DECRYPT.txt" wide //weight: 1
        $x_1_2 = "Keyboard Layout\\Preload" wide //weight: 1
        $x_1_3 = "Control Panel\\International" wide //weight: 1
        $x_1_4 = "msmpeng.exe" wide //weight: 1
        $x_1_5 = "GandCrabGandCrab encrypted" ascii //weight: 1
        $x_1_6 = {65 6e 63 72 79 70 74 69 6f 6e 2e 64 6c 6c 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_J_2147742545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.J!MTB"
        threat_id = "2147742545"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 4c cd 21 54 68 69 73 20 01 01 70 01 01 72 01 01 6f 01 01 67 01 01 72 01 01 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff 30 04 37 6a 00 ff 15 ?? ?? ?? 00 8d 85 ?? ?? ?? ?? 50 6a 00 ff 15 ?? ?? ?? 00 46 3b 75 08 7c db}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e8 10 25 ff 7f 00 00 c3 3f 00 a1 ?? ?? ?? 00 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? 00 c1 e8 10 25 ff 7f 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_K_2147742627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.K!MTB"
        threat_id = "2147742627"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $n_1_1 = "!This program" ascii //weight: -1
        $x_1_2 = "cannot be run in DOS mode." ascii //weight: 1
        $x_1_3 = {33 c8 8d 04 2f 33 c8 2b d9 8b cb 8b c3 c1 e9 05 03 4c 24 18 c1 e0 04 03 44 24 1c 33 c8 8d 04 2b 2b 6c 24 20 33 c8 2b f9 83 ee 01 75 b3 8b 74 24 24 89 3e 5f 89 5e 04 5e 5d 5b 83 c4 18 c3}  //weight: 1, accuracy: High
        $x_1_4 = {ff 74 24 0c 53 53 53 53 53 53 53 53 53 53 ff 15 ?? ?? ?? 00 8b cf e8 ?? ff ff ff 83 c7 08 83 ee 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_M_2147743075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.M!MTB"
        threat_id = "2147743075"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 4c cd 21 54 68 69 73 20 01 01 70 01 01 72 01 01 6f 01 01 67 01 01 72 01 01 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d c4 03 4d fc 0f be 19 e8 ?? ?? ff ff 33 d8 8b 55 c4 03 55 fc 88 1a eb ?? 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 81 ec 00 08 00 00 a1 ?? ?? ?? 00 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? 00 [0-80] a1 ?? ?? ?? 00 c1 e8 10 25 ff 7f 00 00 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_L_2147743279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.L!MTB"
        threat_id = "2147743279"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $n_1_1 = "!This program" ascii //weight: -1
        $x_1_2 = "cannot be run in DOS mode." ascii //weight: 1
        $x_1_3 = {6a 00 ff d6 e8 ?? ?? ff ff 8b 4c 24 0c 30 04 39 83 ef 01 79 e3 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {00 40 3d 00 01 00 00 75 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_N_2147745599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.N!MTB"
        threat_id = "2147745599"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 e8 ?? ?? ff ff 30 04 37 8d 85 ?? ?? ff ff 50 6a 00 ff 15 ?? ?? ?? 00 46 3b 75 08 7c d5 8b 4d fc 5f 33 cd 5e e8 ?? ?? ff ff c9 c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 10 25 ff 7f 00 00 c3 1f 00 a1 ?? ?? ?? 00 69 c0 ?? ?? ?? 00 05 ?? ?? ?? 00 a3 ?? ?? ?? 00 c1 e8 10 25 ff 7f 00 00 c3}  //weight: 1, accuracy: Low
        $n_1_3 = "!This program" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_SE_2147754159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.SE!MTB"
        threat_id = "2147754159"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 56 33 f6 57 8b f8 39 75 08 7e 20 6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 84 3e 00 fe ff ff 46 3b 75 08 7c e0 5f 5e 5d c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 8c 37 32 09 00 00 a1 ?? ?? ?? ?? 88 0c 30 83 fe ?? 75 28 68 ?? ?? ?? ?? 6a 40 ff 74 24 14 50 ff 15 ?? ?? ?? ?? 89 5c 24 18 c7 44 24 18 20 00 00 00 8b 44 24 18 03 c0 89 44 24 18 46 3b 74 24 0c 72 97}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_SF_2147754256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.SF!MTB"
        threat_id = "2147754256"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 c8 c7 85 78 ff ff ff 56 69 72 74 c7 85 7c ff ff ff 75 61 6c 41 c7 45 80 6c 6c 6f 63 83 65 84 00 8d 85 78 ff ff ff 50 ff 75 c8 ff 55 a0 89 45 b8 c7 85 78 ff ff ff 56 69 72 74 c7 85 7c ff ff ff 75 61 6c 50 c7 45 80 72 6f 74 65 c7 45 84 63 74 00 00 8d 85 78 ff ff ff 50 ff 75 c8 ff 55 a0 89 45 dc c7 85 78 ff ff ff 56 69 72 74 c7 85 7c ff ff ff 75 61 6c 46 c7 45 80 72 65 65 00 8d 85 78 ff ff ff 50 ff 75 c8 ff 55 a0}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 d8 47 65 74 50 c7 45 dc 72 6f 63 41 c7 45 e0 64 64 72 65 c7 45 e4 73 73 00 00 eb 07}  //weight: 1, accuracy: High
        $x_1_3 = {8b 95 1c ff ff ff 8b 32 2b f0 8b 42 04 1b c1 8b 8d 70 ff ff ff 33 d2 03 f1 13 c2 8b 8d 1c ff ff ff 89 31 89 41 04 e9 1c ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_AHB_2147754839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.AHB!MTB"
        threat_id = "2147754839"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 84 0e 32 09 00 00 [0-10] 88 04 39}  //weight: 2, accuracy: Low
        $x_1_2 = {30 06 c3 55 0c 00 90 90 90 90 90}  //weight: 1, accuracy: Low
        $x_1_3 = {30 04 1f 56 ff [0-5] 56 ff [0-5] 33 c0 [0-15] ab}  //weight: 1, accuracy: Low
        $x_2_4 = {8a 84 32 e1 bf 01 00 8b 0d ?? ?? ?? ?? 88 04 31 a1 ?? ?? ?? ?? 46 3b f0 72}  //weight: 2, accuracy: Low
        $x_1_5 = {30 0c 37 83 ee 01 0f 89 2f 00 81 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 81 6c 24 [0-8] 81 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Gandcrab_AR_2147755527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.AR!MTB"
        threat_id = "2147755527"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 6b 00 00 00 [0-2] 89 ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? bb 72 00 00 00 b8 65 00 00 00 8b cb [0-2] 89 ?? ?? ?? ?? ?? ba 6e 00 00 00 [0-2] 89 [0-31] b9 6c 00 00 00 ba 33 00 00 00 [0-2] 89 [0-7] 89 [0-5] b8 32 00 00 00 [0-7] b9 2e 00 00 00 ba 64 00 00 00 b8 6c 00 00 00 66 89 0d ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? 8b c8 33 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_KS_2147781755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.KS!MTB"
        threat_id = "2147781755"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 84 1e 00 fe ff ff 57 57 57 57 ff 15 ?? ?? ?? ?? 46 3b 75 08 7c d7}  //weight: 10, accuracy: Low
        $x_10_2 = {89 45 fc 0f be 00 3d b3 01 00 00 74 07 ff 55 fc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_RPS_2147819638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.RPS!MTB"
        threat_id = "2147819638"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 33 c7 45 d4 ?? ?? ?? ?? 81 45 d4 ?? ?? ?? ?? 81 6d d4 ?? ?? ?? ?? 81 6d d4 ?? ?? ?? ?? 81 45 d4 ?? ?? ?? ?? 81 6d d4 ?? ?? ?? ?? 81 6d d4 ?? ?? ?? ?? 81 45 d4 ?? ?? ?? ?? 81 6d d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_RPA_2147830083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.RPA!MTB"
        threat_id = "2147830083"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cf 8b c7 c1 e9 05 03 4b 0c c1 e0 04 03 43 08 33 c8 8d 04 3a 33 c8 2b f1 8b ce 8b c6 c1 e9 05 03 4b 04 c1 e0 04 03 03 33 c8 8d 04 32 33 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_RPF_2147834602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.RPF!MTB"
        threat_id = "2147834602"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 84 40 30 8a ?? ?? ?? ?? 33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 84 40 30 8a ?? ?? ?? ?? 33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 84 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gandcrab_EN_2147941303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gandcrab.EN!MTB"
        threat_id = "2147941303"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d a4 24 00 00 00 00 90 0f b6 4c 85 d4 40 30 8a ?? ?? ?? ?? 33 c9 83 f8 0b 0f 44 c1}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

