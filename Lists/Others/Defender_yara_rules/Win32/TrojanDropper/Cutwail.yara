rule TrojanDropper_Win32_Cutwail_B_2147596614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.B"
        threat_id = "2147596614"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 6a 35 8d ?? ?? fb ff ff ?? e8 ?? ?? 00 00 83 c4 08 68 28 30 40 00 68 3f 00 0f 00 6a 00 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_A_2147596631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.A"
        threat_id = "2147596631"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0f 80 f9 00 74 ?? 30 0b [0-4] 48 74 ?? 43 47 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 04 53 56 57 8b 4d 08 ?? ?? 49 49 0f b6 09 89 4d fc 8b 7d 0c 56 ff 15 ?? ?? ?? ?? ?? ?? 89 1f 83 c7 04 e8 ?? ?? ?? ?? 56 53 ff 15 ?? ?? ?? ?? 89 07 83 c7 04 e8 ?? ?? ?? ?? 3c 00 75 ea 46 ff 4d fc 83 7d fc 00 75 cd ?? ?? 5f 5e 5b c9 c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_C_2147596653_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.C"
        threat_id = "2147596653"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 3d 68 a0 12 00 01 50 e8 e7 fe ff ff 6a 01 8d 85 f4 fd ff ff 50 6a 65 53 e8 78 fd ff ff 56 8d 85 dc fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_D_2147596921_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.D"
        threat_id = "2147596921"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5f 57 b8 00 00 00 00 4f 8b 33 0f ce 8a ca d3 e6 c1 ee 1f 85 f6 74 06}  //weight: 2, accuracy: High
        $x_2_2 = {25 00 00 ff ff 2d 00 00 01 00 66 81 38 4d 5a 75 f4}  //weight: 2, accuracy: High
        $x_2_3 = {46 f3 a4 61 c9 c3 6a 00 6a 04 6a 00}  //weight: 2, accuracy: High
        $x_2_4 = {64 a1 00 00 00 00 8b 40 04 25 00 00 ff ff 2d 00 00 01 00 66 81 38 4d 5a 75 f4}  //weight: 2, accuracy: High
        $x_2_5 = {8b 75 08 8b c6 83 c0 3c 8b 00 03 c6 05 80 00 00 00 8b}  //weight: 2, accuracy: High
        $x_1_6 = "SetThreadContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Cutwail_A_2147596922_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.gen!A"
        threat_id = "2147596922"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 8b 33 0f ce 8a ca d3 e6 c1 ee 1f 85 f6 74 06 8b cf d3 e6 03 c6 42 83 fa 20 75 05 83 c3 04 33 d2 85 ff 75 db 59 01 0d}  //weight: 1, accuracy: High
        $x_1_2 = {8b 00 03 c6 05 80 00 00 00 8b 18 03 de 8b 43 0c 03 45 08 50 ff 15 [0-6] 89 45 fc 8b 33 03 75 08 8b 7b 10 03 7d 08 8b 0e 03 4d 08 41 41 51 ff 75 fc ff 15 ?? ?? ?? ?? 89 07 83 c6 04 83 c7 04 83 3e 00 75 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_F_2147597037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.F"
        threat_id = "2147597037"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 35 f8 23 40 00 ff 15 ?? ?? 40 00 c7 86 b0 00 00 00 (2a|3a) 10 40 00 56 ff 35 f8 23 40 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_G_2147597272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.G"
        threat_id = "2147597272"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 18 72 40 00 8d 4c 24 0c 51 8d 94 24 18 02 00 00 68 08 72 40 00 52 e8 7c 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 50 62 14 13 8d 4c 24 10 51 8d 94 24 18 01 00 00 68 40 62 14 13 52 e8 d5 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Cutwail_H_2147597828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.H"
        threat_id = "2147597828"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc ff 15 ?? ?? 40 00 8b 45 08 [0-3] (8d 8e b0 00 00 00|89 86 b0 00) 56}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc 8d 05 ?? ?? 40 00 50 6a 00 e8 ?? ?? ff ff ff 15 ?? ?? 40 00 8b 45 0c 8d 0e 81 c1 b0 00 00 00 89 01 56}  //weight: 1, accuracy: Low
        $x_1_3 = {c3 8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc ff 15 ?? ?? 40 00 8b 45 0c 8d 0e 81 c1 b0 00 00 00 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Cutwail_I_2147598113_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.I"
        threat_id = "2147598113"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 56 68 00 24 a4 9c 57 ff 15 ?? ?? 00 01 57 ff 15 ?? ?? 00 01 eb 28 68 ?? ?? 00 01 50 e8 ?? ?? ff ff 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_J_2147598114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.J"
        threat_id = "2147598114"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9c 71 9c 40 01 81 83 10 34 50 b0 81 3d 00 04 0c e5 50 c0 c1 04 12 28 58 c4 a1 40 01 06 10 28 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_O_2147598321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.O"
        threat_id = "2147598321"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 50 e8 dd fe ff ff 83 c4 08 68 c8 00 00 00 8d 8d 38 ff ff ff 51 68 ?? (20|21) 00 10 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {10 52 e8 ed fe ff ff 83 c4 08 68 c8 00 00 00 8b 45 fc 50 68 ?? 51 00 10 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Cutwail_R_2147598431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.R"
        threat_id = "2147598431"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {75 f9 83 05 ?? ?? ?? ?? 04 ff 15 ?? ?? 40 00 83 c4 1c ff 15 ?? ?? 40 00 83 f0 06 f7 d0 [0-2] 8d 75 f4}  //weight: 4, accuracy: Low
        $x_4_2 = {8b 4d 08 8b 55 0c 80 01 ?? 41 4a 75 f9 83 05 ?? ?? ?? ?? 04}  //weight: 4, accuracy: Low
        $x_3_3 = {8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc ff 15 ?? ?? 40 00 8b 45 0c 89 86 b0 00 00 00 56 ff 75 fc}  //weight: 3, accuracy: Low
        $x_3_4 = {b9 a0 00 00 00 8d 1d 64 20 40 00 03 d9}  //weight: 3, accuracy: High
        $x_3_5 = {80 f9 00 74 0e 8a 13 32 d1 88 16 48 74 0c 43 46 47 eb eb}  //weight: 3, accuracy: High
        $x_3_6 = {c7 44 24 fc 00 50 c3 00 02 00 ff}  //weight: 3, accuracy: Low
        $x_3_7 = {c7 44 24 fc 00 00 00 00 81 4c 24 fc 00 50 c3 00 02 00 ff}  //weight: 3, accuracy: Low
        $x_3_8 = {b8 04 50 c3 00 ba 04 00 00 00 02 00 ff}  //weight: 3, accuracy: Low
        $x_1_9 = {83 c0 02 ff d0 06 00 8d 05 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_10 = {83 e8 03 ff d0 06 00 8d 05 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_11 = {41 ff d1 c3 06 00 8d 0d ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_12 = {ff 04 24 59 e2 ff e1}  //weight: 1, accuracy: High
        $x_1_13 = {eb 03 e8 61 6c 8d 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Cutwail_V_2147599824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.V"
        threat_id = "2147599824"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 06 f7 d0 8d 75 f4 8b 3e 23 f8 89 3e 0f 00 ff 15 ?? ?? 40 00 83 c4 1c ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 8b 55 0c 80 01 ?? 41 4a 75 f9 83 05 ?? ?? ?? ?? ?? e8 ?? ?? 00 00 83 f0 06}  //weight: 1, accuracy: Low
        $x_1_3 = {56 53 8d 05 ?? ?? 40 00 25 00 00 ff ff 05 00 70 00 00 8d b0 88 00 00 00 8b 48 74 89 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 40 b9 0b 00 00 00 8b c1 05 00 30 00 00 50 29 0c 24 ff 73 50 50 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Cutwail_U_2147599876_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.U"
        threat_id = "2147599876"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 68 56 57 be ?? ?? ?? ?? 8d 7d dc a5 a5 a5 a5 6a 03 a4 5e e8 ?? ?? ?? ?? 33 d2 6a 19 59 f7 f1 80 c2 61 88 54 35 dc 46 83 fe 0c 72 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {75 0f 83 0d ?? ?? ?? ?? 01 ff 15 ?? ?? ?? ?? eb 05 a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? a3 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_W_2147599916_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.W"
        threat_id = "2147599916"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 50 8d 83 ?? ?? 00 00 8b 80 ?? ?? ff ff 89 04 24 ff 73 34 8d 05 ?? ?? ?? ?? ff 90 ?? ?? ?? ?? 96}  //weight: 1, accuracy: Low
        $x_1_2 = {05 00 30 00 00 50 29 0c 24 ff 73 50 50 8d 83 ?? ?? 00 00 8b 88 ?? ?? ff ff 89 0c 24}  //weight: 1, accuracy: Low
        $x_1_3 = {30 00 00 83 07 00 c7 ?? ?? ?? (00 00|ff ff) 00 ?? ?? ?? ?? (c4 fc|ec 04) 8d ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 33 f6 (0b f0|4e) 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 85 19 ff ff ff 33 c0 c9 c3 8d ?? ?? ?? ?? ?? 64 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Cutwail_E_2147600356_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.E"
        threat_id = "2147600356"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\runtime" wide //weight: 10
        $x_10_2 = "drivers\\runtime.sys" wide //weight: 10
        $x_10_3 = "\\\\.\\Runtime" ascii //weight: 10
        $x_2_4 = "NtLoadDriver" ascii //weight: 2
        $x_1_5 = "drivers\\secdrv.sys" wide //weight: 1
        $x_1_6 = "drivers\\ip6fw.sys" wide //weight: 1
        $x_1_7 = "drivers\\netdtect.sys" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Cutwail_Y_2147601662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.Y"
        threat_id = "2147601662"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 0d 18 00 00 00 8b 49 30 8b 1d ?? ?? 40 00 89 59 08 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {25 00 00 ff ff 05 00 ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {30 1f 80 c3 ?? e8 1a 00 00 00 30 0f 80 c1 ?? e8 10 00 00 00 30 17 80 c2 ?? e8 06 00 00 00 eb e0}  //weight: 1, accuracy: Low
        $x_1_4 = {8b f0 c1 e6 03 ff 15 ?? ?? ?? ?? 8b e5 ff 15 ?? ?? ?? ?? 83 c0 ?? 03 c6}  //weight: 1, accuracy: Low
        $x_1_5 = {33 f6 0b f0 c1 e6 03 8d 1d ?? ?? ?? ?? ff 93 ?? ?? ?? ?? 8b e5 8d 15 ?? ?? ?? ?? ff 92 ?? ?? ?? ?? b9 ?? ?? ?? ?? 03 c1 03 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Cutwail_Z_2147603607_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.Z"
        threat_id = "2147603607"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 c1 e3 03 81 c3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b e5 ff 15 ?? ?? ?? ?? c1 e0 11 2d ?? ?? ?? ?? 03 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {03 45 fc 31 03 83 e9 [0-3] 7c 08 03 45 f8 83 c3 04 eb ?? 33 c0 8b 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 2f 0a ab 3d 81 c1 ae c2 10 6d 8b 45 fc 83 c0 04 39 08 75 f9 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Cutwail_AA_2147605015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AA"
        threat_id = "2147605015"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 33 c9 03 4d f0 8b 5d ec 8b 45 f4}  //weight: 1, accuracy: High
        $x_1_2 = {ff e0 b8 fa 1f 00 00 03 45 e4}  //weight: 1, accuracy: High
        $x_1_3 = {45 ec 8d 45 fc 50 6a 04 ff 75 f0 ff 75 ec 01 00 (89|8f)}  //weight: 1, accuracy: Low
        $x_1_4 = {58 6a 40 68 00 30 00 00 ff 73 50 ff 73 34}  //weight: 1, accuracy: High
        $x_1_5 = {50 6a 38 e8 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {50 90 6a 38 e8}  //weight: 1, accuracy: High
        $x_1_7 = {b9 e4 c7 f5 8b 81 c1 f9 04 c6 1e}  //weight: 1, accuracy: High
        $x_1_8 = {b9 cd 25 7f 4c 81 c1 10 a7 3c 5e}  //weight: 1, accuracy: High
        $x_1_9 = {81 c1 fd e6 49 6d 81 e9 28 1a 8e c2}  //weight: 1, accuracy: High
        $x_1_10 = {81 c1 3d e6 49 6d 81 e9 28 1a 8e c2}  //weight: 1, accuracy: High
        $x_1_11 = {ac aa e2 fc c3}  //weight: 1, accuracy: High
        $x_1_12 = {c7 45 fc 01 00 00 00 31 03 83 e9 ?? 2b 4d ?? 7c 11}  //weight: 1, accuracy: Low
        $x_2_13 = {c7 45 fc 01 00 00 00 90 31 03 83 c3 04 3b d9 73 0b}  //weight: 2, accuracy: High
        $x_1_14 = {8f 45 f8 c7 45 fc 01 00 00 00 31 03 83 e9 04 7e}  //weight: 1, accuracy: High
        $x_1_15 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 4d d0 3b 48 08 74 04 8b 00 eb f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Cutwail_AB_2147605027_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AB"
        threat_id = "2147605027"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d ec 8b f3 8b 5b 3c 03 de 8a 43 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-48] 8b 75 0c 8b 7d 10 8b 4d 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_AC_2147605331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AC"
        threat_id = "2147605331"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff e2 68 00 20 00 00 8f 45 ec}  //weight: 1, accuracy: High
        $x_1_2 = {8d 80 86 00 00 00 83 c0 02}  //weight: 1, accuracy: High
        $x_1_3 = {31 03 83 e9 02 49 49 7c 08 03 45 ?? 83 c3 04 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Cutwail_AD_2147605944_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AD"
        threat_id = "2147605944"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 68 80 24 08 9d}  //weight: 1, accuracy: High
        $x_1_2 = "\\System32\\WinNt32.dll" ascii //weight: 1
        $x_1_3 = {53 74 61 72 74 00 00 00 54 79 70 65 00 00 00 00 41 73 79 6e 63 68 72 6f 6e 6f 75 73 00 00 00 00 49 6d 70 65 72 73 6f 6e 61 74 65 00 53 74 61 72 74 53 68 65 6c 6c 00 00 44 4c 4c 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "WLEventStartShell" ascii //weight: 1
        $x_1_5 = {5c 5c 2e 5c 50 72 6f 74 32 00 00 00 52 75 6e}  //weight: 1, accuracy: High
        $x_1_6 = "StartServiceA" ascii //weight: 1
        $x_1_7 = "FindResourceA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_E_2147606365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.gen!E"
        threat_id = "2147606365"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 06 74 c6 46 01 63 c6 46 02 70 c6 46 03 73 c6 46 04 72 c6 46 05 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 24 6c 9d ff 74 24 24 89 44 24 24 89 7c 24 20 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_AG_2147608398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AG"
        threat_id = "2147608398"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 0c 51 e8 ?? ?? ff ff 68 ?? ?? 01 00 8d 55 ec 52 ff 15 ?? ?? 01 00 8d 45 fc 50 6a 00 68 00 01 00 00 6a 22 8d 4d ec 51 6a 00 8b 55 08 52 ff 15 ?? ?? 01 00 89 45 c8 83 7d c8 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Device\\" wide //weight: 1
        $x_1_3 = {8b 4d 08 c7 41 38 ?? ?? 01 00 8b 55 08 c7 42 40 ?? ?? 01 00 8b 45 08 c7 40 70 ?? ?? 01 00 68 ?? ?? 01 00 8d 4d e4 51 ff 15 ?? ?? 01 00 8d 55 ec 52 8d 45 e4 50 ff 15 ?? ?? 01 00 89 45 c8 83 7d c8 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\DosDevices\\" wide //weight: 1
        $x_1_5 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\WinCtrl32" wide //weight: 1
        $x_1_6 = "\\SystemRoot\\system32\\WinCtrl32.dll" wide //weight: 1
        $x_1_7 = "EXERESOURCE" wide //weight: 1
        $x_1_8 = "Impersonate" wide //weight: 1
        $x_1_9 = "StartShell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_AH_2147608840_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AH"
        threat_id = "2147608840"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b c8 64 8b 1d 18 00 00 00 85 c9 74 01 42}  //weight: 2, accuracy: High
        $x_2_2 = {8f 45 f8 09 03 83 e9 04 7e 14 03 45 f8 03 45 fc}  //weight: 2, accuracy: High
        $x_1_3 = {25 00 00 ff ff c1 e2 09}  //weight: 1, accuracy: High
        $x_1_4 = {8b f0 83 c6 c4 8b 08 8b 4c 31 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Cutwail_AJ_2147609389_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AJ"
        threat_id = "2147609389"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 4a 43 8b 03 2d ?? ?? ?? ?? 3b c1 75 f4 42 83 fa ?? 75 ee 83 eb 07 80 3b 90 74 01 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_AL_2147609615_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AL"
        threat_id = "2147609615"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 78 0c 63 74 00 56 74 05 83 c2 04 eb eb}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 cc 77 00 00 75 07}  //weight: 1, accuracy: High
        $x_1_3 = {75 12 53 64 8b 1d 18 00 00 00 8b 5b 30 ff 75 ec 8f 43 08 5b}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4d 08 c1 e1 0a 2b d1 8d 05 ?? ?? ?? ?? d1 e1 03 c1 23 c2 8b f0 ba}  //weight: 1, accuracy: Low
        $x_1_5 = {01 55 f8 31 03 83 e9 04 7e 14 03 45 f8}  //weight: 1, accuracy: High
        $x_1_6 = {e8 0b 00 00 00 90 e8 25 00 00 00 5b ff d0 53 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Cutwail_H_2147609904_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.gen!H"
        threat_id = "2147609904"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 0c ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 75 04 32 c0 eb 0c 8b 45 fc 3b 45 10 75 d7 b0 00 04 01}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 f8 58 89 45 f0 8b 45 fc 89 45 e8 c7 45 e0}  //weight: 1, accuracy: High
        $x_1_3 = {8d 45 e0 50 8d 45 cc 50 55 54 5d 51 83 65 fc 00 eb 09 ff 75 fc 58 40 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Cutwail_AO_2147610126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AO"
        threat_id = "2147610126"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 82 ?? ?? ?? ?? 38 08 74 01 40 56 ff d0 [0-10] 81 ea ?? ?? ff bf}  //weight: 1, accuracy: Low
        $x_1_2 = {01 55 f8 31 03 83 e9 04 7e 14 03 45 f8}  //weight: 1, accuracy: High
        $x_1_3 = {43 61 6e 63 65 6c 49 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_AR_2147619890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AR"
        threat_id = "2147619890"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 ec 8d 45 fc 50 6a 04 ff 75 f0 ff 75 ec 01 00 (89|8f)}  //weight: 1, accuracy: Low
        $x_1_2 = {25 00 00 ff ff c1 e2 09}  //weight: 1, accuracy: High
        $x_1_3 = {80 38 90 74 01 40 83 ec 08 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_AW_2147632846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.AW"
        threat_id = "2147632846"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 3c 08 c2 75 0d 38 54 08 01 75 07 80 7c 08 02 00}  //weight: 2, accuracy: High
        $x_1_2 = {89 46 08 8b 48 3c 03 c8 89 4e 0c 5e}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 54 18 06 8b 4c 18 28 03 c3 8d 14 92 8d ?? d0 d0 00 00 00 03 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Cutwail_K_2147688299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.gen!K"
        threat_id = "2147688299"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 66 be c5 ee 66 81 ee b6 ee 2b f1 2b fe eb ?? 33 c0 66 8b 07 c1 e0 02 8b 73 1c 03 f2 03 f0 ad 03 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 08 8a 45 0c 8a e0 66 50 c1 e0 10 66 58 8b 4d 10 c1 e9 02 fc f2 ab 8b 4d 10 83 e1 03 f2 aa}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 f0 33 d2 b9 3d 00 00 00 f7 f1 8b 45 08 03 45 f8 8a 8a ?? ?? ?? ?? 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_K_2147689799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.gen!K!!Cutwail.gen!K"
        threat_id = "2147689799"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Cutwail: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "K: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 66 be c5 ee 66 81 ee b6 ee 2b f1 2b fe eb ?? 33 c0 66 8b 07 c1 e0 02 8b 73 1c 03 f2 03 f0 ad 03 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 08 8a 45 0c 8a e0 66 50 c1 e0 10 66 58 8b 4d 10 c1 e9 02 fc f2 ab 8b 4d 10 83 e1 03 f2 aa}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 f0 33 d2 b9 3d 00 00 00 f7 f1 8b 45 08 03 45 f8 8a 8a ?? ?? ?? ?? 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Cutwail_CCIO_2147924733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cutwail.CCIO!MTB"
        threat_id = "2147924733"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b8 ab aa aa aa f7 e6 8b c6 c1 ea 04 8d 0c 52 c1 e1 03 2b c1 8a 4c 04 14 8b 44 24 10 32 8e ?? ?? ?? ?? 88 0c 06 46 3b 74 24 2c 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

