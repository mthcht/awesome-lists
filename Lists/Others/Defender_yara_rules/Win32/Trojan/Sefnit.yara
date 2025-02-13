rule Trojan_Win32_Sefnit_A_147641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.A"
        threat_id = "147641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 64 6c 6c 00 44 6c 6c 49 6e 69 74 00 44 6c 6c 49 6e 73 74 61 6c 6c 00 00}  //weight: 10, accuracy: High
        $x_1_2 = {b8 b7 00 00 00 (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_3 = {81 ec bc 06 00 00 03 01 01 05 eb e9 68 04 01 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {ff d2 85 c0 [0-6] c7 45 f8 00 00 00 00 e9}  //weight: 1, accuracy: Low
        $x_1_5 = {8f 45 f4 81 75 f4}  //weight: 1, accuracy: High
        $x_1_6 = {01 40 00 80 03 00 c7 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_B_149331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.B"
        threat_id = "149331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 7c 24 1c 49 8b 04 8e 35 ?? ?? ?? ?? 89 04 8f 83 f9 00 75 ef}  //weight: 2, accuracy: Low
        $x_2_2 = {81 ec 18 06 00 00 03 01 07 09 e9 c7 45 fc 01 00 00 00 c7 85 ?? ?? ?? ?? 01 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {83 c4 1c 58 ff 25 ?? ?? ?? ?? 05 00 a3 00}  //weight: 2, accuracy: Low
        $x_1_4 = {b8 01 40 00 80 5d e9}  //weight: 1, accuracy: High
        $x_1_5 = {55 81 2c 24 ?? ?? ?? ?? 6a 02 00 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_E_154043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.E"
        threat_id = "154043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 b7 a3 42 17 (6a|e9|eb)}  //weight: 1, accuracy: Low
        $x_1_2 = {01 40 00 80 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_3 = {55 83 2c 24 ?? 6a ?? 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_H_158649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.H"
        threat_id = "158649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a9 fe ff ff ff 74 1d 8b 46 24 8b 55 ?? 66 8b 14 4a 8d 04 48 66 31 10 8b 45 ?? 2b 45 ?? 41 d1 f8 3b c8 75 e3}  //weight: 2, accuracy: Low
        $x_1_2 = "gettasks.php?protocol=" ascii //weight: 1
        $x_1_3 = "\\daily-backdoor-stable-ed2k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_J_159259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.J"
        threat_id = "159259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 f8 01 40 00 80}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 8c 28 f4 fe ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {88 94 29 f4 fe ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {8b e5 5d ff 25}  //weight: 1, accuracy: High
        $x_1_5 = {c7 45 f0 70 14 3a 03}  //weight: 1, accuracy: High
        $x_1_6 = {c7 45 f0 40 92 89 d1}  //weight: 1, accuracy: High
        $x_1_7 = {c7 45 f0 b0 e7 d9 f5}  //weight: 1, accuracy: High
        $x_1_8 = {66 c7 45 f4 82 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sefnit_L_159693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.L"
        threat_id = "159693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 74 61 73 6b 73 2e 70 68 70 3f 70 72 6f 74 6f 63 6f 6c 3d ?? 26 70 72 6f 74 6f 76 65 72 73 69 6f 6e 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {67 00 65 00 74 00 74 00 61 00 73 00 6b 00 73 00 2e 00 70 00 68 00 70 00 3f 00 70 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 3d 00 ?? ?? 26 00 70 00 72 00 6f 00 74 00 6f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00}  //weight: 1, accuracy: Low
        $x_2_3 = {5c 6f 75 74 70 75 74 5c 4d 69 6e 53 69 7a 65 52 65 6c 5c (62 6f 74 2e 70|62 61 63 6b 64 6f 6f 72 2e 70)}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_M_161693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.M"
        threat_id = "161693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 8c 28 f4 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {88 94 29 f4 fe ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {8b e5 5d ff 25}  //weight: 1, accuracy: High
        $x_1_4 = {8b 14 8e 81 f2 ?? ?? ?? ?? 89 14 8f 83 f9 00 75 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sefnit_O_161835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.O"
        threat_id = "161835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 14 8e 81 f2}  //weight: 1, accuracy: High
        $x_1_2 = {8b 3c 8e 81 f7}  //weight: 1, accuracy: High
        $x_1_3 = {89 14 8f 83 f9 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 0c be 81 f1 00}  //weight: 1, accuracy: High
        $x_1_5 = {89 14 8f eb (0a 00|83)}  //weight: 1, accuracy: Low
        $x_1_6 = {89 0c ba eb (11 00|83)}  //weight: 1, accuracy: Low
        $x_1_7 = {89 0c ba 83 ff 00 06 00 81 f1}  //weight: 1, accuracy: Low
        $x_1_8 = {81 3a 8b 44 24 04 75}  //weight: 1, accuracy: High
        $x_1_9 = {0f be 42 02 83 f8 48}  //weight: 1, accuracy: High
        $x_1_10 = {8b e5 5d ff 25 ?? ?? ?? 10 03 01 01 01 55 eb 8b}  //weight: 1, accuracy: Low
        $x_1_11 = {0f b7 51 02 83 fa (74 74|65)}  //weight: 1, accuracy: Low
        $x_1_12 = {0f b7 42 06 83 f8 50 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sefnit_A_165199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.gen!A"
        threat_id = "165199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 77 6f 72 6b 73 70 61 63 65 5c 6f 75 74 70 75 74 5c 4d 69 6e 53 69 7a 65 52 65 6c 5c 62 61 63 6b 64 6f 6f 72 2e 70 64 62 00}  //weight: 10, accuracy: High
        $x_10_2 = {2e 63 6f 6d 2f 67 65 74 74 61 73 6b 73 2e 70 68 70 00}  //weight: 10, accuracy: High
        $x_1_3 = {3f 70 72 6f 74 6f 63 6f 6c 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 61 63 6b 64 6f 6f 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 6c 6f 62 61 6c 5c 7b 33 39 44 35 46 43 35 34 2d 44 44 33 36 2d 34 31 61 66 2d 39 33 45 36 2d 44 45 45 33 30 30 32 44 46 42 41 25 64 7d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_B_165201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.gen!B"
        threat_id = "165201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 6f 75 74 70 75 74 5c 4d 69 6e 53 69 7a 65 52 65 6c 5c 75 70 64 61 74 65 72 2e 70 64 62 00}  //weight: 10, accuracy: High
        $x_1_2 = {2e 63 6f 6d 2f 75 70 64 61 74 65 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 00 25 00 73 00 2f 00 25 00 64 00 2d 00 25 00 64 00 2d 00 25 00 64 00 5f 00 47 00 54 00 43 00 5f 00 54 00 4d 00 50 00 5f 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {75 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 00 70 00 64 00 72 00 65 00 6d 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {69 00 70 00 66 00 69 00 6c 00 74 00 65 00 72 00 5f 00 73 00 74 00 61 00 74 00 69 00 63 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {41 00 77 00 72 00 6d 00 5f 00 6d 00 75 00 74 00 65 00 78 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_V_165971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.V"
        threat_id = "165971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s?protocol=%d&protoversion=%d&o=0&p=%s&f=%d" ascii //weight: 1
        $x_1_2 = {2f 67 65 74 74 61 73 6b 73 33 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
        $x_2_4 = {56 8b cf 80 f3 ?? e8 ?? ?? ?? ?? 46 88 18 83 fe 2d 72 e7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_X_166577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.X"
        threat_id = "166577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 83 c0 1c 50 8b 4d 0c 83 c1 14 51 8b 55 0c 83 c2 0c 52 8b 45 0c 83 c0 04 50 8b 4d 08 51 e8 ?? ?? ?? ?? 83 c4 14}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 0f b7 51 02 83 fa 74 eb 74 ?? 8b 45 08 0f b7 48 02 83 f9 54 eb 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_Z_166707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.Z"
        threat_id = "166707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 1d 83 fe 01 75 18 c7 45 fc 0c 00 00 00 e8}  //weight: 2, accuracy: High
        $x_1_2 = {68 06 02 00 00 53 8d 85 ca 00 00 00 50 e8}  //weight: 1, accuracy: High
        $x_1_3 = {2f 67 65 74 38 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 30 74 44 30 6f 63 6d 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "88.198.238.13/" ascii //weight: 1
        $x_1_6 = "62.109.21.90/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_AA_167738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AA"
        threat_id = "167738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 fc 31 4d fc 83 (3d ?? ?? ?? ?? ??|7d ?? ??) 03 02 01 01 0f 85 74 75}  //weight: 2, accuracy: Low
        $x_1_2 = {66 83 7e 08 3a 0f 85 ?? ?? ?? ?? [0-8] 66 83 7e 0a 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {66 83 78 08 3a 0f 85 ?? ?? ?? ?? [0-8] 66 83 78 0a 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_AC_168309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AC"
        threat_id = "168309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 32 6a 13 89 ?? ?? ff 75 08}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 32 6a 13 ff 75 08}  //weight: 1, accuracy: High
        $x_1_3 = {05 22 4e 62 fe}  //weight: 1, accuracy: High
        $x_1_4 = {05 00 80 c1 2a}  //weight: 1, accuracy: High
        $x_1_5 = {8a 0c 0f 30 0c 03}  //weight: 1, accuracy: High
        $x_1_6 = {8a 0c 0f 89 ?? ?? 30 0c 03}  //weight: 1, accuracy: Low
        $x_1_7 = {8a 0c 0f 30 0c 18}  //weight: 1, accuracy: High
        $x_1_8 = {8a 0c 0f 89 ?? ?? 30 0c 18}  //weight: 1, accuracy: Low
        $x_1_9 = {6a 6b 6a 6b 8d 45}  //weight: 1, accuracy: High
        $x_1_10 = {6a 6b 6a 6b 89 ?? ?? 8d 45}  //weight: 1, accuracy: Low
        $x_1_11 = {66 83 f9 24 73 ?? 89 ?? ?? 89 ?? ?? 80 c1 16}  //weight: 1, accuracy: Low
        $x_1_12 = {66 83 f8 24 73 ?? 89 ?? ?? 89 ?? ?? 04 16}  //weight: 1, accuracy: Low
        $x_1_13 = {66 83 fb 24 73 ?? 89 ?? ?? 80 c3 16}  //weight: 1, accuracy: Low
        $x_1_14 = {66 83 f9 24 73 ?? 89 ?? ?? 80 c1 16}  //weight: 1, accuracy: Low
        $x_1_15 = {66 83 7e 08 3a 0f 85 ?? ?? ?? ?? [0-8] 66 83 7e 0a 2f}  //weight: 1, accuracy: Low
        $x_1_16 = {66 83 78 08 3a 0f 85 ?? ?? ?? ?? [0-8] 66 83 78 0a 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sefnit_AI_168558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AI"
        threat_id = "168558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 ff 45 e8 83 f8 05 7e (10 00|0d 00 57 ff (d6|d3))}  //weight: 1, accuracy: Low
        $x_1_2 = {57 ff d6 8b c3 43 83 f8 05 7e}  //weight: 1, accuracy: High
        $x_1_3 = {47 6c 6f 62 61 6c 5c 56 42 6f 78 53 65 72 76 69 63 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_3_4 = "\\output\\MinSizeRel\\updrem.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_AJ_168559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AJ"
        threat_id = "168559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff b0 40 07 00 00 [0-19] ff b0 3c 07 00 00 [0-19] (ff 15|e8)}  //weight: 1, accuracy: Low
        $x_1_2 = {ff b2 40 07 00 00 [0-15] ff b2 3c 07 00 00 [0-16] (ff 15|e8)}  //weight: 1, accuracy: Low
        $x_1_3 = {ff b1 40 07 00 00 [0-15] ff b1 3c 07 00 00 [0-14] (ff 15|e8)}  //weight: 1, accuracy: Low
        $x_1_4 = {89 86 40 07 00 00 89 86 3c 07 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {89 9e 3c 07 00 00 89 9e 44 07 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {89 86 3c 07 00 00 89 86 44 07 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {89 96 3c 07 00 00 89 96 44 07 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {c0 ff 7f c9 c2 02 00 2d}  //weight: 1, accuracy: Low
        $x_1_9 = {0f be c3 69 c0 ?? ?? ?? 00 05}  //weight: 1, accuracy: Low
        $x_1_10 = {80 7b 06 3a 0f 85 ?? ?? ?? ?? 80 7b 07 2f}  //weight: 1, accuracy: Low
        $x_1_11 = {80 78 06 3a 0f 85 ?? ?? ?? ?? 80 78 07 2f}  //weight: 1, accuracy: Low
        $x_1_12 = {50 8b c6 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
        $n_100_13 = "FlashPlayerControl_%s_%d" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_Sefnit_AK_169953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AK"
        threat_id = "169953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 18 8b 45 f4 ff 75 14 03 c6 ff 75 10 ff 75 0c a3 ?? ?? ?? ?? ff 75 08 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6b f6 28 8d 74 32 04 [0-16] 83 3e 00 74 [0-16] 83 c6 04 83 [0-2] 0a 7c ?? eb [0-8] 6b ?? 0a [0-16] 89 ?? ?? 04}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be c3 69 c0 [0-8] 05 ?? ?? ?? ?? (e9|eb)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sefnit_AL_170299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AL"
        threat_id = "170299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fa 7b 0f 85 0e 00 [0-11] 0f be 11}  //weight: 1, accuracy: Low
        $x_1_2 = {83 bc 8a 0c 03 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 82 24 06 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 81 24 06 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_AM_170424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AM"
        threat_id = "170424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "drmnguard.com/gettasks.php" wide //weight: 1
        $x_1_2 = "virtguard.com/gettasks.php" wide //weight: 1
        $x_1_3 = "licguard.com/gettasks.php" wide //weight: 1
        $x_1_4 = "backdoor\\release\\output\\MinSizeRel\\backdoor.pdb" ascii //weight: 1
        $x_1_5 = {8d 45 f3 50 8d 45 f3 50 ff 75 e8 8d 4d d8 88 5d f3 e8 ?? ?? ?? ?? c6 45 fc 03 39 5d e8 74 1b 8d 45 ec 50 ff 75 e8 ff 75 d8 ff 76 08}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 45 f3 50 ff 75 ec 8d 4d d8 88 5d f3 e8 ?? ?? ?? ?? 8b 85 ?? ?? 00 00 2b c3 74 3a 48 75 75 53 8d 45 e4 50 ff 75 ec 89 5d e4 ff 75 d8 ff 75 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_C_170425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.gen!C"
        threat_id = "170425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 6f 75 74 70 75 74 5c 4d 69 6e 53 69 7a 65 52 65 6c 5c 62 61 63 6b 64 6f 6f 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 63 6f 6d 2f 67 65 74 74 61 73 6b 73 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = "/mod.php" wide //weight: 1
        $x_1_4 = {47 6c 6f 62 61 6c 5c 7b 33 39 44 35 46 43 35 34 2d 44 44 33 36 2d 34 31 61 66 2d 39 33 45 36 2d 44 45 45 33 30 30 32 44 46 42 41 25 64 7d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sefnit_AN_170950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AN"
        threat_id = "170950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/%d-%d-%d_GTC_TMP_" ascii //weight: 1
        $x_1_2 = "wrm_mutex" ascii //weight: 1
        $x_1_3 = "self-murder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_AP_174966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AP"
        threat_id = "174966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 3b c5 1b d2 23 54 24 ?? 2b d5 03 d0 8a 14 3a 88 14 38 01 00 90}  //weight: 10, accuracy: Low
        $x_1_2 = {56 8b cf 80 f3 ?? e8 ?? ?? ?? ?? 46 88 18 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b cf 80 f3 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b cf 80 f3 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b cf 80 f3}  //weight: 1, accuracy: Low
        $x_1_3 = {5e 8a 14 01 80 f2 ?? 88 10 40 4e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8a 14 01 80 f2 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8a 14 01 80 f2 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8a 14 01 80 f2 00}  //weight: 1, accuracy: Low
        $x_10_4 = "Windows Internet Name Service" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_AS_198456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AS"
        threat_id = "198456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 00 79 00 6d 00 61 00 6e 00 74 00 65 00 63 00 00 00 00 00 65 00 73 00 65 00 74 00 00 00 00 00 6b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 00 00 61 00 76 00 67 00 00 00 6e 00 6f 00 72 00 74 00 6f 00 6e 00 00 00 00 00 61 00 76 00 69 00 72 00 61 00 00 00 61 00 76 00 61 00 73 00 74 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "/create /tn \"%s\" /ru \"SYSTEM\" /sc hourly /mo 1 /tr \"%s /w\" /st 00:00:00" wide //weight: 2
        $x_4_3 = {2b c8 8b d7 bb ?? ?? ?? ?? 66 33 1c 01 66 89 18 83 c0 02 4a 75 ee}  //weight: 4, accuracy: Low
        $x_2_4 = {b9 a2 9f a2 98 a2 9e a2 99 a2 88 a2 89 a2 cd a2 a4 a2 83 a2 9e a2 99 a2 8c a2 81 a2 81 a2 88 a2 9f a2}  //weight: 2, accuracy: High
        $x_2_5 = {eb 35 ff d7 2b c3 3d 30 75 00 00 77 39 0a 00 2d 26 04 00 00}  //weight: 2, accuracy: Low
        $x_4_6 = {66 89 14 08 83 c0 02 83 f8 ?? 72 dc 8b c6 e8 ?? ?? ?? ?? c3 0e 00 8b ce ba ?? ?? ?? ?? 66 33 90}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_D_199336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.gen!D"
        threat_id = "199336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 52 00 00 00 00 00 2f 00 49 00 00 00}  //weight: 1, accuracy: High
        $x_2_2 = {74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 00 00 54 00 6f 00 72 00 00 00 6e 00 65 00 74 00 73 00 76 00 63 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {8b 56 14 80 f1 ?? 88 0c 10 8a 90 ?? ?? ?? ?? 8b 4e 14 80 f2 ?? 88 54 01 01 83 c0 02 83 f8 16 72 d9}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 4e 24 ba ?? ?? 00 00 66 33 90 ?? ?? ?? ?? 83 c0 02 66 89 54 08 fe 83 f8 ?? 72 e4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_AU_199348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AU"
        threat_id = "199348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {bb 8c ac 00 00 66 33 1c 01 66 89 18 03 c7 4a}  //weight: 2, accuracy: High
        $x_1_2 = {e4 ac f8 ac f8 ac fc ac b6 ac a3 ac a3 ac ff ac fe ac fa ac f9 ac fc ac e8 ac a2 ac e2 ac e9 ac f8 ac}  //weight: 1, accuracy: High
        $x_2_3 = {bb ed a2 00 00 66 33 1c 01 66 89 18 83 c0 02}  //weight: 2, accuracy: High
        $x_1_4 = {9e a2 88 a2 9f a2 9b a2 84 a2 8e a2 88 a2 c0 a2 9e a2 99 a2 8c a2 99 a2 c3 a2 8e a2 82 a2 80 a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_AU_199348_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AU"
        threat_id = "199348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/create /tn \"%s\" /ru \"SYSTEM\" /sc hourly /mo 1 /tr \"%s /w\" /st 00:00:00" wide //weight: 1
        $x_1_2 = {7d 0a 68 57 00 07 80 e8 ?? ?? ff ff 89 79 f4 8b 0e 33 d2 66 89 51 18 b9 ?? ?? ?? ?? 2b c8 8b d7 bb ?? ?? 00 00 66 33 1c 01 66 89 18 83 c0 02 4a 75 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Sefnit_AR_199598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AR"
        threat_id = "199598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 02 75 7f 8b 46 04 66 83 38 2f 75 38 0f b7 48 02 66 83 f9 49 74 06 66 83 f9 55 75 28}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 01 80 f2 ?? 88 10 40 83 ed 01 75 f2 8b 43 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_AV_199689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AV"
        threat_id = "199689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 8b d7 8a 1c 01 80 f3 ?? 88 18 40 4a 75 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 60 8b 45 0c 8d 34 b8 68 ?? ?? ?? ?? ff 36 e8 ?? ?? ?? ?? 59 59 85 c0 74 72 68 ?? ?? ?? ?? ff 36}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_AW_199945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AW"
        threat_id = "199945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 89 0c 07 83 c7 02 83 ff ?? 72 dc 8b c6 e8 ?? ?? ?? ?? c3 0e 00 8b c6 b9 ?? ?? ?? ?? 66 33 8f}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c2 05 c1 e2 0a 52 0c 00 6a 64 59 99 f7 f9 8d 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 07 59 33 f6 33 d2 89 48 14 89 70 10 66 89 10 89 75 fc 89 48 30 89 70 2c 66 89 50 1c c6 45 fc 01 89 48 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sefnit_AX_199995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AX"
        threat_id = "199995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 1e 1b cb 39 8d ?? ?? ?? ?? 7c 0a 7f 59 39 85 ?? ?? ?? ?? 73 51 53 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {75 1f 83 ef 1e 83 db 00 39 9d ?? ?? ?? ?? 7c 0a 7f 2c 39 bd ?? ?? ?? ?? 73 24 68}  //weight: 1, accuracy: Low
        $x_1_3 = {75 27 83 ef 78 83 db 00 39 9d ?? ?? ?? ?? 7c 12 0f 8f ?? ?? ?? ?? 39 bd ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_4 = {75 1d 83 ef 78 83 db 00 39 5e 04 7f 3b 7c 04 39 3e 73 35 68}  //weight: 1, accuracy: High
        $x_4_5 = "o: resuming from idle" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_AY_199996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AY"
        threat_id = "199996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 06 83 7f 14 08 72 04 8b ?? eb 02 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 2d 00 61 00 70 00 70 00 3d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_AZ_199997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.AZ"
        threat_id = "199997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 06 6a 65 ff b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 5a 23 00 00 6a 3b ff b5 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 06 6a 65 51 e8 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 68 5a 23 00 00 6a 3b 52 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "4qn5laf3vbbjmtob" ascii //weight: 1
        $x_1_4 = "4yhyqt34lhsgiorq" ascii //weight: 1
        $x_1_5 = "dltj7e2emw6vx3ox" ascii //weight: 1
        $x_1_6 = "dmnm6to52gf7oh3c" ascii //weight: 1
        $x_1_7 = "hyhinq6d5ykyyrjp" ascii //weight: 1
        $x_1_8 = "ir4jywagolzpgvf4" ascii //weight: 1
        $x_1_9 = "kc2xim2ngcjo3j7a" ascii //weight: 1
        $x_1_10 = "mlil6xmf2izmg3sb" ascii //weight: 1
        $x_1_11 = "mndl2r35myqmks62" ascii //weight: 1
        $x_1_12 = "scbxw2kmwecza2dt" ascii //weight: 1
        $x_1_13 = "sjs5v6s4ow3si5by" ascii //weight: 1
        $x_1_14 = "smhmhkztdpfndjh5" ascii //weight: 1
        $x_1_15 = "vygkl75hjxl325sy" ascii //weight: 1
        $x_1_16 = "yc2sn5nnqhzx7cp2" ascii //weight: 1
        $x_1_17 = "ccczq2ey64363sse" ascii //weight: 1
        $x_1_18 = "qnmoogwnni4ljhpp" ascii //weight: 1
        $x_1_19 = "pu7xvyizwlaj6qzm" ascii //weight: 1
        $x_1_20 = "zrjyaxy22fpa5wmq" ascii //weight: 1
        $x_1_21 = "mttfdkggyxsb65r7" ascii //weight: 1
        $x_1_22 = "r5ps3rub53h3ik7v" ascii //weight: 1
        $x_1_23 = "yorqugmaygmydgdv" ascii //weight: 1
        $x_1_24 = "axo73ert2o4zm4ef" ascii //weight: 1
        $x_1_25 = "g4pn4hpibjrxosbt" ascii //weight: 1
        $x_1_26 = "o42m4b4h2tmj7wpg" ascii //weight: 1
        $x_1_27 = "5qj2lz4bqtkr5pnr" ascii //weight: 1
        $x_1_28 = "tjsk54s63mjzgrtl" ascii //weight: 1
        $x_1_29 = "24uy4p4wbaimdeuz" ascii //weight: 1
        $x_1_30 = "ktdk2e4v3sndmy7d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Sefnit_BJ_200029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.BJ"
        threat_id = "200029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b c8 8b d7 bb ?? ?? ?? ?? 66 33 1c 01 66 89 18 83 c0 02 4a 75 ee}  //weight: 3, accuracy: Low
        $x_3_2 = {39 7e 4c 72 05 8b 7e 38 eb 03 8d 7e 38 ff 75 ?? 8b cb 68}  //weight: 3, accuracy: Low
        $x_1_3 = {2d 00 67 00 70 00 75 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 00 75 00 64 00 61 00 2e 00 65 00 78 00 65 00 00 00 00 00 63 00 70 00 75 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_BN_200310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.BN"
        threat_id = "200310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 86 b0 00 00 00 2b 86 e4 00 00 00 2b 86 ac 00 00 00 03 86 e8 00 00 00 50}  //weight: 1, accuracy: High
        $x_1_2 = {89 51 44 8b 40 04 89 41 48 8d 41 28 83 ec 10 83 78 14 10 72 02 8b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_BP_200464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.BP"
        threat_id = "200464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 14 5f 5f c7 85 10 fd ff ff 5f 5f 5c 2d c7 85 14 fd ff ff 50 64 7f 5d c7 85 18 fd ff ff 2f 67 7d 2c c7 85 1c fd ff ff 5b 5f 5f 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_BQ_200640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.BQ"
        threat_id = "200640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 29 81 7d ec 5c 08 00 00 75 0d c7 45}  //weight: 1, accuracy: High
        $x_1_2 = {89 51 54 83 7d 08 02 74 0f 83 7d 08 03 74 09 c7 45}  //weight: 1, accuracy: High
        $x_1_3 = {81 c1 84 00 00 00 e9 ?? ?? ?? ?? 8b 4d ?? 81 c1 bc 00 00 00 e9 ?? ?? ?? ?? 8b 4d ?? 81 c1 f4 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b7 51 06 40 83 c6 28 89 45 fc 3b c2 7c 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Sefnit_BS_202156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.BS"
        threat_id = "202156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 06 89 45 ec 8b 4d 0c 8b 51 10 89 55 c8 8b 45 c8 83 e8 01 89 45 f0 8b 4d 0c 83 79 14 08 72 0d}  //weight: 1, accuracy: High
        $x_1_2 = {2d 00 2d 00 61 00 70 00 70 00 3d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_BT_202157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.BT"
        threat_id = "202157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 5d e4 83 7f 14 08 72 04 8b 0f eb 02 8b cf 6a 22}  //weight: 1, accuracy: High
        $x_1_2 = {2d 00 2d 00 61 00 70 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_BW_202626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.BW"
        threat_id = "202626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 37 32 04 19 41 88 06 8b c3 8d 78 01 8a 10 40 84 d2 75 f9}  //weight: 2, accuracy: High
        $x_1_2 = {62 6f 74 2e 64 6c 6c 00 5f 65 6e 74 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_BZ_202905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.BZ"
        threat_id = "202905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {46 83 fe 03 72 bd c6 45 ?? 01 eb 88 6a 04}  //weight: 3, accuracy: Low
        $x_3_2 = {6a 05 59 6a 0a 58 89 4d ?? 89 4d ?? 8d 8d ?? ?? ?? ?? c7 45 ?? 3c 00 00 00}  //weight: 3, accuracy: Low
        $x_1_3 = "ocl.exe" wide //weight: 1
        $x_1_4 = "cda.exe" wide //weight: 1
        $x_1_5 = "cpu.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_CA_202906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.CA"
        threat_id = "202906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 2e 83 65 f8 00 83 65 fc 00 8d 45 f0 50 c7 45 f0 ?? ?? ?? ?? c7 45 f4 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "Windows Network Discovery Service" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_CB_202909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.CB"
        threat_id = "202909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 78 14 08 72 02 8b 00 6a 02 50 ff 15 ?? ?? ?? ?? c6 45 fc ?? 56 53}  //weight: 2, accuracy: Low
        $x_1_2 = {5b 00 74 00 61 00 73 00 6b 00 5f 00 73 00 74 00 61 00 72 00 74 00 5d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2c 00 73 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 5f 00 74 00 61 00 73 00 6b 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_CC_203131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.CC"
        threat_id = "203131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 36 8b 3f 8d 4d dc 51 8d 55 98 52 6a 00 6a 00}  //weight: 2, accuracy: High
        $x_2_2 = {6a 0a 8b ce 74 07 68 ?? ?? ?? ?? eb 05 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 0c 68}  //weight: 2, accuracy: Low
        $x_2_3 = ".?AVWatcherExec@@" ascii //weight: 2
        $x_1_4 = "\\themes.dll" wide //weight: 1
        $x_1_5 = "\\startup_module.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sefnit_CD_203132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.CD"
        threat_id = "203132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 8b ff 8a 14 01 80 f2 ?? 88 10 40 4f 75 f4 8b 06 b9 ?? ?? ?? ?? 39 48 f8 7c ca}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 bb 01 00 00 68 ?? ?? ?? ?? 51 57 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_CF_203497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.CF"
        threat_id = "203497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d6 b0 01 eb 3a 53 53 56 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {2d 00 2d 00 69 00 64 00 6c 00 65 00 00 00 00 00 5c 00 72 00 75 00 6e 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "_idle_trigger_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_CG_203498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.CG"
        threat_id = "203498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fe 10 7c d6 6a 01 e8 ?? ?? ?? ?? 59 33 f6 e8 ?? ?? ?? ?? 6a 63 99 59 f7 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 6a 22 bf ?? ?? ?? ?? 57 8d 8d 78 fe ff ff e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sefnit_CH_203510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefnit.CH"
        threat_id = "203510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 1f 48 74 15 2d fe 00 00 00 74 07 b8 ?? ?? ?? ?? 5d c3 b8}  //weight: 2, accuracy: Low
        $x_2_2 = {74 24 ff c9 74 18 81 f9 fe 00 00 00 74 08 48 8d 05 ?? ?? ?? ?? c3 48 8d 05}  //weight: 2, accuracy: Low
        $x_1_3 = {63 64 61 2e 67 7a 00}  //weight: 1, accuracy: High
        $x_1_4 = {2d 2d 63 75 64 61 00}  //weight: 1, accuracy: High
        $x_1_5 = {4c 6f 63 61 6c 5c 5f 5f 72 75 6e 6e 65 72 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 3f 41 56 67 7a 5f 66 69 6c 65 5f 73 74 6f 72 61 67 65 40 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

