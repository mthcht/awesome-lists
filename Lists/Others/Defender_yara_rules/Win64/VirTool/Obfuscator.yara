rule VirTool_Win64_Obfuscator_A_2147648286_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Obfuscator.A"
        threat_id = "2147648286"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 45 d1 8b 46 24 8b 4e 0c 25 00 00 00 08 eb 0b d0 8b 46 08 48 03 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 7b 18 8b 41 3c 48 03 c1 0f b7 50 14 48 8d 74 02 18 0f b7 50 06 48 83 ee 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Obfuscator_C_2147657883_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Obfuscator.C"
        threat_id = "2147657883"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 7c 24 20 (89 44|89 44) ff d2 (83|83) 8b d0 03 d3 (8b 4c|8b 4c) 56 57 51 51 8b 06 (b9 ?? ?? ?? ??|b9 ?? ?? ?? ??) (83|83) (48 83|48 83) 2b c2 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Obfuscator_D_2147682197_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Obfuscator.D"
        threat_id = "2147682197"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 68 3a 08 00 00 48 8b f8 ff 15 ?? ?? ?? ?? ba 08 00 00 00 48 8b c8 41 b8 23 03 00 00 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 74 30 8b 54 24 68 4c 8d 4c 24 68 48 8d 0d c8 36 00 00 41 b8 40 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b d8 48 85 c0 75 1d 48 8b 0d aa 3e 00 00 44 8d 48 0b 4c 8d 44 24 20 ba e9 03 00 00 ff 15 ?? ?? ?? ?? eb 14 ff 15 46 16 00 00 4c 8b c3 33 d2 48 8b c8 ff 15 ?? ?? ?? ?? ba 08 00 00 00 41 b8 0f 02 00 00 48 8b cf}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 01 04 47 41 88 00 0f b6 01 99 83 e0 01 33 c2 3b c2 75 05 ff c3 48 ff c1 ff c3 49 ff c0 48 ff c1 81 fb d6 08 00 00 72 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Obfuscator_ADB_2147684988_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Obfuscator.ADB"
        threat_id = "2147684988"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 41 28 ca 23 c1 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 9e f9 96 ca e8}  //weight: 1, accuracy: High
        $x_1_3 = {b9 b9 06 a0 bf e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Obfuscator_E_2147688417_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Obfuscator.E"
        threat_id = "2147688417"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 24 35 50 c6 44 24 36 72 c6 44 24 37 6f c6 44 24 38 63 c6 44 24 39 65 c6 44 24 3a 73 c6 44 24 3b 73 c6 44 24 3c 4d c6 44 24 3d 65 c6 44 24 3e 6d c6 44 24 3f 6f c6 44 24 40 72 c6 44 24 41 79}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 36 52 c6 44 24 37 65 c6 44 24 38 6d c6 44 24 39 6f c6 44 24 3a 74 c6 44 24 3b 65 c6 44 24 3c 54 c6 44 24 3d 68 c6 44 24 3e 72 c6 44 24 3f 65 c6 44 24 40 61 c6 44 24 41 64}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 30 4e c6 44 24 31 74 c6 44 24 32 43 c6 44 24 33 72 c6 44 24 34 65 c6 44 24 35 61 c6 44 24 36 74 c6 44 24 37 65 c6 44 24 38 54 c6 44 24 39 68 c6 44 24 3a 72 c6 44 24 3b 65 c6 44 24 3c 61 c6 44 24 3d 64 c6 44 24 3e 45 c6 44 24 3f 78}  //weight: 1, accuracy: High
        $x_1_4 = {57 6f 77 36 c7 40 ?? 34 44 69 73 c7 40 ?? 61 62 6c 65 c7 40 ?? 57 6f 77 36 c7 40 ?? 34 46 73 52 c7 40 ?? 65 64 69 72 c7 40 ?? 65 63 74 69 c7 40 ?? 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {57 6f 77 36 c7 44 24 ?? 34 52 65 76 c7 44 24 ?? 65 72 74 57 c7 44 24 ?? 6f 77 36 34 c7 44 24 ?? 46 73 52 65 c7 44 24 ?? 64 69 72 65 c7 44 24 ?? 63 74 69 6f c7 44 24 ?? 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 44 24 40 57 c6 44 24 41 49 c6 44 24 42 4e c6 44 24 43 49 c6 44 24 44 4e c6 44 24 45 45 c6 44 24 46 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win64_Obfuscator_F_2147691622_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Obfuscator.F"
        threat_id = "2147691622"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 48 8b 4c 24 ?? 89 01}  //weight: 1, accuracy: Low
        $x_1_2 = {91 5f 59 c3 03 00 eb 01}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 1c 00 00 00 fc f3 48 a5 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Obfuscator_G_2147696580_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Obfuscator.G"
        threat_id = "2147696580"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 33 c0 65 48 03 40 60 c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b e1 48 8b c2 4c 8b 4c 24 20 48 8b 54 24 10 48 8b 4c 24 08 4c 8b 44 24 18 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Obfuscator_LBF_2147954991_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Obfuscator.LBF"
        threat_id = "2147954991"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 0f 43 d9 44 ?? ?? 45 8d ?? ?? ?? 00 00 45 0f af cb 41 ?? ?? 44 ?? ?? 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

