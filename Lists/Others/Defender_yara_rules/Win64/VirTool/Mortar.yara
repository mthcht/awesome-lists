rule VirTool_Win64_Mortar_A_2147809913_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Mortar.A"
        threat_id = "2147809913"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mortar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 95 8c fe ff ff 48 03 95 e0 fd ff ff 44 8b 8d ?? fe ff ff 48 8b 8d 68 fe ff ff e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 89 44 24 20 48 8b 86 88 00 00 00 48 8d ?? ?? 4c 8d ?? ?? ?? ?? ?? 48 8b 8d 68 fe ff ff 41 b9 08 00 00 00 e8 ?? ?? ?? ?? 45 39 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 20 40 00 00 00 44 8b 85 f8 fe ff ff 48 8b 95 d8 fe ff ff 48 8b 8d 68 fe ff ff 41 b9 00 30 00 00 e8 ?? ?? ?? ?? 48 89 85 e0 fd ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 d0 fe ff ff 48 03 85 e0 fd ff ff 48 89 ?? 80 00 00 00 [0-3] 48 8b 8d 70 fe ff ff e8 ?? ?? ?? ?? 48 8b 8d 70 fe ff ff e8 ?? ?? ?? ?? b3 01}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 c6 c7 46 30 ?? ?? ?? ?? 48 89 f2 48 8b 8d 70 fe ff ff e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {48 89 44 24 20 48 8b 86 88 00 00 00 48 8d ?? ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? 48 8b 8d 68 fe ff ff 41 b9 02 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {48 8b 85 d8 fe ff ff 48 3b 85 d0 fd ff ff 0f ?? ?? ?? ?? ?? 48 8b 95 d8 fe ff ff 48 8b 8d 68 fe ff ff e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Mortar_B_2147819935_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Mortar.B"
        threat_id = "2147819935"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mortar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 48 8d ?? ?? ?? 48 89 cb 40 30 f6 48 c7 44 24 20 00 00 00 00 e8 ?? ?? ?? ?? 48 89 c1 4c 8d ?? ?? ?? 48 89 da 41 b9 10 00 00 00 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 0f 1f 00 31 d2 41 b2 01}  //weight: 1, accuracy: Low
        $x_1_2 = {53 56 48 8d ?? ?? ?? 48 89 cb 44 89 c6 48 c7 44 24 20 00 00 00 00 4c 8d ?? ?? ?? 41 89 f0 48 89 d9 e8 ?? ?? ?? ?? 85 c0 75 11}  //weight: 1, accuracy: Low
        $x_1_3 = {80 7d e8 00 74 1e 4c 8b 45 d8 45 31 c9 ba 01 00 00 00 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 45 d0}  //weight: 1, accuracy: Low
        $x_1_4 = {41 b9 04 00 00 00 41 b8 00 10 00 00 ba 08 00 00 00 31 c9 ff 15 ?? ?? ?? ?? 48 89 85 70 ff ff ff c7 40 30 1f 00 10 00 48 8b 95 70 ff ff ff 48 8b 4d e8}  //weight: 1, accuracy: Low
        $x_1_5 = {48 89 38 48 89 c7 4c 89 6f 08 48 89 f2 48 89 57 10 c7 45 fc 00 00 00 00 48 8d ?? ?? 48 89 44 24 28 44 89 64 24 20 4c 8d ?? ?? ?? ?? ?? 49 89 f9 48 89 d9 e8 ?? ?? ?? ?? 48 89 c3 85 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win64_Mortar_C_2147819936_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Mortar.C"
        threat_id = "2147819936"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mortar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4d e0 e8 ?? ?? ?? ?? 48 8b 55 e0 8b 45 d8 48 c1 e0 0a 8b 4d dc 48 8d ?? ?? ?? 8b 55 c8 89 14 88 48 8b 55 e0 8b 45 d8 48 c1 e0 0a 48 63 4d dc 48 8d ?? ?? ?? 8b 55 cc 89 14 88 83 45 dc 02 81 7d dc ff 00 00 00 ?? ?? 83 7d d8 03 ?? ?? 48 c7 45 c0 01 00 00 00 48 83 7d e0 00 ?? ?? 48 83 7d e8 00 ?? ?? 48 8b 4d e0 48 8b 45 e0 48 8b 00 ff ?? 88 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 55 f8 48 8b 4d e0 e8 ?? ?? ?? ?? 48 8b 4d e0 48 8b 45 e0 48 8b 00 ff ?? e0 00 00 00 48 85 c0 ?? ?? 48 8b 4d e0 48 8b 45 e0 48 8b 00 ff ?? e0 00 00 00 48 89 c2 48 8d ?? ?? 45 31 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {53 56 48 8d ?? ?? ?? 48 89 cb 40 30 f6 48 c7 44 24 20 00 00 00 00 e8 ?? ?? ?? ?? 48 89 c1 4c 8d ?? ?? ?? 48 89 da 41 b9 10 00 00 00 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 0f 1f 00 31 d2 41 b2 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

