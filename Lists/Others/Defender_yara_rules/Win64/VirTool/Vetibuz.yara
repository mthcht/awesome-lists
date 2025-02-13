rule VirTool_Win64_Vetibuz_A_2147833347_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Vetibuz.A!MTB"
        threat_id = "2147833347"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Vetibuz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 41 b8 00 10 00 00 ba a0 86 01 00 33 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {41 b8 a0 86 01 00 48 8b 95 ?? ?? 00 00 48 8b 8d ?? ?? 00 00 ff 15 ?? ?? ?? ?? 89 85}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 2c 76 c6 45 2d 69 c6 45 2e 72 c6 45 2f 75 c6 45 30 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Vetibuz_B_2147833348_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Vetibuz.B!MTB"
        threat_id = "2147833348"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Vetibuz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 41 b8 00 10 00 00 ba a0 86 01 00 33 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {41 b8 a0 86 01 00 48 8b 95 ?? ?? 00 00 48 8b 8d ?? ?? 00 00 ff 15 ?? ?? ?? ?? 89 85}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 28 61 c6 45 29 70 c6 45 2a 69 c6 45 2b 2e c6 45 2c 67 c6 45 2d 69 c6 45 2e 74 c6 45 2f 68 c6 45 30 75 c6 45 31 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Vetibuz_C_2147838151_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Vetibuz.C!MTB"
        threat_id = "2147838151"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Vetibuz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 c4 15 00 00 01 00 00 00 c7 85 e4 15 00 00 a0 86 01 00 b9 a0 86 01 00 ff 15 ?? ?? ?? ?? 48 89 85 08 16 00 00 c7 85 24 16 00 00 ff ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b8 a0 86 01 00 48 8b 95 ?? ?? 00 00 48 8b 8d ?? ?? 00 00 ff 15 ?? ?? ?? ?? 89 85}  //weight: 1, accuracy: Low
        $x_1_3 = {48 ff c0 48 89 45 28 48 8b 4d 28 ff 15 ?? ?? ?? ?? 48 89 45 48 4c 8b 45 28 48 8b 55 48 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {41 b8 e8 03 00 00 33 d2 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 61 c6 85 ?? ?? ?? ?? 70 c6 85 ?? ?? ?? ?? 69 c6 85 ?? ?? ?? ?? 2f c6 85 ?? ?? ?? ?? 76 c6 85 ?? ?? ?? ?? 33 c6 85 ?? ?? ?? ?? 2f c6 85 ?? ?? ?? ?? 66 c6 85 ?? ?? ?? ?? 69 c6 85 ?? ?? ?? ?? 6c c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 2f c6 85}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 8b 85 c8 00 00 00 48 8b 55 28 48 8b 4d 08 e8 ?? ?? ?? ?? b9 b8 0b 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

