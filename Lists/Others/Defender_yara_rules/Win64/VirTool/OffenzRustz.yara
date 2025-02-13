rule VirTool_Win64_OffenzRustz_A_2147838741_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/OffenzRustz.A!MTB"
        threat_id = "2147838741"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "OffenzRustz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 78 48 8b 44 24 78 4c 8b 8c 24 88 00 00 00 4c 8b 84 24 80 00 00 00 48 8b 94 24 a8 00 00 00 48 8b 8c 24 c8 00 00 00 48 89 44 24 20 e8}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 44 24 40 48 8b 44 24 40 4c 8b 94 24 a8 00 00 00 48 8b 54 24 50 48 8b 8c 24 c8 00 00 00 4c 8b 8c 24 d8 00 00 00 45 31 c0 45 31 db 4c 89 54 24 20 c7 44 24 28 00 00 00 00 48 89 44 24 30 e8}  //weight: 1, accuracy: High
        $x_1_3 = {48 c7 85 58 05 00 00 fe ff ff ff 4c 89 85 d0 00 00 00 48 89 95 d8 00 00 00 48 89 8d e0 00 00 00 48 89 8d e8 00 00 00 48 89 95 a8 04 00 00 4c 89 85 b0 04 00 00 c6 85 a7 04 00 00 00 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f 57 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 85 e0 00 00 00 48 8b 8d e8 00 00 00 48 89 8d b8 34 00 00 48 89 85 c0 34 00 00 48 8d ?? ?? ?? ?? ?? 48 89 e0 48 89 48 28 48 c7 40 30 01 00 00 00 48 c7 40 20 01 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 41 b8 02 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_OffenzRustz_B_2147839557_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/OffenzRustz.B!MTB"
        threat_id = "2147839557"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "OffenzRustz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 45 00 48 89 55 f8 48 89 4d e8 48 89 4d f0 48 89 95 58 02 00 00 4c 89 85 60 02 00 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? 41 b8 03 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b 45 c0 48 8b 55 c8 48 8d ?? ?? e8 ?? ?? ?? ?? eb 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b 45 f8 4c 8b 4d 00 48 8b 45 30 48 89 45 60 0f 10 45 20 0f 29 45 50 48 8d ?? ?? 48 89 4d 08}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 e0 48 89 48 20 4c 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 41 b9 0f 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

