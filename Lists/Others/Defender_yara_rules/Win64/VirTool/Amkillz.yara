rule VirTool_Win64_Amkillz_A_2147844671_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Amkillz.A!MTB"
        threat_id = "2147844671"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Amkillz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 12 48 c6 45 13 3f c6 45 14 3f c6 45 15 3f c6 45 16 3f c6 45 17 74 c6 45 18 33 c7 45 34 11 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 85 b8 00 00 00 48 89 44 24 20 44 8b 4d 34 4c 8d ?? ?? ba 00 04 00 00 48 8d ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 04 48 8b 8d 20 01 00 00 0f b6 04 01 b9 01 00 00 00 48 6b c9 00 48 8b 95 30 01 00 00 0f b6 0c 0a 3b c1}  //weight: 1, accuracy: High
        $x_1_4 = {48 c7 44 24 20 00 00 00 00 41 b9 01 00 00 00 4c 8d ?? ?? ?? ?? ?? 48 8b 95 18 05 00 00 48 8b 4d 78 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Amkillz_B_2147919851_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Amkillz.B!MTB"
        threat_id = "2147919851"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Amkillz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8c 24 a8 07 00 00 48 8b 05 e7 33 11 00 48 33 c5 48 89 85 48 07 00 00 [0-18] c6 45 08 48 c6 45 09 3f c6 45 0a 3f c6 45 0b 74 c6 45 0c 3f c6 45 0d 48 c6 45 0e 3f c6 45 0f 3f c6 45 10 74 c7 45 34 09 00 00 00 83 bd 70 07 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b 85 70 07 00 00 33 d2 b9 38 00 00 00 ?? ?? ?? ?? ?? ?? 48 89 45 58 48 83 7d 58 00 ?? ?? b8 ff ff ff ff [0-24] 48 89 45 78 48 83 7d 78 00 ?? ?? b8 ff ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 4d 78 ?? ?? ?? ?? ?? ?? 48 89 85 98 00 00 00 48 83 bd 98 00 00 00 00 ?? ?? b8 ff ff ff ff ?? ?? ?? ?? ?? 48 c7 44 24 20 00 00 00 00 41 b9 00 04 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 95 98 00 00 00 48 8b 4d 58 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 85 98 00 00 00 48 89 85 f8 04 00 00 48 63 85 d4 04 00 00 48 8b 8d f8 04 00 00 48 03 c8 48 8b c1 48 89 85 f8 04 00 00 48 c7 44 24 20 00 00 00 00 41 b9 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 95 f8 04 00 00 48 8b 4d 58 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 ff ff ff ff ?? ?? ?? ?? ?? 44 8b 4d 34 ?? ?? ?? ?? ba 00 04 00 00 [0-18] 89 85 d4 04 00 00 81 bd d4 04 00 00 00 04 00 00 ?? ?? b8 ?? 00 00 00 ?? ?? ?? ?? ?? 83 3d 97 32 11 00 00 ?? ?? 48 8b 95 98 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

