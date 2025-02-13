rule VirTool_Win64_Dilenesz_A_2147890409_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dilenesz.A!MTB"
        threat_id = "2147890409"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dilenesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b f4 ff 15 ?? ?? ?? ?? 48 8b f8 48 85 c0 74 77 48 8d ?? ?? ?? ?? ?? 48 8b c8 ff 15 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8b cf 48 8b d8 ff 15 ?? ?? ?? ?? 4c ?? ?? ?? ?? 45 33 c0 48 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 89 32 4d 8b c5 4c 89 64 24 20 48 8b d3 48 8b cf ff 15 ?? ?? ?? ?? 48 8b d3 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 41 b9 14 01 00 00 4c 89 64 24 20 4c 8d ?? ?? ?? ?? ?? 48 8b cf 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 20 00 00 00 4c 89 64 24 58 48 89 5c 24 50 48 89 74 24 48 e8 c9}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b f8 e8 ?? ?? ?? ?? 48 8b d6 48 8b cf e8 ?? ?? ?? ?? 33 d2 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 41 b8 4a 01 00 00 48 8b cf ff 15 ?? ?? ?? ?? 48 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 85 94 00 00 00 49 8b d6 89 05 2b 07 02 00 48 89 1d 11 07 02 00 4c 89 64 24 20 48 8b cf ff 15 ?? ?? ?? ?? 49 8b d6 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Dilenesz_B_2147894338_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dilenesz.B!MTB"
        threat_id = "2147894338"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dilenesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 7c 24 30 48 8d ?? ?? ?? ?? ?? 33 c9 ff ?? 48 8b 44 24 30 0f 57 c0 0f 57 c9 44 8b c3 33 d2 b9 ff ff 1f 00 48 8b 30 33 c0 48 89 44 24 50 48 89 44 24 70 4c 89 7c 24 38 0f 11 44 24 40 0f 11 4c 24 60 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 20 40 00 00 00 48 8b c8 45 ?? ?? ?? 41 b9 00 10 00 00 48 8b d8 ff 15 ?? ?? ?? ?? 33 d2 c7 44 24 20 40 00 00 00 41 b9 00 10 00 00 41 b8 20 01 00 00 48 8b cb 48 8b e8 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b9 20 01 00 00 48 89 35 89 3f 00 00 4c 8d ?? ?? ?? ?? ?? 4c 89 35 8c 3f 00 00 49 8b d6 4c 89 7c 24 20 48 8b cb ff 15 ?? ?? ?? ?? 45 ?? ?? ?? 4c 89 7c 24 20 4c 8d ?? ?? ?? ?? ?? 48 8b d5 48 8b cb ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

