rule VirTool_Win64_Injeshimesz_A_2147919104_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injeshimesz.A!MTB"
        threat_id = "2147919104"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injeshimesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 0f b6 d6 48 8b cb ?? ?? ?? ?? ?? 48 8b cb ?? ?? ?? ?? ?? 0f 57 c0 0f 11 45 d8 0f 11 45 e8 0f 11 45 f8 c7 45 d8 30 00 00 00 4c 89 74 24 58 c6 44 24 20 00 45 33 c9 ?? ?? ?? ?? ba 03 00 1f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b cb 48 83 3d 9f a1 04 00 07 48 0f 47 0d 7f a1 04 00 ?? ?? ?? ?? ?? 48 89 44 24 38 44 89 74 24 30 44 89 74 24 28 44 89 74 24 20 ba 03 00 00 00 [0-20] 48 8b f8 48 83 f8 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {84 c0 0f 84 [0-35] 48 8b c8 [0-54] 48 83 3d 25 79 04 00 07 48 0f 47 15 05 79 04 00 4c 8b 05 0e 79 04 00 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b d8 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 85 db [0-70] 48 8b c8 ?? ?? ?? ?? ?? 4c 89 74 24 28 44 89 74 24 20 45 33 c9 ?? ?? ?? ?? ?? ?? ?? 33 d2 33 c9 ?? ?? ?? ?? ?? ?? 48 8b f8 48 8b ce}  //weight: 1, accuracy: Low
        $x_1_5 = {48 89 44 24 40 ?? ?? ?? ?? 48 89 44 24 38 4c 89 74 24 30 4c 89 74 24 28 44 89 74 24 20 45 33 c0 ?? ?? ?? ?? 48 8b 4c 24 68 [0-19] 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Injeshimesz_B_2147919106_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injeshimesz.B!MTB"
        threat_id = "2147919106"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injeshimesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 68 41 8b f0 c7 44 24 20 04 00 00 00 48 8b fa 41 b8 c0 11 00 00 33 d2 41 b9 00 30 00 00 48 8b d9 ?? ?? ?? ?? ?? ?? 48 89 44 24 30 48 85 c0 ?? ?? ?? ?? ?? ?? 41 b9 c0 11 00 00 48 c7 44 24 20 00 00 00 00 4c 8b c7 48 8b d0 48 8b cb}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b cb 85 c0 ?? ?? ?? ?? ?? ?? 0f 57 c0 48 c7 44 24 20 00 00 00 00 41 b9 30 00 00 00 ?? ?? ?? ?? ?? 33 d2 0f 11 44 24 38 0f 11 44 24 48 0f 11 44 24 58 ?? ?? ?? ?? ?? ?? 8b f8 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {66 89 5c 24 28 [0-83] 48 83 3d 93 20 04 00 07 48 0f 47 15 73 20 04 00 4c 8b 05 7c 20 04 00 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 c0 ?? ?? ?? ?? ?? ?? 48 8b f8 48 83 f8 ff ?? ?? ?? ?? ?? ?? 48 c7 44 24 20 00 00 00 00 45 33 c9 45 8b c6 48 8b d5 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_5 = {48 89 5c 24 20 56 48 83 ec 70 48 8b 05 6f 17 04 00 48 33 c4 48 89 44 24 68 ?? ?? ?? ?? ?? 48 8b d9 ?? ?? ?? ?? ?? 48 89 44 24 20 ?? ?? ?? ?? ?? 48 83 7b 18 07 4c 8b 43 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

