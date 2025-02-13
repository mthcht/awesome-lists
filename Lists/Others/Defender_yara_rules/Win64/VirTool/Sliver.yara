rule VirTool_Win64_Sliver_A_2147842382_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sliver.A!MTB"
        threat_id = "2147842382"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 6c 24 30 48 8d ?? ?? ?? 48 8b 44 24 48 48 89 04 24 48 8b 44 24 40 48 89 44 24 08 e8 ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 04 24 48 c7 44 24 08 00 00 00 00 48 8b 44 24 40 48 89 44 24 10 48 c7 44 24 18 00 30 00 00 48 c7 44 24 20 04 00 00 00 e8 ?? ?? ?? ?? 48 8b 44 24 28 48 89 44 24 50 48 8b 6c 24 30 48 83 c4}  //weight: 1, accuracy: Low
        $x_1_2 = {65 48 8b 0c 25 28 00 00 00 48 8b 89 00 00 00 00 48 3b 61 10 0f ?? ?? ?? ?? ?? 48 83 ec 28 48 89 6c 24 20 48 8d ?? ?? ?? 48 8b 4c 24 40 48 8d ?? ?? 48 39 c1 76 43 48 8b 44 24 38 0f b6 4c 01 ff 84 c9 75 3a 48 8b ?? ?? ?? ?? ?? 48 89 0c 24 48 8b 4c 24 30 48 89 4c 24 08 48 89 44 24 10 66 ?? e8 ?? ?? ?? ?? 48 8b 44 24 18 48 89 44 24 50 48 8b 6c 24 20 48 83 c4 28 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {48 83 ec 48 48 89 6c 24 40 48 8d ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 84 00 48 8b ?? ?? ?? ?? ?? 48 8b 4c 24 50 48 8b ?? ?? ?? ?? ?? 48 89 04 24 0f 57 c0 0f 11 44 24 08 48 89 54 24 18 48 89 4c 24 20 0f 11 44 24 28 e8 ?? ?? ?? ?? 48 8b 44 24 38 48 85 c0 74 1f 48 8b ?? ?? ?? ?? ?? 48 89 0c 24 48 89 44 24 08 e8 ?? ?? ?? ?? 48 8b 6c 24 40 48 83 c4 48 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {65 48 8b 04 25 28 00 00 00 48 8b 80 00 00 00 00 48 8b 40 30 48 8b ?? ?? ?? ?? ?? 48 8b 80 38 03 00 00 48 89 0c 24 48 89 44 24 08 b8 ff ff ff ff 48 89 44 24 10 e8 ?? ?? ?? ?? 48 8b 44 24 18 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Sliver_JZ_2147904604_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sliver.JZ!MTB"
        threat_id = "2147904604"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b 04 02 83 c1 ?? 0b 53 ?? 49 83 c2 ?? 03 53 ?? 44 0f af 83 ?? ?? ?? ?? 03 ca 8b 83 ?? ?? ?? ?? 2b 43 ?? 2d ?? ?? ?? ?? 89 4b ?? 31 43 ?? 48 63 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {44 88 04 01 8b 43 ?? ff 83 ?? ?? ?? ?? 83 f0 ?? 01 43 ?? 49 81 fa ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

