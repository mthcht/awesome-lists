rule VirTool_Win64_Ciphesez_A_2147894337_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Ciphesez.A!MTB"
        threat_id = "2147894337"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Ciphesez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 89 74 24 10 89 44 24 0c c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 89 1c 24 e8 ?? ?? ?? ?? 83 ec 1c 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 85 ec ef ff ff c7 44 24 10 00 00 00 00 89 74 24 04 89 1c 24 83 c0 01 89 44 24 0c 8b 85 e8 ef ff ff 89 44 24 08 e8 ?? ?? ?? ?? 83 ec 14 85}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 04 00 10 00 00 89 44 24 08 89 1c 24 e8 ?? ?? ?? ?? 83 ec 0c 85 c0 0f 84 ?? ?? ?? ?? 8b 85 c0 ef ff ff 8b 95 c4 ef ff ff c1 e8 02 89 95 c8 ef ff ff 85}  //weight: 1, accuracy: Low
        $x_1_4 = {83 ec 1c 8b 44 24 20 c7 44 24 04 00 00 00 00 c7 04 24 ff 0f 1f 00 89 44 24 08 e8 ?? ?? ?? ?? 31 d2 83 ec 0c 85}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 44 24 0c 00 80 00 00 c7 44 24 08 00 00 00 00 89 74 24 04 89 1c 24 e8 ?? ?? ?? ?? 83 ec 10 89 1c 24 e8 ?? ?? ?? ?? 50 c7 44 24 08 2e 00 00 00 c7 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

