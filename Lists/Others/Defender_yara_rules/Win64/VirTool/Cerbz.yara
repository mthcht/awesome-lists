rule VirTool_Win64_Cerbz_A_2147844663_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cerbz.A!MTB"
        threat_id = "2147844663"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cerbz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 28 48 8d ?? ?? ?? ?? ?? 48 89 44 24 20 44 8b 8d f8 00 00 00 4c 8b 85 18 01 00 00 48 8d ?? ?? ?? ?? ?? 48 8b 8d b8 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 58 c7 45 74 ff ff ff ff 48 c7 85 98 00 00 00 00 00 00 00 48 c7 85 b8 00 00 00 ff ff ff ff b8 18 00 00 00 48 6b c0 00 48 8b 4d 10}  //weight: 1, accuracy: High
        $x_1_3 = {b8 18 00 00 00 48 6b c0 00 48 8b 4d 10 48 03 c8 48 8b c1 4c 8d ?? ?? ?? ?? ?? ba 06 00 00 00 48 8b c8 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 44 24 30 48 8d ?? ?? ?? ?? ?? 48 89 44 24 28 48 8b 85 b8 00 00 00 48 89 44 24 20 4c 8b 8d 98 00 00 00 41 b8 08 00 00 00 8b 55 74 48 8b 8d a8 01 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

