rule VirTool_Win64_PipImpos_A_2147788330_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/PipImpos.A!MTB"
        threat_id = "2147788330"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PipImpos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 70 4c 8d ?? ?? ?? 48 8b 4c 24 60 45 33 ff 4c 89 7c 24 28 33 d2 c7 44 24 78 01 00 00 00 48 89 44 24 7c 45 8d ?? ?? c7 84 24 84 00 00 00 02 00 00 00 4c 89 7c 24 20 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b9 81 00 06 00 48 8d ?? ?? ?? ?? ?? 45 33 c0 33 d2 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 75 14 ff 15 ?? ?? ?? ?? 8b d0}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b8 00 02 00 00 48 8b e8 e8 ?? ?? ?? ?? 48 8d ?? ?? ?? 41 b9 00 01 00 00 4c 8d ?? ?? ?? ?? ?? 48 89 44 24 20 41 8d ?? ?? 48 8b cd ff 15 ?? ?? ?? ?? 33 d2 48 8d ?? ?? ?? ?? ?? 41 b8 00 00 06 00 ff 15 ?? ?? ?? ?? 48 8b c8 4c 8b f0 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 74 24 20 41 b8 ff 00 00 00 48 8d ?? ?? ?? ?? ?? ?? 48 8b cb ff 15 ?? ?? ?? ?? 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 75 20 ff 15 ?? ?? ?? ?? 44 8b 44 24 60}  //weight: 1, accuracy: Low
        $x_1_5 = {33 c0 33 c9 0f a2 44 8b c1 45 33 db 44 8b cb 41 81 f0 6e 74 65 6c 41 81 f1 47 65 6e 75 44 8b d2 8b f0 33 c9 41 8d ?? ?? 45 0b c8 0f a2 41 81 f2}  //weight: 1, accuracy: Low
        $x_1_6 = {48 8b 45 18 48 89 45 10 ff 15 ?? ?? ?? ?? 8b c0 48 31 45 10 ff 15 ?? ?? ?? ?? 8b c0 48 8d ?? ?? 48 31 45 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

