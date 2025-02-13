rule VirTool_Win64_Dumplesesz_A_2147894336_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dumplesesz.A!MTB"
        threat_id = "2147894336"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dumplesesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b cb ff 15 ?? ?? ?? ?? 45 33 c0 4c ?? ?? ?? ?? 41 ?? ?? ?? 8d ?? ?? ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? b9 01 00 00 00 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 44 8b c7 33 d2 b9 10 10 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 74 24 48 48 89 4c 24 40 41 b9 02 00 00 00 48 ?? ?? ?? ?? 45 33 c0 48 89 4c 24 30 8b d7 48 89 74 24 28 48 8b c8 48 89 74 24 20 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 48 8b 15 94 43 00 00 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 74 24 30 48 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 28 80 00 00 00 45 33 c9 45 33 c0 c7 44 24 20 02 00 00 00 ba 00 00 00 10 ff 15 ?? ?? ?? ?? 44 8b 05 4c 43 00 00 4c ?? ?? ?? ?? 48 8b 15 48 43 00 00 48 8b c8 48 89 74 24 20 ff 15 ?? ?? ?? ?? 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

