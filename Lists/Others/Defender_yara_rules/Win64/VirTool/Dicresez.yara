rule VirTool_Win64_Dicresez_A_2147846431_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dicresez.A!MTB"
        threat_id = "2147846431"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dicresez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 9c 24 f0 08 00 00 e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 0d 81 23 00 00 33 d2 0f 10 05 58 23 00 00 89 8d d0 03 00 00 41 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 d0 07 00 00 ff 15 ?? ?? ?? ?? 33 d2 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 4c 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 e8 03 00 00 ff 15 ?? ?? ?? ?? 41 b8 01 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b 9c 24 f0 08 00 00 48 8d ?? ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {33 d2 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 e2 ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

