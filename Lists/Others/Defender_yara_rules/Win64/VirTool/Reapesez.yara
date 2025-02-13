rule VirTool_Win64_Reapesez_A_2147892465_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Reapesez.A!MTB"
        threat_id = "2147892465"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Reapesez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 7c 24 60 48 8d 84 ?? ?? ?? ?? ?? 4c 89 7c 24 58 4c 8d ?? ?? ?? ?? ?? 4c 89 7c 24 50 48 8d ?? ?? ?? ?? ?? 4c 89 7c 24 48 41 b9 ff 01 0f 00 4c 89 7c 24 40 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c9 4c 89 7c 24 30 44 89 7c 24 28 48 8d ?? ?? ?? ?? ?? ba 00 00 00 40 c7 44 24 20 03 00 00 00 45 ?? ?? ?? ff 15 ?? ?? ?? ?? 48 83}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 28 08 00 00 00 4c ?? ?? ?? ?? 48 89 4c 24 20 ba df 20 99 99 48 8b c8 4c 89 74 24 78 44 89 bc 24 80 00 00 00 ff 15 ?? ?? ?? ?? 3b c7 ?? ?? 48 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {45 33 c0 33 d2 48 8b cd ff 15 ?? ?? ?? ?? 3d 20 04 00 00 ?? ?? 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

