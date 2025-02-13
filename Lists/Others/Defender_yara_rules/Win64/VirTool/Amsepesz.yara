rule VirTool_Win64_Amsepesz_A_2147916125_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Amsepesz.A!MTB"
        threat_id = "2147916125"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Amsepesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e0 61 00 6d 00 ?? ?? ?? ?? 66 89 45 f0 c7 45 e4 73 00 69 00 c7 45 e8 2e 00 64 00 c7 45 ec 6c 00 6c 00 ?? ?? ?? ?? ?? ?? 48 85 c0 ?? ?? 45 33 c9 [0-20] 33 c9 [0-21] 48 89 5c 24 60 48 8b c8 c7 45 d0 41 6d 73 69 c7 45 d4 53 63 61 6e c7 45 d8 42 75 66 66 66 c7 45 dc 65 72 c6 45 de 00 ?? ?? ?? ?? ?? ?? 48 8b d8 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {45 8b 07 41 8b d5 b9 58 00 00 00 ?? ?? ?? ?? ?? ?? 4c 8b e0 ?? ?? ?? ?? ?? 48 8b c8 ?? ?? ?? ?? ?? ?? 48 8b 44 24 28 48 89 45 b8 48 8b 4d e0 48 81 e1 ff ff fc ff 48 83 c9 01 48 89 4d e0 c7 45 a0 10 00 10 00 ?? ?? ?? ?? ?? 49 8b cc ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 01 81 38 ?? ?? ?? ?? ?? ?? 4c 8b 41 08 49 8b 80 98 00 00 00 48 8b 10 49 89 ?? f8 00 00 00 48 8b 41 08 b9 57 00 07 80 48 89 48 78 b8 ff ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

