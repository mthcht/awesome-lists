rule VirTool_Win64_Cofflodesz_A_2147914832_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cofflodesz.A!MTB"
        threat_id = "2147914832"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cofflodesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 d0 00 00 00 48 63 d0 48 89 d0 48 c1 e0 02 48 01 d0 48 c1 e0 03 ?? ?? ?? ?? 48 8b 85 08 01 00 00 48 01 d0 48 89 85 b0 00 00 00 48 8b 85 b0 00 00 00 8b 40 10 89 c0 41 b9 40 00 00 00 41 b8 00 30 10 00 48 89 c2 b9 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d e0 44 8b 45 d8 48 8b 45 18 48 83 c0 08 48 8b 00 4c 8b 4d f0 48 8b 55 f8 89 4c 24 20 48 89 c1 ?? ?? ?? ?? ?? 89 45 e4 83 7d e4 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {89 85 a4 00 00 00 48 8b 85 b8 00 00 00 8b 40 0c 89 c2 48 89 d0 48 c1 e0 03 48 01 d0 48 01 c0 48 89 c2 48 8b 85 a8 00 00 00 48 01 c2 8b 85 a4 00 00 00 48 01 d0 48 89 c1 ?? ?? ?? ?? ?? 48 89 85 80 00 00 00 48 8b 85 80 00 00 00 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 85 d8 00 00 00 0f b7 40 08 66 83 f8 04 ?? ?? ?? ?? ?? ?? 48 8b 85 80 00 00 00 48 85 c0 ?? ?? ?? ?? ?? ?? 8b 85 c4 00 00 00 c1 e0 03 48 63 d0 48 8b 85 ?? 00 00 00 48 01 c2 8b 85 d0 00 00 00 48 98 48 8b 4c c5 a0 48 8b 85 d8 00 00 00 8b 00 89 c0 48 83 c0 04 48 01 c8 48 29 c2 b8 ff ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

