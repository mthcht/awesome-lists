rule VirTool_Win64_Plant_A_2147910518_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Plant.A"
        threat_id = "2147910518"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Plant"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 e8 ?? ?? ?? ?? 48 89 44 24 50 ?? ?? ?? ?? ?? 48 89 44 24 20 ?? ?? ?? ?? ?? 41 b8 01 00 00 00 33 d2 33 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 13 00 00 00 66 89 44 24 24 c7 44 24 20 00 00 00 00 eb}  //weight: 1, accuracy: High
        $x_1_3 = {48 63 44 24 20 ?? ?? ?? ?? ?? ?? ?? ?? 24 00 01 00 00 48 8b 4c c4 60 ?? ?? ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 44 24 20 44 8b 8c 24 88 00 00 00 4c 8b 84 24 10 01 00 00 48 8b 54 24 68 48 8b 8c 24 80}  //weight: 1, accuracy: High
        $x_1_5 = {88 01 48 03 ce 03 c6 3d ?? ?? 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

