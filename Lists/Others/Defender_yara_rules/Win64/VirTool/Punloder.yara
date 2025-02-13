rule VirTool_Win64_Punloder_A_2147823371_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Punloder.A"
        threat_id = "2147823371"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Punloder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 8b ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 63 85 84 00 00 00 48 3d 4f 01 00 00 ?? ?? 48 63 85 84 00 00 00 48 8d ?? ?? ?? ?? ?? 0f be 04 01 35 c4 00 00 00 88 85 a4 00 00 00 48 63 45 44 48 8b ?? ?? ?? ?? ?? 48 03 c8 48 8b c1 48 c7 44 24 20 00 00 00 00 41 b9 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 20 00 00 00 c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 33 d2 48 8d ?? ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

