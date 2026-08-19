rule VirTool_Win64_Hijetesz_A_2147976423_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hijetesz.A"
        threat_id = "2147976423"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hijetesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 40 e8 ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b 00 41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b ?? ?? ?? ?? ?? ff ?? 48 89 45 f8 48 83 7d f8 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 08 48 8b ?? ?? ?? ?? ?? 48 8b 45 f8 49 89 c8 48 89 c1 e8 ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b 10 ?? ?? ?? ?? 48 8b 45 f8 49 89 c9 41 b8 20 00 00 00 48 89 c1 48 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 d8 48 8b 45 18 89 10 8b 45 d8 41 89 c0 ba 00 00 00 00 b9 ff ff 1f 00 48 8b ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

