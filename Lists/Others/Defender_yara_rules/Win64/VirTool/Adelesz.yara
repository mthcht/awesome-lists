rule VirTool_Win64_Adelesz_A_2147965883_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Adelesz.A"
        threat_id = "2147965883"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Adelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 18 48 8b 40 08 48 89 45 f8 48 8b 45 f8 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 80 48 89 c1 48 8b ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 ec 41 b9 40 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b ?? ?? ?? ?? ?? ff ?? 48 89 45 e0 8b 55 ec 48 8b 45 e0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 55 f8 8b 45 ec ?? ?? ?? ?? ?? ?? ?? 49 89 d0 89 c2 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? ff ?? 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c2 b9 00 00 00 00 48 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

