rule VirTool_Win64_Delepesz_A_2147980262_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Delepesz.A"
        threat_id = "2147980262"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Delepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 00 48 89 c1 e8 ?? ?? ?? ?? 89 85 34 01 00 00 8b 85 34 01 00 00 ?? ?? ?? ?? ?? ?? ?? 89 c2 e8 ?? ?? ?? ?? 8b 85 34 01 00 00 41 89 c0 ba 00 00 00 00 b9 ff ff 1f 00 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c0 48 89 c1 e8 ?? ?? ?? ?? 48 89 85 20 01 00 00 8b 95 f0 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 85 20 01 00 00 49 89 c9 41 89 d0 48 89 c2 b9 10 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 01 00 00 00 ?? ?? ?? ?? ?? 48 8b 95 e8 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 85 28 01 00 00 48 c7 44 24 20 00 00 00 00 41 b9 48 00 00 00 49 89 c8 48 89 c1 48 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

