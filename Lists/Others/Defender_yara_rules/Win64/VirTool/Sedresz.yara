rule VirTool_Win64_Sedresz_A_2147982450_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sedresz.A"
        threat_id = "2147982450"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sedresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 44 24 28 33 d2 b9 01 00 00 00 ff ?? ?? ?? ?? ?? 48 8b c8 33 d2 48 8b d8 ff ?? ?? ?? ?? ?? 48 8b cb ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 20 44 8b ce 4d 8b c6 ba 08 a8 07 80 49 8b cf ff ?? ?? ?? ?? ?? 8b d8 49 8b ce e8 ?? ?? ?? ?? 85 db ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 65 00 00 00 33 c9 ff ?? ?? ?? ?? ?? 48 8b d8 48 8b d0 33 c9 ff ?? ?? ?? ?? ?? 48 8b c8 ff ?? ?? ?? ?? ?? 4c 8b e8 48 8b d3 33 c9 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

