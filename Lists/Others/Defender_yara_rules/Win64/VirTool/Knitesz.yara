rule VirTool_Win64_Knitesz_A_2147977022_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Knitesz.A"
        threat_id = "2147977022"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Knitesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d9 31 d2 4d 89 f8 41 b9 00 30 00 00 ff ?? ?? ?? ?? ?? 48 89 45 b8 48 85 c0 ?? ?? ?? ?? ?? ?? 4c 8b 75 f8 48 c7 44 24 20 00 00 00 00 48 89 d9 48 89 c2 4d 89 f0 4d 89 f9 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 18 [0-17] e8 ?? ?? ?? ?? ?? 4c 8b 4d b8 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 48 89 d9 31 d2 45 31 c0 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

