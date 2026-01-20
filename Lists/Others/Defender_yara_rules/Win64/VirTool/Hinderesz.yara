rule VirTool_Win64_Hinderesz_A_2147961360_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hinderesz.A"
        threat_id = "2147961360"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hinderesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b fa 44 8b f1 33 f6 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 8b d8 48 85 c0 [0-19] 48 8b c8 ff ?? ?? ?? ?? ?? 48 89 05 30 48 04 00 ?? ?? ?? ?? ?? ?? ?? 48 8b cb ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 85 c0 ?? ?? ?? ?? ?? ?? 0f 57 c0 0f 11 85 88 00 00 00 48 89 b5 98 00 00 00 48 89 b5 a0 00 00 00 41 b8 16 00 00 00 [0-20] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

