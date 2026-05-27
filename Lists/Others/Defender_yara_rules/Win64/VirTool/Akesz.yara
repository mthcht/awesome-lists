rule VirTool_Win64_Akesz_A_2147970302_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Akesz.A"
        threat_id = "2147970302"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Akesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 00 48 89 94 24 60 01 00 00 48 89 94 24 68 01 00 00 48 8b 94 24 c8 00 00 00 4c 89 44 24 30 45 31 c0 c7 84 24 44 01 00 00 01 01 00 00 48 89 44 24 38 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 ff}  //weight: 1, accuracy: High
        $x_1_2 = {41 57 41 56 41 55 41 54 55 57 56 53 48 81 ec 48 08 00 00 48 89 8c 24 ?? 08 00 00 [0-21] 48 89 94 24 98 08 00 00 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 4c 89 f9 48 89 c2 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

