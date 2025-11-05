rule VirTool_Win64_Trampelesz_A_2147956755_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Trampelesz.A"
        threat_id = "2147956755"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Trampelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 28 ?? ?? ?? ?? ?? ?? ?? 33 ff ?? ?? ?? ?? ?? ?? 48 85 c0 [0-25] 48 8b c8 [0-19] 4c 8b c0 48 85 c0 ?? ?? 33 c9 80 38 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c1 48 c1 e8 28 88 47 07 48 8b c1 48 c1 e9 38 48 c1 e8 30 88 47 08 88 4f 09 33 c9 66 c7 47 0a 41 ff c6 47 0c e2 c7 44 24 20 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

