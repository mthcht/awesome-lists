rule VirTool_Win64_Voledesz_A_2147982443_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Voledesz.A"
        threat_id = "2147982443"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Voledesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 85 e0 01 00 00 41 b9 40 00 00 00 41 b8 00 10 00 00 48 89 c2 b9 00 00 00 00 48 8b ?? ?? ?? ?? ?? ff ?? 48 89 85 d8 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c2 48 8b 8d e0 01 00 00 48 8b 85 d8 01 00 00 49 89 c8 48 89 c1 e8}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 85 d8 01 00 00 ff ?? 48 8b 85 d8 01 00 00 41 b8 00 80 00 00 ba 00 00 00 00 48 89 c1 48 8b ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

