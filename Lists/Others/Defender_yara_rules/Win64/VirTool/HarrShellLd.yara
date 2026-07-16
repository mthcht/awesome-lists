rule VirTool_Win64_HarrShellLd_A_2147973477_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/HarrShellLd.A"
        threat_id = "2147973477"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "HarrShellLd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 31 c9 45 31 c0 31 d2 48 89 44 24 28 48 8b 4c 24 48 48 89 ?? 24 20}  //weight: 1, accuracy: Low
        $x_1_2 = {45 31 c9 4c 8b 44 24 40 48 8b 4c 24 38 48 89 44 24 20 ba 10 66 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

