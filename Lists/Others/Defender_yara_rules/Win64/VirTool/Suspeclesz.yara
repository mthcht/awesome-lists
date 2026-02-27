rule VirTool_Win64_Suspeclesz_A_2147963656_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Suspeclesz.A"
        threat_id = "2147963656"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Suspeclesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 54 24 20 31 c9 48 89 44 24 48 [0-19] 48 89 44 24 40 31 c0 c7 44 24 64 04 00 00 00 48 89 44 24 38 48 89 44 24 30 c7 44 24 28 04 00 00 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 70 48 89 d9 48 89 6c 24 20 ?? ?? ?? ?? ?? ?? ?? ?? 41 b9 40 00 00 00 48 01 f2 ff ?? 44 8b 84 24 3c 01 00 00 [0-24] 49 83 c6 02 ?? ?? ?? ?? ?? 48 89 d9 31 d2 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

