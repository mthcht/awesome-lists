rule VirTool_Win64_Vepesz_A_2147965882_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Vepesz.A"
        threat_id = "2147965882"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Vepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 e9 41 89 d8 e8 ?? ?? ?? ?? 85 c0 [0-36] 41 89 d8 41 83 e8 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 f8 ff ?? ?? 89 c3 41 c6 04 1c 00 83 fb 04 ?? ?? 41 81 3c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {89 18 4c 89 e9 ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 04 00 00 00 e8 ?? ?? ?? ?? 85 c0 ?? ?? 4c 89 e9 ?? ?? ?? ?? ?? ?? ?? ?? 41 89 d8 e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

