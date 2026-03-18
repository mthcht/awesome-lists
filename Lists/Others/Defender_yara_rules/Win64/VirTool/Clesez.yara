rule VirTool_Win64_Clesez_A_2147965080_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Clesez.A"
        threat_id = "2147965080"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Clesez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f9 e8 ?? ?? ?? ?? 83 3f 01 [0-20] 48 8b 48 10 48 89 8c 24 c0 08 00 00 f3 0f 6f 00 66 0f 7f 84 24 b0 08 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 8c 24 d8 00 00 00 48 8b 94 24 d0 00 00 00 e8 [0-18] 48 89 f1 e8 ?? ?? ?? ?? 48 8b 76 10 48 85 f6 [0-19] 48 89 84 24 68 02 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 89 e1 e8 [0-25] 41 b8 3b 00 00 00 4c 89 e9 e8 ?? ?? ?? ?? 41 c6 45 18 00 ?? ?? ?? ?? ?? ?? ?? ?? 4c 89 e2 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

