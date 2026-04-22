rule VirTool_Win64_Refledesz_A_2147967496_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Refledesz.A"
        threat_id = "2147967496"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Refledesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f9 4c 89 fa 4d 89 e0 e8 ?? ?? ?? ?? a8 01 ?? ?? ?? ?? ?? ?? 48 89 d3 e8 ?? ?? ?? ?? c6 85 d0 04 00 00 c3 48 c7 85 68 02 00 00 00 00 00 00 8b 0d ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 54 24 30 89 4c 24 28}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 f1 49 89 f9 e8 [0-17] 48 89 44 24 20 [0-18] 41 b8 07 00 00 00 48 89 f1 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 44 24 20 [0-24] ba 17 00 00 00 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 8d e8 05 00 00 ff [0-18] 48 89 85 d0 05 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 85 d8 05 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

