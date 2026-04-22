rule VirTool_Win32_Revesez_A_2147967494_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Revesez.A"
        threat_id = "2147967494"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Revesez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 ?? ?? ?? ?? ?? 8b 05 08 83 d8 00 85 c0 ?? ?? ?? ?? ?? ?? 8b 05 38 83 d8 00 8b 0d 34 83 d8 00 85 c0 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 04 00 00 00 00 c7 44 24 08 02 00 00 00 ?? ?? ?? ?? ?? ?? ?? 89 44 24 0c e8 ?? ?? ?? ?? 8b 05 dc 82 d8 00 89 c1 b8 ?? ?? ?? ?? f7 e1 89 04 24 c1 f9 1f 69 c1 ?? ?? ?? ?? 01 d0 89 44 24 04 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4c 24 08 ?? ?? ?? ?? ?? ?? 89 94 24 24 01 00 00 89 8c 24 28 01 00 00 ?? ?? ?? ?? ?? ?? ?? 31 c0 e8 [0-16] 89 8c 24 80 01 00 00 c7 84 24 88 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

