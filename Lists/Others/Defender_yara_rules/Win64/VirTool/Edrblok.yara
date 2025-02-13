rule VirTool_Win64_Edrblok_C_2147926577_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Edrblok.C"
        threat_id = "2147926577"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Edrblok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d1 57 8d c3 ?? ?? ?? ?? a7 05 ?? ?? ?? ?? 33 4c ?? ?? 90 4f 7f bc ee e6 0e 82}  //weight: 1, accuracy: Low
        $x_1_2 = {87 1e 8e d7 ?? ?? ?? ?? 44 86 ?? ?? ?? ?? a5 4e ?? ?? 94 37 d8 09 ec ef c9 71}  //weight: 1, accuracy: Low
        $x_1_3 = {3b 39 72 4a ?? ?? ?? ?? 9f 31 ?? ?? ?? ?? bc 44 ?? ?? 84 c3 ba 54 dc b3 b6 b4}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 00 00 00 00 b9 41 00 00 00 48 89 d7 f3 48 ab c7 85 2c 03 00 00 04 01 00 00 66 0f ef c0 0f 11 45 b0 0f 11 45 c0 66 0f d6 45 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

