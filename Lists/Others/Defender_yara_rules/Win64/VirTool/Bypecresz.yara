rule VirTool_Win64_Bypecresz_A_2147961812_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bypecresz.A"
        threat_id = "2147961812"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bypecresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 4c 24 54 4c 8b 44 24 68 48 8b 54 24 78 ?? ?? ?? ?? ?? ?? ?? e8 [0-18] 48 39 84 24 00 03 00 00 ?? ?? ?? ?? ?? ?? c7 44 24 60 01 00 00 00 c7 44 24 64 00 00 00 00 44 8b 44 24 60 48 8b 54 24 70 48 8b 4c 24 58 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 48 81 ec e8 02 00 00 48 8b ?? ?? ?? ?? ?? 48 33 c4 48 89 84 24 d0 02 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 84 24 98 00 00 00 [0-21] 48 8b f8 48 8b f1 b9 48 00 00 00 f3 a4}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b f8 33 c0 b9 c0 01 00 00 f3 aa ?? ?? ?? ?? ?? ?? ?? 48 89 84 24 ?? 00 00 00 e8 ?? ?? ?? ?? 88 44 24 32 0f b6 84 24 08 03 00 00 85 c0 ?? ?? 0f b6 44 24 32 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

