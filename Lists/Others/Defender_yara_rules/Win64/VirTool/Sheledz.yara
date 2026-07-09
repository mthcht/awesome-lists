rule VirTool_Win64_Sheledz_A_2147973213_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sheledz.A"
        threat_id = "2147973213"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sheledz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 53 48 81 ec ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 8d f0 01 00 00 ba 02 00 00 00 b9 04 00 00 00 e8 ?? ?? ?? ?? 89 c1 [0-17] 41 89 c8 48 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 f8 83 e0 07 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 0f b6 04 02 88 45 f7 48 8b 55 f8 48 8b 45 28 48 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 c1 e8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

