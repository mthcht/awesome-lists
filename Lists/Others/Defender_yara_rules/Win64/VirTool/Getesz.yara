rule VirTool_Win64_Getesz_A_2147961816_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Getesz.A"
        threat_id = "2147961816"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Getesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 84 24 30 01 00 00 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 84 24 38 01 00 00 48 8b 84 24 50 01 00 00 bb 00 00 00 02 31 c9 bf 02 00 00 00 be 01 00 00 00 ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 44 24 70 48 8b 8c 24 40 01 00 00 48 8b 5c 24 30 ?? ?? e8 ?? ?? ?? ?? 8b 44 24 38 e8 ?? ?? ?? ?? 48 c7 44 24 28 00 00 00 00 bb 0a 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 4c 24 28 48 89 c3 48 89 c8 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? 48 8b 44 24 70 48 8b 8c 24 40 01 00 00 48 8b 5c 24 30 [0-18] 48 89 94 24 88 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

