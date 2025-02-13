rule VirTool_Win64_Meteremulaprz_A_2147844677_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Meteremulaprz.A!MTB"
        threat_id = "2147844677"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Meteremulaprz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 81 ec 78 01 00 00 48 c7 84 24 58 01 00 00 00 00 00 00 48 c7 84 24 68 01 00 00 00 00 00 00 c7 84 24 60 01 00 00 00 00 00 00 e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 38 48 c7 44 24 28 00 00 00 00 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 44 24 28}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 84 24 50 01 00 00 4c 8d ?? ?? ?? ?? ?? ?? 41 b8 20 00 00 00 8b d0 48 8b 8c 24 58 01 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 84 24 58 01 00 00 8b 84 24 50 01 00 00 44 8b c0 48 8d 54 24 30 48 8b 8c 24 58 01 00 00 e8}  //weight: 1, accuracy: High
        $x_1_5 = {48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 45 33 c9 4c 8b 84 24 58 01 00 00 33 d2 33 c9 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

