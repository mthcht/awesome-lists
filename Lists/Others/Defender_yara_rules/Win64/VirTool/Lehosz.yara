rule VirTool_Win64_Lehosz_A_2147959641_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Lehosz.A"
        threat_id = "2147959641"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Lehosz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 44 24 38 00 00 00 00 [0-19] e8 [0-17] 48 89 44 24 40 c7 44 24 30 00 00 00 00 48 8b 4c 24 40 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 4c 24 28 48 c7 44 24 20 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 44 8b c0 48 8b 54 24 40 48 8b 4c 24 38 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {44 89 4c 24 20 4c 89 44 24 18 48 89 54 24 10 48 89 4c 24 08 48 83 ec ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4c 24 58 89 4c 24 20 [0-20] 48 8b 54 24 40 48 8b c8 e8 ?? ?? ?? ?? 48 83 c4}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 89 4c 24 20 44 89 44 24 18 48 89 54 24 10 48 89 4c 24 08 48 83 ec ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 8c 24 88 00 00 00 48 89 4c 24 30 48 8b 8c 24 80 00 00 00 48 89 4c 24 28 48 8b 4c 24 78 48 89 4c 24 20 44 8b 4c 24 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

