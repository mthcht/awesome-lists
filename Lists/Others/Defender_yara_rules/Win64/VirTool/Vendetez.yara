rule VirTool_Win64_Vendetez_A_2147964052_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Vendetez.A"
        threat_id = "2147964052"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Vendetez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c1 48 81 fa 00 10 00 00 ?? ?? 48 83 c2 27 48 8b 49 f8 48 2b c1 48 83 e8 08 48 83 f8 1f ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 ec 38 83 fa 01 ?? ?? 33 c0 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 28 45 33 c9 33 d2 89 44 24 20 33 c9 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b f0 48 3b c3 [0-19] 48 89 44 24 40 48 c7 44 24 48 66 00 00 00 ?? ?? ?? ?? ?? b1 01 e8 ?? ?? ?? ?? 45 8b c7 33 d2 b9 38 04 00 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

