rule VirTool_Win64_Injedepesz_A_2147967497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injedepesz.A"
        threat_id = "2147967497"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injedepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 44 24 40 33 d2 b9 10 00 00 00 ff ?? ?? ?? ?? ?? 48 8b d8 48 85 c0 ?? ?? 4d 8b c7 48 8b d0 49 8b cc ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 8b 54 24 40}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 a4 24 18 08 00 00 48 8b cf 8b d8 c7 44 24 20 04 00 00 00 ff ?? ?? ?? ?? ?? 4c 8b f8 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? ba 01 00 00 00 48 8b cf ff}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 01 00 00 00 48 8b cf ff [0-16] 49 8b d7 ?? ?? ?? ?? ?? ?? ?? e8 [0-17] 4c 8b cb ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 49 8b d7 48 8b cf ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

