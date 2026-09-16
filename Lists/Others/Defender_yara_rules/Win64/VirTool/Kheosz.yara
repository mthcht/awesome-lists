rule VirTool_Win64_Kheosz_A_2147978064_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kheosz.A"
        threat_id = "2147978064"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kheosz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 2e 32 11 48 83 c0 01 48 83 c1 01 88 50 ff 4c 39 c0 ?? ?? ?? ?? ?? ?? ?? c6 44 24 3c 00 ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 54 24 ?? 32 11 48 83 c0 01 48 83 c1 01 88 50 ff 4c 39 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c1 e6 04 ?? ?? ?? ?? ?? 45 31 c0 48 8b 4c 30 08 ?? ?? ?? ?? ?? 41 b9 19 00 02 00 48 89 44 24 20 ff ?? ?? ?? ?? ?? 89 44 24 4c 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {41 b9 02 00 00 00 31 c9 48 69 c0 f0 d8 ff ff 41 b8 20 00 00 00 48 89 fa 49 89 45 48 e8 ?? ?? ?? ?? 41 b9 04 00 00 00 41 b8 00 30 00 00 31 c9 ba 00 00 01 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

