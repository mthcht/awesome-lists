rule VirTool_Win64_Perasz_A_2147967986_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Perasz.A"
        threat_id = "2147967986"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Perasz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 e8 [0-17] 48 89 c1 e8 ?? ?? ?? ?? 48 89 c1 48 8b 15 58 0b 0d 00 48 8b 45 c8 89 5c 24 28 48 89 4c 24 20 41 b9 01 00 00 00 41 b8 00 00 00 00 48 89 c1 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 e8 c7 44 24 20 04 00 00 00 41 b9 00 00 00 00 41 b8 06 00 00 00 ba 00 00 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 8b 45 e0 c7 44 24 20 04 00 00 00 41 b9 00 00 00 00 41 b8 ff ff ff ff ba 00 00 00 00 48 89 c1 e8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

