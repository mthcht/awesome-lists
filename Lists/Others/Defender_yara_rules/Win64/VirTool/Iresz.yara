rule VirTool_Win64_Iresz_A_2147975262_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Iresz.A"
        threat_id = "2147975262"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Iresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 43 10 41 b9 00 30 00 00 48 8b 4b 08 33 d2 c7 44 24 20 04 00 00 00 4d 8b 40 08 ff ?? ?? ?? ?? ?? 48 8b e8 48 85 c0 ?? ?? 48 85 ff ?? ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4d 10 ?? ?? ?? ?? 41 b9 02 00 00 00 48 89 44 24 28 45 33 c0 44 89 4c 24 20 ba 00 00 00 02 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 4d 20 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 44 24 20 4d 8b 48 08 4d 8b 00 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 48 8b 43 10 4c 8b 40 08 4c 39 84 24 80 00 00 00 ?? ?? ?? ?? ?? ?? 48 8b 4b 08 ?? ?? ?? ?? ?? 41 b9 40 00 00 00 48 89 44 24 20 48 8b d5 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

