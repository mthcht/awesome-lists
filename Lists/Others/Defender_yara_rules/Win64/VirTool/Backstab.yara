rule VirTool_Win64_Backstab_A_2147899792_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Backstab.A"
        threat_id = "2147899792"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Backstab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5d a0 ff ?? ?? ?? 00 00 48 8b c8 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? 00 00 85 c0 ?? ?? 48 8b 4d a0 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 ?? ?? ?? ?? ?? 89 5c 24 74 ?? ?? ?? c7 45 ?? 04 00 00 00 ff ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 5c 24 28 ?? ?? ?? ?? 41 b9 10 00 00 00 48 89 5c 24 20 33 d2 ff ?? ?? ?? 00 00 48 8b 4d ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {bf 01 00 00 00 89 7c 24 40 ff ?? ?? ?? 00 00 33 d2 b9 00 10 00 00 44 8b c0 89 44 24 44 44 8b f0 ff ?? ?? ?? 00 00 49 3b c4}  //weight: 1, accuracy: Low
        $x_1_4 = {48 33 c4 48 89 85 30 08 00 00 0f 10 ?? ?? ?? ?? 00 8b 05 0b 42 00 00 4c 8b e2 48 89 54 24 78 44 8b f9 89 4c 24 60 33 d2 41 b8 f4 01 00 00 0f 29 85 10 04 00 00 ?? ?? ?? ?? ?? ?? ?? 89 85 20 04 00 00 e8 ?? ?? 00 00 33 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

