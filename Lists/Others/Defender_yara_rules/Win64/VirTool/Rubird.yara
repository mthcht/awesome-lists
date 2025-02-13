rule VirTool_Win64_Rubird_A_2147923512_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rubird.A"
        threat_id = "2147923512"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rubird"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 85 20 02 00 00 00 00 00 00 4c 89 bd e0 00 00 00 48 8b bd f0 01 00 00 48 8b b5 f8 01 00 00 c7 44 24 28 40 00 00 00 c7 44 24 20 00 30 00 00 ?? ?? ?? ?? ?? ?? ?? 4c ?? ?? ?? ?? ?? ?? 48 89 f9 45 31 c0 ff ?? ?? ?? ?? ?? 48 8b 95 20 02 00 00 4c 8b 8d e0 00 00 00 48 c7 44 24 20 00 00 00 00 48 89 f9 4c 8b 85 30 02 00 00 ff ?? ?? ?? ?? ?? 48 8b 95 20 02 00 00 48 c7 44 24 20 00 00 00 00 48 89 f1 49 89 d0 45 31 c9 ff ?? ?? ?? ?? ?? 48 89 f1 31 d2 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 45 00 88 45 d0 0f 28 45 e0 0f 28 4d f0 0f 29 4d c0 0f 29 45 b0 ?? ?? ?? ?? 31 c9 31 d2 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

