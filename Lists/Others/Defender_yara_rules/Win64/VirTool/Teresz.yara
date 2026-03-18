rule VirTool_Win64_Teresz_A_2147965077_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Teresz.A"
        threat_id = "2147965077"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Teresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 45 b0 48 8b 4d b8 48 8b c1 49 2b c0 41 be 19 00 00 00 ?? ?? ?? ?? ?? ?? ?? 49 3b c6 ?? ?? ?? ?? ?? ?? 48 89 45 b0 ?? ?? ?? ?? 48 83 f9 0f 48 0f 47 5d a0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 4c 24 30 48 89 44 24 28 48 c7 44 24 20 16 00 00 00 [0-17] e8 ?? ?? ?? ?? ?? 41 b8 0c 00 00 00 [0-17] e8}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b 64 24 48 45 33 f6 44 89 74 24 20 45 33 c9 45 33 c0 ba 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 8b f0 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

