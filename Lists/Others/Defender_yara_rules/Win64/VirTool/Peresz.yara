rule VirTool_Win64_Peresz_A_2147961358_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Peresz.A"
        threat_id = "2147961358"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Peresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 08 00 c6 45 18 00 48 8b 4d d8 4c 89 64 24 20 48 c7 44 24 28 00 00 00 00 4c 8b 25 cc 96 01 00 45 31 f6 31 d2 45 31 c0 45 31 c9 ?? ?? ?? 41 89 c7 48 89 5c 24 20 48 c7 44 24 28 00 00 00 00 31 c9 31 d2 45 31 c0 45 31 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 74 24 38 48 89 5c 24 30 4c 89 74 24 28 4c 89 7d 30 44 89 7c 24 20 48 89 f9 ba 30 00 00 00 41 b8 03 00 00 00 4c 89 8d 88 00 00 00 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? c7 85 d0 00 00 00 00 00 00 00 44 8b b5 f8 00 00 00 ?? ?? ?? ?? ?? ?? ?? 45 31 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

