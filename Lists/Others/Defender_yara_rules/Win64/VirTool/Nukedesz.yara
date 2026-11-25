rule VirTool_Win64_Nukedesz_A_2147982774_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nukedesz.A"
        threat_id = "2147982774"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nukedesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 20 48 8b 54 24 38 41 b8 40 00 00 00 b8 04 00 00 00 44 0f 44 c0 48 03 1d ?? ?? ?? ?? 48 89 4b 08 49 89 d9 48 89 53 10 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c3 80 38 00 ?? ?? ?? ?? ?? ?? 31 d2 b9 02 00 00 00 ff ?? ?? ?? ?? ?? 48 89 84 24 60 01 00 00 48 ff c0}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b8 08 00 00 00 [0-18] 48 8b 0d ?? ?? ?? ?? 48 8b 74 24 38 e8 ?? ?? ?? ?? 48 89 c3 80 38 00 [0-17] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

