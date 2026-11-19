rule VirTool_Win64_Volodesz_A_2147982444_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Volodesz.A"
        threat_id = "2147982444"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Volodesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 60 8b 40 50 41 b9 40 00 00 00 41 b8 00 30 00 00 8b d0 33 c9 ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 44 24 40 48 83 c0 02 48 8b d0 48 8b 4c 24 58 ff ?? ?? ?? ?? ?? ?? 48 8b 4c 24 30 48 89 01 48 8b 44 24 30 48 83 c0 08 48 89 44 24 30 48 83 7c 24 48 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 44 24 30 33 c0 85 c0 ?? ?? 45 33 c0 33 d2 48 c7 c1 ff ff ff ff ff ?? ?? ?? ?? ?? ?? 45 33 c0 ba 01 00 00 00 48 8b 4c 24 28 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

