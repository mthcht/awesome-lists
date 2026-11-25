rule VirTool_Win64_Trewesz_A_2147982771_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Trewesz.A"
        threat_id = "2147982771"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Trewesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 09 00 00 00 ?? ?? ?? ?? ?? 48 8b d6 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 30 00 00 00 00 ?? ?? ?? ?? ?? c7 44 24 28 80 00 00 00 45 33 c9 ba 00 00 00 40 c7 44 24 20 02 00 00 00 41 b8 01 00 00 00 ff ?? ?? ?? ?? ?? 48 8b f8 48 83 f8 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {44 8b 05 b3 29 02 00 ?? ?? ?? ?? ?? 48 8b 15 9f 29 02 00 48 8b c8 c7 44 24 40 00 00 00 00 48 c7 44 24 20 00 00 00 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

