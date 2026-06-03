rule VirTool_Win64_Relesz_A_2147970839_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Relesz.A"
        threat_id = "2147970839"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Relesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 56 48 83 ec 08 41 50 41 51 48 83 ec 20 48 8b ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 41 b8 0d 00 00 00 48 8b c8 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 83 c4 20}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b 44 24 30 ?? ?? ?? ?? ?? b8 49 ba 00 00 66 c7 43 0a 41 ff 66 89 03 ba 0d 00 00 00 48 8b ?? ?? ?? ?? ?? 48 8b cb 48 89 43 02 c6 43 0c d2 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

