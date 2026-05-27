rule VirTool_Win64_Revshemesz_A_2147970300_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Revshemesz.A"
        threat_id = "2147970300"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Revshemesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 85 c8 0f 00 00 48 83 bd c8 0f 00 00 00 ?? ?? ?? ?? ?? ?? 4c 8b [0-18] 48 8b 85 c8 0f 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 80 41 b9 00 00 00 00 41 b8 00 00 00 00 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 85 b4 0f 00 00 01 85 dc 0f 00 00 4c 8b [0-22] 48 8b 85 c0 0f 00 00 49 89 c9 41 b8 00 10 00 00 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

