rule VirTool_Win64_Loadepesz_A_2147955142_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Loadepesz.A"
        threat_id = "2147955142"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Loadepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 85 d8 1c 00 00 [0-32] 48 89 45 08 ?? ?? ?? ?? ?? ?? ?? 48 89 45 28 c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 ba 01 00 00 00 48 8b 4d 08}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 38 14 00 00 48 8b 00 48 8b 8d 48 11 00 00 48 03 c8 48 8b c1 48 89 85 d8 14 00 00 48 8b 85 d8 14 00 00 48 83 c0 02 48 89 85 b8 1c 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

