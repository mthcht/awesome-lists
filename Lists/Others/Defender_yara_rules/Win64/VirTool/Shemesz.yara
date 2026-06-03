rule VirTool_Win64_Shemesz_A_2147970840_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shemesz.A"
        threat_id = "2147970840"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shemesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 e8 ?? ?? ?? ?? 4c 8b c6 48 8b 54 24 70 48 8b ce ff [0-18] e8 ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 48 8b 4c 24 70 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c8 e8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 41 b9 40 00 00 00 4c 8b c3 48 8b d6 48 8b 4c 24 68 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

