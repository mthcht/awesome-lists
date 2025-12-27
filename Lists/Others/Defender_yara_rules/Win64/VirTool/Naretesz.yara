rule VirTool_Win64_Naretesz_A_2147959638_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Naretesz.A"
        threat_id = "2147959638"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Naretesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b c6 33 d2 b9 02 00 00 00 ff ?? ?? ?? ?? ?? 48 8b d8 48 85 c0 ?? ?? ff ?? ?? ?? ?? ?? 44 8b c0 8b d6 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 46 48 8b cb ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 0f 47 54 24 78 45 33 c9 ?? ?? ?? ?? ?? ?? ?? 33 c9 ff ?? ?? ?? ?? ?? b9 20 4e 00 00 ff ?? ?? ?? ?? ?? 48 8b 55 ?? 48 83 fa 07 [0-21] 48 8b 4c 24 78 48 8b c1 48 81 fa 00 10 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

