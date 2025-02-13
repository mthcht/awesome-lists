rule VirTool_WinNT_Mondae_A_2147630960_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Mondae.A"
        threat_id = "2147630960"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Mondae"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 5c 2e 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 00 40 00 00 8b 5d d4 8b fb f3 ab 83 c3 04 c7 03 09 00 00 00 83 c3 04 89 5d cc 83 c3 24 c7 03 1e 00 00 00 83 c3 04 b9 fe 01 00 00 8b f2 8b fb f3 a5 50 52 ff 15 ?? ?? ?? ?? 81 c3 f8 07 00 00 c7 03 03 00 00 00 83 c3 04 6a 63 59}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 9e 88 00 00 00 39 1b 89 5d fc 75 0a b8 01 00 00 c0 e9 d1 00 00 00 8b 45 08 8d 50 01 8a 08 40 84 c9 75 f9 57 8b 3d ?? ?? ?? ?? 2b c2 50 ff 75 08 8d 86 74 01 00 00 50 ff d7 83 c4 0c 85 c0 75 61 8d 96 90 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

