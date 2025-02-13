rule VirTool_WinNT_Wopla_A_2147602457_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Wopla.A"
        threat_id = "2147602457"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Wopla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 83 e8 18 89 42 14 c6 42 0c 58 c6 42 0d 68 89 72 0e c6 42 12 50 c6 42 13 e9 8b c2 5f eb 02}  //weight: 1, accuracy: High
        $x_1_2 = {72 27 83 65 0c 00 85 f6 76 1b ff 37 e8 ?? ?? 00 00 83 c7 04 84 c0 74 08 ff 45 0c 39 75 0c 72 ea 39 75 0c 72 04 83 63 18 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_WinNT_Wopla_B_2147602458_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Wopla.B"
        threat_id = "2147602458"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Wopla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b c6 89 45 10 7d b0 e9 80 00 00 00 b8 06 00 00 80 e9 81 00 00 00 53 8b 45 14 8b 4d 1c 8d 1c 08 8d 45 28}  //weight: 1, accuracy: High
        $x_1_2 = {ff 34 88 e8 ?? ?? ff ff 8b 4d 10 89 01 8b 45 08 0f 22 c0 fb b0 01 eb 02 32 c0 5d c2 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

