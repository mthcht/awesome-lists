rule VirTool_WinNT_Grolf_A_2147624839_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Grolf.A"
        threat_id = "2147624839"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Grolf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 05 8b 4d 1c eb f3 c7 45 30 0f 00 00 c0 8b 06 85 c0 74 07}  //weight: 1, accuracy: High
        $x_1_2 = {83 e8 05 89 43 01 c6 03 e9 8b c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

