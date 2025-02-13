rule VirTool_WinNT_Pitou_A_2147688428_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Pitou.A"
        threat_id = "2147688428"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Pitou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9c 56 57 50 53 51 52 e8 ?? ?? ?? ?? 8f 46 08 8f 46 04 8f 46 0c 8f 06 8f 46 1c 8f 46 18 8f 46 20 58 3b 05 80 54 47 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Pitou_B_2147688430_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Pitou.B"
        threat_id = "2147688430"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Pitou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 00 58 c6 41 09 68 66 c7 41 0e 50 e9}  //weight: 1, accuracy: High
        $x_1_2 = {8a 11 32 d0 88 17 8a d0 d0 ea 02 c0 32 d0}  //weight: 1, accuracy: High
        $x_1_3 = {66 c1 c1 08 0f b7 c9 81 e9 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 83 e9 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

