rule VirTool_WinNT_Koutodoor_A_2147627137_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Koutodoor.A"
        threat_id = "2147627137"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 07 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0 74 ?? (46|47) 81 (fe|ff) 00 30 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 07 03 c6 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0 74 ?? 46 81 fe 00 30 00 00 7c}  //weight: 1, accuracy: Low
        $x_2_3 = {99 f7 7d 0c 8b 45 08 (32 ??|8a 04 02 30 ??)}  //weight: 2, accuracy: Low
        $x_2_4 = {0c 0f 75 07 80 7c ?? 0d 85 74 ?? ?? 83 ?? 20}  //weight: 2, accuracy: Low
        $x_2_5 = {83 4d f4 ff c7 45 f0 80 0f 05 fd}  //weight: 2, accuracy: High
        $x_2_6 = {c7 45 f8 00 40 96 d5 c7 45 fc 36 ff ff ff}  //weight: 2, accuracy: High
        $x_3_7 = {3d 44 50 00 00 3d 45 50 00 00 75}  //weight: 3, accuracy: Low
        $x_1_8 = {25 ff ff fe ff 0f 22 c0 58}  //weight: 1, accuracy: High
        $x_1_9 = {8d 45 fc 56 50 e8 ?? ?? 00 00 8b 0d ?? ?? 01 00 a1 ?? ?? 01 00 8b 51 01 8b 30 8b 14 96 89 15 ?? ?? 01 00 8b 49 01 8b 00 c7 04 88 ?? ?? 01 00 ff 75 fc e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {b9 50 45 00 00 39 0c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Koutodoor_B_2147636445_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Koutodoor.B"
        threat_id = "2147636445"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 07 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0 74 ?? (46|47) 81 (fe|ff) 00 30 00 00 72 df}  //weight: 1, accuracy: Low
        $x_1_2 = {99 f7 7d 0c 8b 45 08 8a 04 02 32 01 32 45 14 46 3b 75 14 88 01 7c e1}  //weight: 1, accuracy: High
        $x_1_3 = {b8 00 40 96 d5 c7 45 fc 36 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Koutodoor_C_2147638003_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Koutodoor.C"
        threat_id = "2147638003"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 04 20 22 00 0f 84 ?? ?? ?? ?? 2d ff c0 00 00 74 ?? 83 e8 3d 74}  //weight: 1, accuracy: Low
        $x_1_2 = "\\ApsX85.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

