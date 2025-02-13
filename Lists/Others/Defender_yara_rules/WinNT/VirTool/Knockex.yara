rule VirTool_WinNT_Knockex_B_2147598252_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Knockex.B"
        threat_id = "2147598252"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Knockex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 8b ec 83 c4 fc fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 ff 35}  //weight: 2, accuracy: High
        $x_2_2 = {83 c4 04 ff 64 24 fc 50 fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0}  //weight: 2, accuracy: High
        $x_2_3 = {ff 75 08 58 66 81 38 ff 25 75 07 ff 70 02 58 ff 30}  //weight: 2, accuracy: High
        $x_1_4 = {8b 45 08 3d 73 33 31 00}  //weight: 1, accuracy: High
        $x_1_5 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Knockex_D_2147598255_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Knockex.D"
        threat_id = "2147598255"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Knockex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 39 e8 75 ?? (8b|ff) [0-3] 8d 54 0a 05 81 3a 58 83 c0 03 75 ?? (8b|ff) [0-3] eb ?? 81 3a 58 ff 30 60 75 ?? (8b|ff) [0-3] eb 02 eb 0b c6 01 e9 2b d1 83 ea 05 89 51 01}  //weight: 3, accuracy: Low
        $x_1_2 = {66 81 38 ff 25 75 ?? (8b|ff)}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 9c 50 ff 75 a0 68 30 80 12 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

