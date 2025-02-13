rule VirTool_WinNT_Kelzef_B_2147654492_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Kelzef.B"
        threat_id = "2147654492"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Kelzef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MeTerviceEescriqtorTable" ascii //weight: 1
        $x_1_2 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 76 63 68 6f 73 74 2e 65 78 65 00 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Kelzef_A_2147673420_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Kelzef.A"
        threat_id = "2147673420"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Kelzef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 6d 6b 64 72 76 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {67 69 67 61 6c 61 6e 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {4b 4c 5a 20 46 49 4c 45 20 46 4f 55 4e 44 21 20 25 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 37 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_WinNT_Kelzef_C_2147679413_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Kelzef.C"
        threat_id = "2147679413"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Kelzef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6e 65 74 00 73 74 61 72 74 20 6e 65 77 64 72 69 76 65 72 00}  //weight: 2, accuracy: High
        $x_1_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 44 44 00 72 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 67 69 67 61 6c 61 6e 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 37 00}  //weight: 1, accuracy: High
        $x_1_5 = {5f 65 77 64 72 69 76 65 72 00 2d 6c 69 6e 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

