rule VirTool_WinNT_Rovnix_A_2147649638_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rovnix.A"
        threat_id = "2147649638"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 3d 46 4a 74 17 66 8b 46 10 83 c6 10 66 85 c0 75 ee 66 81 3e 46 4a}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 04 85 d2 b8 0d 00 00 c0 74 13 8b 4c 24 10 85 c9 74 1a 8b 44 24 08 50 52 ff d1 c2 10 00 8b 4c 24 0c 85 c9 74 07 8b 54 24 08 52 ff d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rovnix_B_2147681749_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rovnix.B"
        threat_id = "2147681749"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 3c 01 13 13 13 13 74 08 40}  //weight: 1, accuracy: High
        $x_1_2 = {81 3b 03 00 00 80 57 8b 7d 14 75 0f 56 8d b7 b8 00 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rovnix_C_2147683868_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rovnix.C"
        threat_id = "2147683868"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d 08 03 00 00 80 75 ?? eb 09 8b 45 fc 83 c0 01 89 45 fc 83 7d fc 01 73 ?? 8b 4d fc 83 3c 8d ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 2a 74 0d 0f b6 4d ff 83 f9 3b 0f 85 ?? ?? ?? ?? 8b 55 f4 52 8b 45 e4 50 8b 4d e0 51 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? c7 45 f8 22 00 00 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rovnix_D_2147690904_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rovnix.D"
        threat_id = "2147690904"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 14 b8 46 4a 00 00 66 39 06 0f 84 6b ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8d 74 86 14 b8 46 4a 00 00 66 39 06 0f 84}  //weight: 1, accuracy: High
        $x_1_3 = {ff 3c 2a 74 ?? 3c 3b 74 ?? 3c 28 74 04 3c 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_WinNT_Rovnix_E_2147734236_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rovnix.E!bit"
        threat_id = "2147734236"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rovnix"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 33 c7 d1 ef a8 01 74 06 81 f7 ?? ?? ?? ?? d1 e9 4e 75 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Device\\SafeBrain" wide //weight: 1
        $x_1_3 = "\\INJECTS.SYS" ascii //weight: 1
        $x_1_4 = "*\\safemon\\*.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

