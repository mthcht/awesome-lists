rule VirTool_Win64_Rovnix_A_2147649305_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rovnix.A"
        threat_id = "2147649305"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 3d 46 4a 74 18 66 8b 43 10 48 83 c3 10 66 85 c0 75 ed 66 81 3b 46 4a}  //weight: 2, accuracy: High
        $x_1_2 = {c6 03 68 8b 46 18 89 43 01 c6 43 05 e8 48 8b 46 10 48 2b c3 48 83 e8 0a 89 43 06 eb 04}  //weight: 1, accuracy: High
        $x_1_3 = {48 85 c9 74 08 4d 85 c9 74 0e 49 ff e1 4d 85 c0 74 06 48 8b ca 49 ff e0 b8 0d 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win64_Rovnix_C_2147681750_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rovnix.C"
        threat_id = "2147681750"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3c 11 13 13 13 13 75 09}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 03 00 00 80 75 3d 4c 8d 0d ?? ?? ?? ?? 49 8b 09 48 85 c9 74 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {80 3b e8 75 0b b9 b9 05 00 00 66 39 4b 05 74 08 48 03 d8 44 39 2b eb da 8b 43 01 48 8d 5c 18 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_Win64_Rovnix_E_2147690907_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rovnix.E"
        threat_id = "2147690907"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 85 c9 74 08 4d 85 c9 74 0e 49 ff e1 4d 85 c0 74 06 48 8b ca 49 ff e0 b8 0d 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {40 80 ff 28 74 16 40 80 ff 2a 74 10 40 80 ff 3c 74 0a}  //weight: 1, accuracy: High
        $x_1_3 = {b8 46 4a 00 00 48 83 c3 14 66 39 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_Win64_Rovnix_E_2147690916_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rovnix.E!exhaustive"
        threat_id = "2147690916"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rovnix"
        severity = "Critical"
        info = "exhaustive: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 85 c9 74 08 4d 85 c9 74 0e 49 ff e1 4d 85 c0 74 06 48 8b ca 49 ff e0 b8 0d 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

