rule VirTool_WinNT_Boaxxe_A_2147598052_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Boaxxe.A"
        threat_id = "2147598052"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b c6 0f 8c ?? 02 00 00 8b 85 ?? ?? ff ff 8b 15 ?? ?? 01 00 8b 0d ?? ?? 01 00 89 85 ?? ?? ff ff 89 85 ?? ?? ff ff a1}  //weight: 2, accuracy: Low
        $x_2_2 = {89 85 94 fa ff ff 75 07 33 c0 e9 ?? 03 00 00 33 c0 6a 32 b9 00 01 00 00 8d bd 9c fa ff ff f3 ab 59 6a}  //weight: 2, accuracy: Low
        $x_1_3 = "Boot Bus Extender" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Boaxxe_B_2147598053_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Boaxxe.B"
        threat_id = "2147598053"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b c6 0f 8c ?? (02|03) 00 00 8b 85 ?? ?? ff ff 89 85 ?? ?? ff ff 89 85 ?? ?? ff ff a1}  //weight: 2, accuracy: Low
        $x_2_2 = {33 c0 8d bd (84|94) fa ff ff f3 ab 6a 32 59 8d bd (84|94) fe ff ff f3 ab 6a (54|5b) 59 8d bd (f0|fc) f4 ff ff f3 ab 0f b7 8d (5c|6c) f6 ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = "Boot Bus Extender" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Boaxxe_C_2147598054_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Boaxxe.C"
        threat_id = "2147598054"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b c6 0f 8c ?? 03 00 00 8b 85 ?? ?? ff ff 89 85 ?? ?? ff ff 89 85 ?? ?? ff ff a1}  //weight: 2, accuracy: Low
        $x_2_2 = {8d bd cc fa ff ff f3 ab 6a 32 59 8d bd cc fe ff ff f3 ab 6a 5b 59 8d bd 28 f5 ff ff f3 ab 0f b7 8d a4 f6 ff ff}  //weight: 2, accuracy: High
        $x_1_3 = "Boot Bus Extender" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Boaxxe_D_2147598055_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Boaxxe.D"
        threat_id = "2147598055"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3b c7 0f 8c ?? 02 00 00 8b 85 ?? ?? ff ff 8b 15 ?? ?? 01 00 8b 0d ?? ?? 01 00 89 85 ?? ?? ff ff 89 85 ?? ?? ff ff a1}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 32 b9 00 01 00 00 8d bd 9c fa ff ff f3 ab 59 6a 54 8d bd 9c fe ff ff f3 ab 59 8d bd 18 f5 ff ff f3 ab 0f b7 8d 74 f6 ff ff}  //weight: 2, accuracy: High
        $x_1_3 = "Boot Bus Extender" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Boaxxe_E_2147598056_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Boaxxe.E"
        threat_id = "2147598056"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Boaxxe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 05 80 38 55 89 4d 08 75 61 66 81 78 01 8b ec 75 59 66 81 78 03 83 ec 75 51 80 78 05 14 75 4b 6a 01 68}  //weight: 1, accuracy: High
        $x_1_2 = {6a 0b ff d3 8b 45 ?? 89 46 1c 0a 00 72 ?? 8d 4d ?? 51 50 ff ?? 0c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (eb ??|e9 ?? ?? ?? ??) 8b 4e 0c 89 01 89 7e 1c (eb|e9)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

