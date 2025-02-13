rule VirTool_WinNT_Idicaf_A_2147607513_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Idicaf.A"
        threat_id = "2147607513"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Idicaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 00 66 c7 45 ?? 68 00 66 c7 45 ?? 79 00 66 c7 45 ?? 73 00}  //weight: 2, accuracy: Low
        $x_2_2 = {68 42 52 69 6e 56 6a 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 31 8d 45 fc 50 56 57 ff 75 08 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {eb 37 60 8b c0 61 e8 ?? ?? ff ff a1 ?? ?? ?? ?? 8b 40 01 8b 0d ?? ?? ?? ?? 8b 55 f8 89 0c 82 83 25 ?? ?? ?? ?? 00 fb}  //weight: 1, accuracy: Low
        $x_1_4 = {42 72 65 61 6b 49 6e 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Idicaf_B_2147607514_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Idicaf.B"
        threat_id = "2147607514"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Idicaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 45 fc 50 6a 0b ff 15 ?? ?? 01 00 60 b8 01 00 00 00 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 45 fc 0f 84 e1 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {74 0e 8b 45 e0 c7 00 10 00 00 c0 e9 db 02 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 58 00 50 00 53 00 41 00 46 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 72 61 63 6b 4d 65 2e 73 79 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Idicaf_C_2147610136_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Idicaf.C"
        threat_id = "2147610136"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Idicaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7f 0c 00 f8 00 80 74}  //weight: 1, accuracy: High
        $x_1_2 = {b9 d4 40 07 00 3b c1}  //weight: 1, accuracy: High
        $x_1_3 = {85 c9 74 13 8b 50 40 3b ca 74 0c 89 15 ?? ?? ?? ?? 89 48 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

