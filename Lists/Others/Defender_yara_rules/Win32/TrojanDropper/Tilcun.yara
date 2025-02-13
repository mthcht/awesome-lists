rule TrojanDropper_Win32_Tilcun_A_2147603537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tilcun.A"
        threat_id = "2147603537"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tilcun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 f1 c1 e8 02 8b c8 74 14 8d 85 ?? ?? ff ff 8b 15 ?? ?? 40 00 31 10 83 c0 04 49 75 f2 6a 02 53 53}  //weight: 3, accuracy: Low
        $x_3_2 = {53 50 6a 26 68 ?? ?? 40 00 ff 75 ?? ff 15 ?? ?? 40 00 83 fb 26 7d 0a 80 b3 ?? ?? 40 00 ?? 43 eb f1 56}  //weight: 3, accuracy: Low
        $x_1_3 = {5c 77 69 6e 73 79 73 2e 72 65 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 5d 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {7e 74 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Tilcun_B_2147605454_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tilcun.B"
        threat_id = "2147605454"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tilcun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b cf 0f b6 45 ff 2b c8 6a 00 83 e9 07 6a 00 51 ff 75 f8 ff d3 8d 45 f4 6a 00 50 8d 85 ?? ?? ff ff 6a 06 50 ff 75 f8 ff 15 ?? ?? 40 00 33 c0 80 b4 05 ?? ?? ff ff ?? 40 83 f8 06 7c f2}  //weight: 3, accuracy: Low
        $x_1_2 = {5c 77 69 6e 73 79 73 2e 72 65 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 21 74 9e 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

