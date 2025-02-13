rule TrojanSpy_Win32_Dabvegi_A_2147628671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Dabvegi.A"
        threat_id = "2147628671"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 72 54 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 6f 53 70 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 54 4f 50 5f 53 4e 49 46 46 45 52 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 52 41 42 42 45 5f 49 50 5f 50 4f 52 54 5f 53 4e 49 46 46 45 52 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 54 41 52 54 5f 53 4e 49 46 46 45 52 00}  //weight: 1, accuracy: High
        $x_1_6 = {55 50 44 41 54 45 5f 50 41 53 54 41 5f 4b 45 59 00}  //weight: 1, accuracy: High
        $x_1_7 = {52 45 47 49 53 54 52 41 5f 49 4e 46 45 43 54 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 61 76 65 44 65 6c 65 74 65 53 74 61 72 74 75 70 4b 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_Win32_Dabvegi_B_2147664379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Dabvegi.B"
        threat_id = "2147664379"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 10 66 8b 4d ?? 33 d2 66 3b 08 0f 94 c2 f7 da}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 8e f8 00 00 00 89 46 5c 89 41 0c c7 01 53 5a 44 44 c7 41 04 88 f0 27 33 66 c7 41 08 41 00}  //weight: 1, accuracy: High
        $x_1_3 = {8d 47 fe 83 f8 04 0f 87 f9 00 00 00 ff 24 85 ?? ?? ?? ?? 8d 4d ?? 8d 55 ?? 51 8b 0d ?? ?? ?? ?? 8d 45 ?? 52 89 75 ?? c7 45 ?? 05 00 00 00 c7 45 ?? 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {80 e1 7f 66 0f b6 c9 66 6b c9 02 0f 80 ?? ?? ?? ?? (34 1b|80) 66 33 ?? 8a ?? 33 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Dabvegi_D_2147678888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Dabvegi.D"
        threat_id = "2147678888"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 bd 74 ff ff ff (89 13|e9 03) 00 00 73 0c c7 85}  //weight: 1, accuracy: Low
        $x_1_2 = {80 e1 7f 66 0f b6 c9 66 6b c9 02 0f 80 ?? 07 00 00 (34|80 f2) 1b 66 33 ?? 8a ?? 33 ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 68 00 00 00 80 6a 00 6a 00 8b 45 08 8b 08 51 8d 55 b8 52 ff 15 ?? ?? 40 00 50 8b 45 ?? 50 e8 ?? ?? ?? ff 89 45 ac}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

