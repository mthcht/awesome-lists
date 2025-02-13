rule TrojanDropper_Win32_Jadtre_A_2147626102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jadtre.A"
        threat_id = "2147626102"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jadtre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 03 ff e0 ff b5 06 00 8b ff 55 8b 45 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 c4 50 8b 45 fc 83 c0 3c 50 57 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {c1 e8 08 25 ff 00 00 00 0f b6 c0 89 45 f8 83 7d f8 02 75 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Jadtre_C_2147659821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jadtre.C"
        threat_id = "2147659821"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jadtre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f b6 50 09 c1 e1 08 0b ca 0f b6 50 0c c1 e1 08 0b ca 89 4d fc 8a 48 0a 32 48 05 3a 48 02 74 04 83 65 fc 00 b9 09 00 00 00 d3 4d fc}  //weight: 20, accuracy: High
        $x_10_2 = {56 6a 04 8d 45 fc 50 68 39 24 22 00 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00 eb 02}  //weight: 10, accuracy: Low
        $x_5_3 = {c7 40 fb e9 00 00 00 8b 45 dc 03 45 e0 8b 4d e4 2b c8 8b 45 dc 03 45 e0 89 48 fc 8b 45 dc ff e0}  //weight: 5, accuracy: High
        $x_5_4 = {5c 5c 2e 5c 47 75 6e 74 69 6f 72 00}  //weight: 5, accuracy: High
        $x_2_5 = "\\\\.\\pipe\\{5E73E82B-9894-493b-A424-676808F8A45E}" ascii //weight: 2
        $x_2_6 = "\\{65B4B2F0-2810-4df5-BD0F-0CE435A61102}" ascii //weight: 2
        $x_2_7 = "\\KB2536276666.log" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_20_*) and 2 of ($x_2_*))) or
            ((1 of ($x_20_*) and 1 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Jadtre_D_2147678920_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jadtre.D"
        threat_id = "2147678920"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jadtre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 5c 2e 5c 47 75 6e 74 69 6f 72 00}  //weight: 10, accuracy: High
        $x_10_2 = {5c 5c 2e 5c 70 69 70 65 5c 7b 35 45 37 33 45 38 32 42 2d 39 38 39 34 2d 34 39 33 62 2d 41 34 32 34 2d 36 37 36 38 30 38 46 38 41 34 35 45 7d 00}  //weight: 10, accuracy: High
        $x_1_3 = {4d 41 43 48 49 4e 45 5c 25 73 00 00 45 76 65 72 79 6f 6e 65 00 00 00 00 73 66 63 5f 6f 73 2e 64 6c 6c 00 00 53 66 63 46 69 6c 65 45 78 63 65 70}  //weight: 1, accuracy: High
        $x_1_4 = {49 6d 6d 4c 6f 61 64 4c 61 79 6f 75 74 00 00 00 69 6d 6d 33 32 2e 64 6c 6c 00 00 00 49 00 6d 00 65 00 20 00 46 00 69 00 6c 00 65 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 5c 2e 5c 25 43 3a 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 00 47 6c 6f 62 61 6c 5c 7b 36 35 42 34 42 32 46 30 2d 32 38 31 30 2d 34 64 66 35 2d 42 44 30 46 2d 30 43 45 34 33 35 41 36 31 31 30 32 7d 00 00 00 73 74 69 6e}  //weight: 1, accuracy: High
        $x_1_6 = {3a 44 45 4c 46 49 4c 45 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 00 6f 70 65 6e 00 00 00 00 33 36 30 74 72 61 79 2e 65 78 65 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 48 61 72 64 77 61 72}  //weight: 1, accuracy: High
        $x_1_7 = {5c 5c 2e 5c 48 69 6e 74 44 65 66 65 6e 64 00 00 5c 5c 2e 5c 44 50 30 30 30 30 00 00 53 65 74 7c 44 72 76 4d 6f 6e 7c 30 00 00 00 00 49 4d 45 20 66 69 6c 65 00 00 00 00 73 65 74 75 70 2e 65 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

