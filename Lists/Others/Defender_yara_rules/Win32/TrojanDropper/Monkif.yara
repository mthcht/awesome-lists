rule TrojanDropper_Win32_Monkif_A_2147616041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Monkif.A"
        threat_id = "2147616041"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d f4 93 08 00 00 74 0c 46 81 fe e8 19 10 00 7c e4}  //weight: 1, accuracy: High
        $x_1_2 = {6a e8 53 ff 15 ?? ?? ?? ?? 83 f8 ff 74 1f 57 8d 45 f4 50 6a 10 56 8b 35 04 20 40 00 53 ff d6 57 8d 45 f4 50 6a 08}  //weight: 1, accuracy: Low
        $x_1_3 = {43 83 fb 0a 7f 28 68 d0 07 00 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 00 03 00 00 74 de 81 3d ?? ?? ?? ?? 01 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Monkif_B_2147616051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Monkif.B"
        threat_id = "2147616051"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 7d f4 93 08 00 00 74 0c 46 81 fe e8 19 10 00 7c}  //weight: 2, accuracy: High
        $x_2_2 = {51 72 6f 63 65 73 73 33 32 46 69 72 73 74 00 00 5a 72 6f 63 65 73 73 33 32 4e 65 78 74}  //weight: 2, accuracy: High
        $x_1_3 = {00 4c 6f 63 61 6c 5c 55 49 45 49 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 62 61 6b 00 71 71 25 73}  //weight: 1, accuracy: High
        $x_1_5 = {6d 6f 6e 6b 65 79 2e 67 69 66 00}  //weight: 1, accuracy: High
        $x_1_6 = {45 d1 4c c6 45 d2 64 c6 45 d3 74 c6 45 d4 45 c6 45 d5 6e c6 45 d6 74 c6 45 d7 72 c6 45 d8 69 c6 45 d9 65 c6 45 da 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Monkif_F_2147621201_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Monkif.F"
        threat_id = "2147621201"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 f4 4c c6 45 f5 6f c6 45 f6 63 c6 45 f7 61 c6 45 f8 6c c6 45 f9 5c c6 45 fa 55 c6 45 fb 49 c6 45 fc 45 c6 45 fd 49}  //weight: 1, accuracy: High
        $x_1_2 = {81 7d f4 93 08 00 00 74 0c 46 81 fe e8 19 10 00 7c e4}  //weight: 1, accuracy: High
        $x_1_3 = {8d 48 fe 81 f9 ?? ?? ?? ?? 7c c7}  //weight: 1, accuracy: Low
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 50 52 2e 54 4f 43 4f 4c 53 5c 46 69 6c 74 65 72 5c 74 65 78 74 2f 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {b8 68 58 4d 56 b9 14 00 00 00 66 ba 58 56 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Monkif_G_2147622748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Monkif.G"
        threat_id = "2147622748"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 45 f4 4c c6 45 f5 6f c6 45 f6 63 c6 45 f7 61 c6 45 f8 6c c6 45 f9 5c c6 45 fa 55 c6 45 fb 49 c6 45 fc 45 c6 45 fd 49}  //weight: 2, accuracy: High
        $x_1_2 = {00 04 00 00 74 de 81 3d ?? ?? ?? ?? 01 04 00 00 74 d2 06 00 81 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 46 fe 83 c4 ?? 3d 04 af 22 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Monkif_J_2147641347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Monkif.J"
        threat_id = "2147641347"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 74 24 0c 2b f7 [0-9] 2a c2 2c ?? [0-7] 42 3b 54 24 10 [0-3] 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 73 30 30 31 2e 74 6d 70 [0-5] 54 68 72 65 61 64 69 6e 67 4d 6f 64 65 6c [0-5] 70 61 72 74 6d 65 6e 74 [0-5] 25 73 25 73 5c 25 73 00 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Monkif_J_2147641347_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Monkif.J"
        threat_id = "2147641347"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 0c 2b f7 8a 84 16 ?? ?? ?? ?? 2a c2 2c 4f 88 82 ?? ?? ?? ?? 42 3b 54 24 10 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 01 00 00 80 ff 55 f4 85 c0 75 3e ff 75 08 ff d6 50 ff 75 08 6a 01 53 53 ff 75 fc ff 55 f8 85 c0 75 27 bf ?? ?? ?? ?? 57 ff d6 50 57 6a 01 53 68 ?? ?? ?? ?? ff 75 fc ff 55 f8 85 c0 75 0b ff 75 fc ff 55 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Monkif_J_2147641347_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Monkif.J"
        threat_id = "2147641347"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 0c 2b f7 8d 8a ?? ?? ?? ?? 8a 04 0e 2a c2 2c 4f 42 3b 54 24 10 88 01 7c ea}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 01 00 00 80 ff 55 f4 85 c0 75 3e ff 75 08 ff d6 50 ff 75 08 6a 01 53 53 ff 75 fc ff 55 f8 85 c0 75 27 bf ?? ?? ?? ?? 57 ff d6 50 57 6a 01 53 68 ?? ?? ?? ?? ff 75 fc ff 55 f8 85 c0 75 0b ff 75 fc ff 55 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

