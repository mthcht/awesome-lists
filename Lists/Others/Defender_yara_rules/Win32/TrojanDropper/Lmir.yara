rule TrojanDropper_Win32_Lmir_ZX_2147583441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lmir.ZX"
        threat_id = "2147583441"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 65 73 6b 74 6f 70 00 00 5c 64 6c 6c 63 61 63 68 65 5c 76 65 72 63 6c 73 69 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {5c 76 65 72 63 6c 73 69 64 2e 65 78 65 00 00 00 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {63 6c 69 65 6e 74 2e 65 78 65 00 00 77 69 6e 6e 74 00 00 00 77 69 6e 64 6f 77 73 00 73 79 73 74}  //weight: 1, accuracy: High
        $x_1_4 = {73 79 73 74 65 6d 33 32 00 00 00 00 53 65 44 65}  //weight: 1, accuracy: High
        $x_1_5 = {51 8d 44 24 00 6a 00 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Lmir_S_2147609928_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lmir.S"
        threat_id = "2147609928"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d7 8b f0 81 e6 ff 01 00 00 81 c6 00 02 00 00 c1 e6 0a 56}  //weight: 2, accuracy: High
        $x_1_2 = {2e 64 6c 6c 50 8d 85}  //weight: 1, accuracy: High
        $x_1_3 = {2e 74 6d 70 50 8d 85}  //weight: 1, accuracy: High
        $x_3_4 = {6a 03 57 6a 01 68 00 00 00 80 89 38 ff 75 08 ff 15 ?? ?? ?? ?? 8b d8 83 fb ff 89 5d 08 0f 84 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 6a 02 57 6a fc 53 ff d6}  //weight: 3, accuracy: Low
        $x_3_5 = {6a 02 57 6a f8 ff 75 08 ff d6 8d 45 ec 57 50 8d 45 fc 6a 04 50 ff 75 08 ff d3 57 ff 75 08}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Lmir_D_2147616898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lmir.D"
        threat_id = "2147616898"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 f0 c7 45 ?? 25 73 6d 6d c7 45 ?? 78 25 6c 78 c7 45 ?? 2e 65 78 65 c6 45 fc 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 78 0d 80 3c 30 5c 75 f7 66 c7 44 30 01 77 74}  //weight: 1, accuracy: High
        $x_1_3 = {50 68 09 4a 00 00 51 [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 01 53 e8 ?? ?? ?? ?? ff d0 6a 04 53 e8 ?? ?? ?? ?? 8b f0 6a 01 ff d6 0b c0 74 1f 50 6a 00 68 ff 0f 1f 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

