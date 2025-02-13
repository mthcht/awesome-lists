rule TrojanSpy_Win32_Ifnapod_C_2147603483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ifnapod.C"
        threat_id = "2147603483"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ifnapod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 27 8d 44 24 10 50 ff d5 ff 35 ?? ?? 00 10 ff 74 24 18 ff 15 ?? ?? 00 10 dc 1d ?? ?? 00 10 83 c4 0c df e0 9e 76 cc eb b3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 3e 99 59 f7 f9 46 83 fe 08 8a 82 ?? ?? 00 10 88 44 35 c7 7c e4 80 65 d0 00 8d 85 34 fe ff ff 68 ?? ?? 00 10 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {57 4c 45 76 65 6e 74 4c 6f 67 6f 66 66 00 57 4c 45 76 65 6e 74 4c 6f 67 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ifnapod_A_2147603495_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ifnapod.A"
        threat_id = "2147603495"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ifnapod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fe 08 0f 84 ?? ?? 00 00 83 fe 0d 0f 84 ?? ?? 00 00 83 fe 2d 0f 84 ?? ?? 00 00 83 fe 56 74 44 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 11 ff 15 ?? ?? 00 10 a8 80}  //weight: 1, accuracy: Low
        $x_1_2 = {39 7d 08 0f 85 ?? ?? 00 00 8b 45 0c 2d 01 02 00 00 74 20 83 e8 03}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 10 8b 40 08 83 f8 10 0f 84 ?? ?? 00 00 3d ae 00 00 00 74 73 3d 02 03 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {49 6e 73 74 61 6c 6c 46 00 49 6e 73 74 61 6c 6c 46 4e 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ifnapod_B_2147603496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ifnapod.B"
        threat_id = "2147603496"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ifnapod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 0b 80 38 68 75 06 8b 40 01 89 46 0c ff 76 14 ff 76 10 ff 76 0c ff 76 04 e8}  //weight: 1, accuracy: High
        $x_1_2 = {76 0e 80 39 68 75 09 39 59 01 8d 71 01 0f 94 c2 85 d2 75 0f 83 c0 04 eb ce 83 c7 14 83 3f 00 75 a9 eb 33}  //weight: 1, accuracy: High
        $x_1_3 = {5f 50 72 6f 67 5f 48 6f 6f 6b 41 6c 6c 41 70 70 73 40 38 00 66 6e 44 4c 4c 00 66 6e 46 4e 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

