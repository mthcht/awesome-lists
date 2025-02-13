rule TrojanDropper_Win32_Nebuler_A_2147625555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nebuler.A"
        threat_id = "2147625555"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 91 00 50 40 00 33 d0 8b 85 ?? ?? ?? ff 88 90 00 50 40 00 8d 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Nebuler_B_2147630356_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nebuler.B"
        threat_id = "2147630356"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ff b7 00 00 00 74 ?? 83 ff 05}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 11 01 00 00 68 ff ff 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 7e 08 11 01 00 00}  //weight: 1, accuracy: High
        $x_2_4 = {ff ff 2a cb 80 14 75 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Nebuler_C_2147631748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nebuler.C"
        threat_id = "2147631748"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 bd 6c 6a fe ff 00 98 00 00 73 29 8b 85 6c 6a fe ff 0f b6 ?? ?? ?? ?? ?? ?? 8b 95 6c 6a fe ff 0f b6 82 00 60 40 00 33 c1 8b 8d 6c 6a fe ff 88 81 00 60 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Nebuler_D_2147632359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nebuler.D"
        threat_id = "2147632359"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 83 c0 01 89 45 e4 07 00 88 94 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 e4 83 c2 01 89 55 e4 07 00 88 8c 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d e4 83 c1 01 89 4d e4 07 00 88 84 0d}  //weight: 1, accuracy: Low
        $x_4_4 = {2a cb 80 14 75 0f 06 00 81 bd}  //weight: 4, accuracy: Low
        $x_4_5 = {71 fe ff 8b ?? ?? ?? ?? ff 0f b6 ?? 00 60 40 00 33 ?? 8b}  //weight: 4, accuracy: Low
        $x_4_6 = {8b 51 08 ff d2 89 45 ?? 8b 45 08 05 ?? ?? ?? ?? 50 8b 4d ?? 51 8b 55 08 8b 42 04 ff d0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Nebuler_E_2147633742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nebuler.E"
        threat_id = "2147633742"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nebuler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {8b 51 08 ff d2 89 45 ?? 8b 45 08 05 ?? ?? ?? ?? 50 8b 4d ?? 51 8b 55 08 8b 42 04 ff d0}  //weight: 9, accuracy: Low
        $x_1_2 = {8b 55 ec 3b 15 00 70 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d ec 3b 0d 00 70 40 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 ec 3b 05 00 70 40 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 ec 8a 88 00 70 40 00}  //weight: 1, accuracy: High
        $x_1_6 = {8b 4d ec 8a 91 00 70 40 00}  //weight: 1, accuracy: High
        $x_1_7 = {8b 55 ec 8a 82 00 70 40 00}  //weight: 1, accuracy: High
        $x_1_8 = {0f b6 91 00 70 40 00 33 d0}  //weight: 1, accuracy: High
        $x_1_9 = {0f b6 88 00 70 40 00 33 ca}  //weight: 1, accuracy: High
        $x_1_10 = {0f b6 82 00 70 40 00 33 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

