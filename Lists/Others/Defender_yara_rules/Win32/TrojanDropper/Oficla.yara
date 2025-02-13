rule TrojanDropper_Win32_Oficla_G_2147800199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Oficla.G"
        threat_id = "2147800199"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 0f 0f 86 ?? ?? ?? ?? 83 bd ?? ?? ff ff 53 0f 86 ?? ?? ?? ?? 0f be 05 00 83 bd ?? ?? ff}  //weight: 3, accuracy: Low
        $x_1_2 = {83 c7 01 83 ff (28|32) 75}  //weight: 1, accuracy: Low
        $x_3_3 = {c7 04 24 04 01 00 00 04 00 89 ?? 24 04}  //weight: 3, accuracy: Low
        $x_1_4 = {0f be 81 00 30 40 00 83 e0 0f 39 ?? 75}  //weight: 1, accuracy: Low
        $x_1_5 = {ff ff ff 03 00 00 0f 86 04 00 81 bd ?? (e9|ea)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Oficla_B_2147801505_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Oficla.B"
        threat_id = "2147801505"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 5c 24 08 c7 44 24 04 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 03 00 83 ec 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 0b 83 c3 01 39 5f 18 76}  //weight: 1, accuracy: High
        $x_1_3 = {31 c3 89 d8 5b 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Oficla_C_2147803890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Oficla.C"
        threat_id = "2147803890"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 02 00 00 00 d3 ea a3 ?? ?? ?? ?? c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 40 89 14 24 ff d0 83 ec 1c 89 85 ?? ?? ?? ?? 83 c0 01 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 01 81 f9 00 08 00 00 19 c0 83 c2 01 21 c1 83 ad ?? ?? ?? ?? 01}  //weight: 1, accuracy: Low
        $x_1_3 = {89 54 24 0c 8b 95 ?? ?? ?? ?? c7 44 24 10 00 00 00 00 d3 e8 8b 8d ?? ?? ?? ?? 89 44 24 04 89 54 24 08 89 0c 24 ff 15 ?? ?? ?? ?? 0f b7 5d 96 c7 85 ?? ?? ?? ?? 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Oficla_I_2147803976_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Oficla.I"
        threat_id = "2147803976"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 81 f9 00 08 00 00 19 c0 83 c2 01 21 c1 83 ad ?? ?? ?? ?? 01}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c1 01 d2 75 f6 8b 9d ?? ?? ?? ?? 83 c7 01 39 bd ?? ?? ?? ?? 89 0b 0f 84 ?? ?? ?? ?? 83 c3 04 89 9d ?? ?? ?? ?? eb af}  //weight: 1, accuracy: Low
        $x_1_3 = {89 44 24 0c 8b 85 ?? ?? ?? ?? 89 4c 24 04 c7 44 24 10 00 00 00 00 89 14 24 89 44 24 08 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Oficla_N_2147804015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Oficla.N"
        threat_id = "2147804015"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 88 00 70 40 00 0f af d1 01 d3 83 f8 0d 75 ec}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 04 04 01 00 00 c7 04 24 0a 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {a1 ef 54 15 c6 a2 a6 5f 45 90 a3 90 f8 34 98 c4}  //weight: 1, accuracy: High
        $x_1_4 = {83 f9 07 7f 15 c1 e1 02 b8 ?? ?? 2b cb d3 e8 83 e0 0f ff 24 85 00 60 40 00 ?? ?? ?? 0f 8d 0c 8d e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Oficla_AB_2147804129_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Oficla.AB"
        threat_id = "2147804129"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 52 8b 45 b4 83 e8 ?? f7 d0 88 03 43 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 8a 00 a0 40 00 66 85 c0 74 02 d1 e1 81 f1 ?? ?? ?? ?? 89 8c ?? ?? ff ff ff 83 c2 04 83 fa 3c 75 de}  //weight: 1, accuracy: Low
        $x_1_3 = {00 a0 40 00 8b 9d ?? ?? ff ff 88 d1 d3 fb 29 da 81 f2 ?? ?? ?? ?? 89 94 ?? ?? ff ff ff 83 c0 04 83 f8 3c 75 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Oficla_K_2147804148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Oficla.K"
        threat_id = "2147804148"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 5c 24 08 c7 44 24 04 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 03 00 83 ec 0c}  //weight: 5, accuracy: Low
        $x_5_2 = {c7 04 24 04 01 00 00 04 00 89 ?? 24 04}  //weight: 5, accuracy: Low
        $x_5_3 = {c7 04 24 00 40 40 00 e8 0e 00 00 00 52 c9 c3}  //weight: 5, accuracy: High
        $x_1_4 = {a1 ef 54 15 c6 a2 a6 5f 45 90 a3 90 f8 34 98 c4 c9 9b 20 65 fc 8d 89}  //weight: 1, accuracy: High
        $x_1_5 = {a5 ef 54 12 c6 a5 af 5f 45 90 aa 90 f5 34 98 ca cd 9b 20 62 fc 8a 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Oficla_T_2147804175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Oficla.T"
        threat_id = "2147804175"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 04 24 00 00 00 00 ff d0 83 ec 0c}  //weight: 2, accuracy: High
        $x_1_2 = {83 f9 07 7f 15 c1 e1 ?? b8 ?? ?? ?? ?? d3 e8 83 e0 0f ff 24 85}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 5d 0c 8a 4d 10 d3 eb 8b 55 0c 8b 42 3c 8b 4c 03 78 01 cb}  //weight: 1, accuracy: High
        $x_2_4 = {c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 02 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 40 89 04 24 ff ?? 83 ec 1c}  //weight: 2, accuracy: Low
        $x_2_5 = {89 44 24 04 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Oficla_X_2147804187_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Oficla.X"
        threat_id = "2147804187"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Oficla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 d8 af bb b4 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 02 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {89 44 24 04 c7 04 24 e2 a9 a3 eb e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 14 87 d3 e2 31 d3 40 83 f8 0c 75}  //weight: 1, accuracy: High
        $x_1_4 = {e8 52 52 8b 45 ?? 83 e8 ?? f7 d0 88 03 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

