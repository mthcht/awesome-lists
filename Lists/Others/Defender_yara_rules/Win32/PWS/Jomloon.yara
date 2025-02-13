rule PWS_Win32_Jomloon_A_2147610681_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Jomloon.A"
        threat_id = "2147610681"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Jomloon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 08 7c 05 33 c0 c2 08 00 33 d2 8a 54 41 05 52 33 d2 8a 54 41 04 8b 44 81 14 52 50 e8}  //weight: 1, accuracy: High
        $x_3_2 = {8b 4d 0c 25 ff 00 00 00 89 4d 0c 89 45 08 50 51 8b 45 08 8b 4d 0c d2 c8 89 45 08 59 58 8a 45 08}  //weight: 3, accuracy: High
        $x_2_3 = {66 89 51 0c 8a 08 80 f9 e8 75 0f 8b 48 01 8d 4c 19 05 2b c8 83 e9 05 89 48 01 6a 02}  //weight: 2, accuracy: High
        $x_1_4 = {55 4b 4f 53 00 00 00 00 32 30 30 33 00}  //weight: 1, accuracy: High
        $x_1_5 = {7b 36 45 43 42 30 42 45 38 2d 39 33 33 43 2d 39 31 44 32 2d 43 39 30 31 2d 39 41 31 31 45 41 31 35 31 32 31 41 7d 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Jomloon_D_2147622933_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Jomloon.D"
        threat_id = "2147622933"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Jomloon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f0 8a 14 06 32 d1 88 10 40 4f 75 f5}  //weight: 2, accuracy: High
        $x_2_2 = {75 09 68 d0 07 00 00 ff d3 eb e4 8b b4 24 ?? ?? 00 00 83 7e 24 01 74 09 68 2c 01 00 00 ff d3 eb f1}  //weight: 2, accuracy: Low
        $x_2_3 = {eb 33 83 f8 05 75 0b 8d 54 24 20 bf ?? ?? 00 10 eb 23 83 f8 06 75 0b 8d 54 24 20 bf ?? ?? 00 10 eb 13 83 f8 07 8d 54 24 20}  //weight: 2, accuracy: Low
        $x_1_4 = {55 4b 4f 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Jomloon_F_2147627057_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Jomloon.F"
        threat_id = "2147627057"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Jomloon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "38101905-D80F-4788-96F6-986A8186178A" ascii //weight: 1
        $x_1_2 = "\\w.?AV_com_" ascii //weight: 1
        $x_1_3 = "HookEx" ascii //weight: 1
        $x_1_4 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 [0-4] 44 00 69 00 73 00 6b 00 53 00 61 00 66 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Jomloon_E_2147627063_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Jomloon.E"
        threat_id = "2147627063"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Jomloon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 51 8b 45 08 8b 4d 0c d2 c8 89 45 08 59 58 8a 45 08}  //weight: 3, accuracy: High
        $x_1_2 = {bb 00 10 40 00 8b [0-6] 75 ?? 8b (45 a4|4c)}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 44 1e 09 e9 e8 ?? ?? ?? ?? 80 7d 00 e8 75 17 8b 56 0a 8d 44 3a 05}  //weight: 1, accuracy: Low
        $x_1_4 = {c6 40 09 e9 83 c0 0a 50 e8 [0-8] 80 ?? 09 e8 75 15 8b ?? 0a 8d 44 ?? 05}  //weight: 1, accuracy: Low
        $x_1_5 = {99 01 00 00 8a ?? 98 01 00 00 33 ?? 51 8a ?? 97 01 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b6 86 99 01 00 00 50 0f b6 86 98 01 00 00 50 0f b6 86 97 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

