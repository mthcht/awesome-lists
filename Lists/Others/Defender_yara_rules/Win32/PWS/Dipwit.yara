rule PWS_Win32_Dipwit_A_2147627791_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dipwit.A"
        threat_id = "2147627791"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dipwit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 26 69 70 3d ab e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 40 02 8b 00 ab 66 b8 ff d0 66 ab 66 b8 85 c0 66 ab 66 b8 75 f0}  //weight: 1, accuracy: High
        $x_2_3 = {81 7d 50 57 65 62 4d 75 42 81 7d 58 20 4b 65 65 75 39 81 7d 60 43 6c 61 73}  //weight: 2, accuracy: High
        $x_2_4 = {ad 33 c2 d3 c2 ab e2 f8 5f 51 6a 06 6a 02 51 51}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dipwit_B_2147633880_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dipwit.B"
        threat_id = "2147633880"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dipwit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {57 65 62 4d 75 ?? 81 7d ?? 6f 6e 65 79 75 ?? 81 7d ?? 20 4b 65 65 75 ?? 81 7d ?? 70 65 72 2c}  //weight: 3, accuracy: Low
        $x_2_2 = {b8 26 64 74 3d ab}  //weight: 2, accuracy: High
        $x_1_3 = {68 10 02 00 00 ff 75 ?? 6a 21 8d 45 ?? 50 68 88 c0 07 00 ff 75 ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 6a 00 68 06 04 00 00 68 ee 01 13 00 ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dipwit_C_2147641363_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dipwit.C"
        threat_id = "2147641363"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dipwit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 38 57 65 62 4d 75 ?? [0-1] 81 78 08 20 4b 65 65 75 ?? [0-1] 81 78 12 61 73 73 69}  //weight: 2, accuracy: Low
        $x_2_2 = {d3 c2 87 d9 45 43 e2 ea 8b dd c1 e3 02 5d 5f 8d 85 ?? ?? ?? ?? 8d 4d ?? 6a 00 6a 06 6a 02}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 40 02 8b 00 ab 66 b8 ff d0 66 ab 66 b8 6a 00 66 ab b0 b8 aa}  //weight: 1, accuracy: High
        $x_1_4 = {b8 d9 9b 8b c2 f7 d0 ab}  //weight: 1, accuracy: High
        $x_1_5 = {d1 9b 93 93 f7 15 06 00 c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

