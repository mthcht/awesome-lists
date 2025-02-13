rule Trojan_Win32_Lukicsel_A_2147626997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lukicsel.A"
        threat_id = "2147626997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 10 e8 ?? ?? ?? ?? 8b d8 85 db 74 ?? 6a 00 6a 00 8b 44 24 ?? 50 8b 44 24 ?? 50 53 e8 ?? ?? ?? ?? 68 e8 03 00 00 e8 ?? ?? ?? ?? 6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 c0 ?? e8 ?? ?? ?? ?? 83 f8 ff 74}  //weight: 1, accuracy: Low
        $x_1_2 = {74 50 6a 00 8d 45 f0 50 6a 04 8b 45 08 50 56 e8 ?? ?? ?? ?? 6a 00 8d 45 f0 50 6a 04 8b 45 fc 50 56 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {74 2a 8b 04 24 50 6a 00 6a 10 e8 ?? ?? ?? ?? 8b d8 85 db 74 11 6a 00 6a 00 6a 00 8b 44 24 10 50 53 e8 ?? ?? ?? ?? 53 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Lukicsel_D_2147629881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lukicsel.D"
        threat_id = "2147629881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 06 88 07 46 47 4b 75 f2 05 00 e8}  //weight: 1, accuracy: Low
        $x_2_2 = {8b d8 6a 00 8d 45 ec 50 6a 04 8d 45 f8 28 00 b8 ?? ?? ?? ?? 89 45 f4 b8 ?? ?? ?? ?? 89 45 f0}  //weight: 2, accuracy: Low
        $x_2_3 = {6b 62 64 61 74 61 74 ?? 2e 64 6c 6c 00 6b 62 64}  //weight: 2, accuracy: Low
        $x_3_4 = {85 f6 72 17 46 33 ff 53 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 05 43 47 4e 75 ec 81 ff e8 03 00 00 75 04 33 db eb 06}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lukicsel_E_2147630505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lukicsel.E"
        threat_id = "2147630505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 85 db 7c 0f 43 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 5d f8 8b 45 f4 83 c0 34 03 d8 8d 55 f4 8b c3 b9 04 00 00 00 e8 ?? ?? ?? ?? 8b 45 f4 89 45 f0 8b 5d f8 83 ee 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f4 8b 40 08 ba ?? ?? ?? ?? 8b 08 ff 51 38 8b 45 f4 8b 40 08 ba ?? ?? ?? ?? 8b 08 ff 51 38 8b 45 f4 8b 40 08 ba ?? ?? ?? ?? 8b 08 ff 51 38}  //weight: 1, accuracy: Low
        $x_1_4 = {66 83 7b 12 00 74 0c 56 8b 4b 4c 8b d3 8b 43 14 ff 53 10 85 f6 75 0c ba 02 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Lukicsel_F_2147637385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lukicsel.F"
        threat_id = "2147637385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 57 69 6e 6c 6f 67 6f 6e 4c 6f 67 6f 66 66 45 76 65 6e 74 00 57 69 6e 6c 6f 67 6f 6e 53 74 61 72 74 75 70 45 76 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 45 08 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 ef}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 02 ff 15 ?? ?? ?? ?? 8b d8 85 db 75 ?? e8 ?? ?? ?? ?? 83 f8 02 75 05 e8 ?? ?? ?? ?? 68 e8 03 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lukicsel_G_2147638898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lukicsel.G"
        threat_id = "2147638898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 6c 6f 67 6f 6e 4c 6f 67 6f 66 66 45 76 00 57 69 6e 6c 6f 67 6f 6e 53 74 61 72 74 75 70 45 76 00}  //weight: 1, accuracy: High
        $x_1_2 = {8e 5e 40 fd 6c 6d 6a 47 1e e0 a7 8f e9 2d b7 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {8d 45 08 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 ef}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lukicsel_H_2147640733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lukicsel.H"
        threat_id = "2147640733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 74 06 04 ?? ff 45 ?? 83 7d ?? 0c 75 ef 8d 46 04 8b 00 b2 04 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {7c 12 43 8d 45 ?? e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 ef}  //weight: 1, accuracy: Low
        $x_2_3 = {83 c0 34 03 d8 8d 55 ?? 8b c3 b9 04 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 5d ?? 83 ee 0a 85 f6 72 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lukicsel_I_2147645345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lukicsel.I"
        threat_id = "2147645345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 2e 64 6c 6c 00 57 69 6e 6c 6f 67 6f 6e 4c 6f 67 45 58 00 57 69 6e 6c 6f 67 6f 6e 53 74 61 72 74 45 58}  //weight: 1, accuracy: High
        $x_1_2 = {62 2e 64 6c 6c 00 57 69 6e 4f 66 66 [0-1] 45 58 00 57 69 6e 53 74 61 72 74 [0-1] 45 58}  //weight: 1, accuracy: Low
        $x_1_3 = {61 2e 64 6c 6c 00 61 61 62 62 00 79 79 62 62}  //weight: 1, accuracy: High
        $x_1_4 = {61 77 65 72 2e 64 6c 6c 00 73 64 66 63 76 62 00 73 64 66 63 76 62 61 64 73 66 00}  //weight: 1, accuracy: High
        $x_10_5 = {32 06 88 07 46 47 4b 75 ef}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lukicsel_J_2147646923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lukicsel.J"
        threat_id = "2147646923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 6f 6d 62 69 65 2e 65 78 65 00 49 72 63 43 6f 6e 6e 65 63 74 69 6f 6e 00 4d 65 65 62 65 79 2e 53 6d 61 72 74 49 72 63 34 6e 65 74}  //weight: 1, accuracy: High
        $x_1_2 = {5a 6f 6d 62 69 65 00 41 74 74 61 63 6b 00 70 61 72 61 6d 73 41 74 74 61 63 6b 00 49 72 63 4d 65 73 73 61 67 65 44 61 74 61 00 49 72 63 43 6c 69 65 6e 74}  //weight: 1, accuracy: High
        $x_1_3 = "All Attacks Stopped!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lukicsel_L_2147657952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lukicsel.L"
        threat_id = "2147657952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 fb 1d 75 ?? c7 06 9a 02 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 08 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

