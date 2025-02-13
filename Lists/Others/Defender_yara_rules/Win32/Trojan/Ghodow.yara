rule Trojan_Win32_Ghodow_A_2147632111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghodow.A"
        threat_id = "2147632111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghodow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d ec 02 76 19 89 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {80 39 8b 75 06 80 79 01 35 74 09 41 42 83 fa 64 7c ee eb 03}  //weight: 1, accuracy: High
        $x_1_3 = {cd 2a 8d 15 ?? ?? ?? ?? cd ee eb 13 68 f4 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ghodow_A_2147632111_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghodow.A"
        threat_id = "2147632111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghodow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 6e 69 6f 6e 69 64 3d 25 73 26 6d 61 63 3d 25 73 26 69 65 76 65 72 3d 25 64 26 61 6c 65 78 61 3d 25 64 26 73 79 73 74 65 6d 76 65 72 3d 25 64 26 61 6e 74 69 73 6f 66 74 77 61 72 65 3d 25 73 26 70 6c 75 67 69 6e 76 65 72 3d 25 73 00}  //weight: 2, accuracy: High
        $x_2_2 = {2f 63 6f 75 6e 74 2e 61 73 70 78 3f 69 3d 00}  //weight: 2, accuracy: High
        $x_2_3 = {25 73 2f 4e 65 77 43 6f 6e 66 69 67 2e 61 73 70 78 3f 6d 3d 00}  //weight: 2, accuracy: High
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44 5c 7b 33 43 45 46 46 36 43 44 2d 36 46 30 38 2d 34 65 34 64 2d 42 43 43 44 2d 46 46 37 34 31 35 32 38 38 43 33 42 7d 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 56 65 72 73 69 6f 6e 20 56 65 63 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {51 51 53 65 6c 66 25 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {8b 7d 0c 8b 4d 10 e8 ?? ?? ?? ?? 30 27 83 c7 01 83 e9 01 75 f1}  //weight: 1, accuracy: Low
        $x_1_8 = {b8 de 45 90 87 0b c0 74 2f 0f b6 d8 0f b6 14 1f 0f b6 0c 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ghodow_B_2147632167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghodow.B"
        threat_id = "2147632167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghodow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 02 6a 00 68 00 fd ff ff 55 ?? ?? ?? ?? ff d7}  //weight: 2, accuracy: Low
        $x_2_2 = {68 73 00 09 00 ?? ff 15 ?? ?? ?? ?? 83 f8 7a 89 44 24 10 75}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 [0-8] 68 00 00 00 c0}  //weight: 2, accuracy: Low
        $x_1_4 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 64 72 69 76 65 30 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 6e 69 6f 6e 69 64 3d 25 73 26 6d 61 63 3d 25 73 26 69 65 76 65 72 3d 31 26 61 6c 65 78 61 3d 30 26 73 79 73 74 65 6d 76 65 72 3d 32 26 61 6e 74 69 73 6f 66 74 77 61 72 65 3d 30 26 70 6c 75 67 69 6e 76 65 72 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 2f 63 6f 75 6e 74 2e 61 73 70 78 3f 69 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

