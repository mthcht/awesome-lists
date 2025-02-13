rule Trojan_Win32_Nedsym_A_2147605132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nedsym.A"
        threat_id = "2147605132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nedsym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 57 0c ff 75 94 68 ?? ?? 42 00 ff 75 f0 68 ?? ?? 42 00 8d 45 e8 ba 05 00 00 00 e8 ?? ?? fd ff 46 ff 4d d8 0f 85 ?? fd ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nedsym_B_2147605133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nedsym.B"
        threat_id = "2147605133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nedsym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 57 0c ff b5 44 ff ff ff 68 ?? ?? 43 00 ff 75 e4 68 ?? ?? 43 00 8d 45 dc ba 05 00 00 00 e8 ?? ?? fc ff 43 ff 4d c4 0f 85 ?? fd ff ff}  //weight: 4, accuracy: Low
        $x_2_2 = {73 79 73 72 65 67 00 00 ff ff ff ff 07 00 00 00 53 75 6d 6d 61 72 79 00}  //weight: 2, accuracy: High
        $x_1_3 = {43 68 6f 6f 73 69 6e 67 20 52 65 73 70 6f 6e 63 65 73 2e 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 73 74 61 74 31 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 75 2e 70 68 70 3f 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 64 70 6f 72 74 2e 73 79 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nedsym_C_2147607898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nedsym.C"
        threat_id = "2147607898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nedsym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 57 0c ff b5 40 ff ff ff 68 ?? ?? 59 00 ff 75 f4 68 ?? ?? 59 00 8d 45 ec ba 05 00 00 00 e8 ?? ?? e6 ff a1 ?? ?? 5a 00 80 38 00 74 6c}  //weight: 4, accuracy: Low
        $x_1_2 = {43 68 6f 6f 73 69 6e 67 20 52 65 73 70 6f 6e 63 65 73 2e 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 73 74 61 74 31 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 79 73 72 65 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nedsym_F_2147632028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nedsym.F"
        threat_id = "2147632028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nedsym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 52 65 73 70 6f 6e 63 65 20 42 6c 61 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 2f 73 74 61 74 32 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5c 73 79 73 74 65 6d 33 32 5c 71 74 70 6c 75 67 69 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 26 6d 61 63 72 6f 73 65 73 5f 76 65 72 73 69 6f 6e 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 26 64 65 6c 69 76 65 72 65 64 70 65 72 63 65 6e 74 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 4c 4f 42 41 4c 5f 52 41 4e 44 4f 4d 49 5a 45 44 5f 42 4f 44 59 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 43 6f 6e 74 72 6f 6c 20 54 68 72 65 61 64 2e 2e 2e 2e 4e 6f 20 4a 6f 62 73 20 4c 6f 61 64 65 64 2c 20 53 6c 65 65 70 69 6e 67 20 33 30 30 20 73 65 63 6f 6e 64 73 2e 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 43 61 6c 63 75 6c 61 74 69 6e 67 20 44 65 6c 69 76 65 72 65 64 20 50 65 72 63 65 6e 74 2e 2e 2e 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Nedsym_G_2147643150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nedsym.G"
        threat_id = "2147643150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nedsym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 af 6a 04 68 00 10 00 00 68 54 96 01 00 6a 00 e8 ?? ?? ?? ?? 89 45 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {58 ff d0 85 c0 75 1d 8b 7d 0c 8a 07 0c 20 3c 74 75 09 c6 05}  //weight: 1, accuracy: High
        $x_1_3 = {85 c0 75 06 8b 5c ee 6c eb 2e 43 81 fb e7 03 00 00 75 df 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Nedsym_G_2147643150_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nedsym.G"
        threat_id = "2147643150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nedsym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 84 c0 74 13 fe c2 8a ca 80 e1 1f 80 c1 61 fe ce 32 ce 32 c1 aa eb e8}  //weight: 1, accuracy: High
        $x_1_2 = {4e 80 3e 77 75 0d 80 7e 01 77 75 07 80 7e 02 77 75 01 ad}  //weight: 1, accuracy: High
        $x_1_3 = {81 3e 52 4d 5f 51 0f 85 ?? ?? ?? ?? 81 7e 04 50 5f 45 4e 0f 85 ?? ?? ?? ?? 81 7e 08 43 4f 44 45 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nedsym_J_2147671584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nedsym.J"
        threat_id = "2147671584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nedsym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 03 04 24 13 54 24 04 83 c4 08 8b d8 ff d3 8b d0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 80 38 22}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 68 e8 03 00 00 e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

