rule Trojan_Win32_Tepoyx_A_2147657109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepoyx.A"
        threat_id = "2147657109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepoyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 50 45 00 00 0f 85 ?? ?? ?? ?? 8d 50 78 8b 12 03 55 ?? 89 55 ?? 83 c0 78 8b 40 04}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7e 04 05 72 0c 83 7e 04 05 75 0b 83 7e 08 00 75 05 e8 ?? ?? ?? ?? 83 7e 04 06 72 ?? c7 03 ff ff ff ff 68 ?? ?? ?? ?? 68 08 00 02 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepoyx_I_2147691707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepoyx.I"
        threat_id = "2147691707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepoyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {81 38 50 45 00 00 0f 85 ?? ?? ?? ?? 8d 50 78 8b 12 03 55 ?? 89 55 ?? 83 c0 78 8b 40 04}  //weight: 8, accuracy: Low
        $x_4_2 = {41 00 75 00 74 00 6f 00 43 00 6f 00 6e 00 66 00 69 00 67 00 55 00 52 00 4c 00 00 00 57 00 61 00 72 00 6e 00 6f 00 6e 00 42 00 61 00 64 00 43 00 65 00 72 00 74 00 52 00 65 00 63 00 76 00 69 00 6e 00 67 00 00 00 00 00 43 00 6c 00 65 00 61 00 72 00 42 00 72 00 6f 00 77 00 73 00 69 00 6e 00 67 00 48 00 69 00 73 00 74 00 6f 00 72 00 79 00 4f 00 6e 00 45 00 78 00 69 00 74 00 00 00 00 00 43 00 6c 00 65 00 61 00 6e 00 54 00 49 00 46 00 00 00 00 00 55 00 73 00 65 00 41 00 6c 00 6c 00 6f 00 77 00 4c 00 69 00 73 00 74 00 00 00}  //weight: 4, accuracy: High
        $x_4_3 = {55 73 65 20 50 72 6f 78 79 20 4f 6e 20 4c 6f 63 61 6c 20 4e 61 6d 65 73 20 43 68 65 63 6b 3d 30 0d 0a 4e 6f 20 50 72 6f 78 79 20 53 65 72 76 65 72 73 3d 0d 0a 4e 6f 20 50 72 6f 78 79 20 53 65 72 76 65 72 73 20 43 68 65 63 6b 3d 30 0d 0a 55 73 65 20 41 75 74 6f 6d 61 74 69 63 20 50 72 6f 78 79 20 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 3d 31 0d 0a [0-8] 41 75 74 6f 6d 61 74 69 63 20 50 72 6f 78 79 20 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 20 55 52 4c 3d 00}  //weight: 4, accuracy: Low
        $x_1_4 = {75 73 65 72 5f 70 72 65 66 28 22 62 72 6f 77 73 65 72 2e 63 61 63 68 65 2e 64 69 73 6b 2e 65 6e 61 62 6c 65 22 2c 20 66 61 6c 73 65 29 3b 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 74 79 70 65 22 2c 20 [0-4] 32 29 3b 0d 0a 00}  //weight: 1, accuracy: Low
        $x_1_6 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c 20 22 00 22 29 3b 0d 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Tepoyx_J_2147694104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepoyx.J"
        threat_id = "2147694104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepoyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 3a 04 00 00 6a 0b 6a 49 6a 46 6a 41 6a 6e 8b 4c 24 ?? 8b d3 8b c6 e8 ?? ?? ?? ?? a3}  //weight: 2, accuracy: Low
        $x_2_2 = {68 1d 06 00 00 6a 10 6a 12 6a 4e 6a 65 6a 42 8b 4c 24 ?? 8b d3 8b c6 e8 ?? ?? ?? ?? a3}  //weight: 2, accuracy: Low
        $x_1_3 = "&ver=0000048" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepoyx_K_2147709202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepoyx.K"
        threat_id = "2147709202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepoyx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 46 32 cb 81 e1 ff 00 00 00 66 89 0c 46 40 4a 75 ed}  //weight: 1, accuracy: High
        $x_1_2 = {68 72 06 00 00 6a 10 6a 25 6a 4f 6a 6e 6a 6f 8b cf 8b d3 8b c6 e8}  //weight: 1, accuracy: High
        $x_1_3 = "&ilvl=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

