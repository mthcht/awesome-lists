rule Trojan_Win32_Pirpi_A_2147628906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pirpi.A"
        threat_id = "2147628906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 32 d3 30 10 88 14 01 40 4f 75 f2}  //weight: 1, accuracy: High
        $x_1_2 = {74 2a 68 01 00 00 7f e8 ?? ?? ?? ?? 39 85 ?? ?? ?? ?? 74 18 81 bd ?? ?? ?? ?? bd 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pirpi_B_2147628907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pirpi.B"
        threat_id = "2147628907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 03 ff 55 e8 c6 45 ?? 6b c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 6e}  //weight: 2, accuracy: Low
        $x_2_2 = {85 d2 7e 1d 8a 84 ?? ?? ?? ?? ?? 3c 7a 7f 0d 3c 61 7c 09}  //weight: 2, accuracy: Low
        $x_2_3 = {03 c8 05 f5 3f 00 00 a3 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? b8 01 00 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {73 70 30 00 55 8d 6c 24 c8 81 ec 68 01 00 00 a1 c8 e1 ca 76}  //weight: 2, accuracy: High
        $x_1_5 = {6e 74 6c 6d 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {6d 73 6e 74 6c 6d 2e 74 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pirpi_F_2147634392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pirpi.F"
        threat_id = "2147634392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 4b 8b 4d 08 8b 55 0c 8b 44 8a fc 0f be 08 83 f9 74 75 39 8b 55 08 8b 45 0c 8b 4c 90 fc 0f be 51 01 83 fa 35 75 26}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 0f 27 00 00 7e 23 b8 ad 8b db 68 f7 e9 c1 fa 0c 8b c2 c1 e8 1f 03 d0 8b c1 8b fa b9 10 27 00 00 99 f7 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Pirpi_G_2147639910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pirpi.G"
        threat_id = "2147639910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 84 fe ff ff 50 ff 15 ?? ?? ?? ?? 8d 4d 90 51 8d 55 fc 52 68 71 17 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7d 8c 93 00 00 00 72 07 33 c0 e9 ?? 01 00 00 b9 1a 00 00 00 33 c0 8d 7d 94 f3 ab 66 ab aa b9 1a 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d5 99 b9 1a 00 00 00 f7 f9 46 3b f7 8a 54 14 10 88 54 1e ff}  //weight: 1, accuracy: High
        $x_1_4 = {81 bd 00 f5 ff ff 00 10 00 00 73 14 8b 95 f0 f6 ff ff 52 ff 15 ?? ?? ?? ?? 33 c0 e9 ?? ?? 00 00 6a 00 6a 00 68 00 08 00 00 8b 85 f0 f6 ff ff 50 ff 15 ?? ?? ?? ?? b9 00 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Pirpi_A_2147644971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pirpi.gen!A"
        threat_id = "2147644971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ca 8b 45 08 33 d2 66 8b 14 45 ?? ?? ?? ?? 33 c0 66 a1 ?? ?? ?? ?? 33 d0 2b ca}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 7a 1c 89 82 60 09 00 00 89 82 64 09 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b9 41 00 00 00 8d ba 1c 08 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 04 31 84 c0 74 09 3a c3 74 05 32 c3 88 04 31 41 3b cd 72 eb}  //weight: 1, accuracy: High
        $x_1_4 = {89 82 70 09 00 00 b8 02 00 00 00 5f 5e}  //weight: 1, accuracy: High
        $x_1_5 = {8a 08 80 f1 ?? 8b 95 ?? ?? ?? ?? 88 0a 8b 85 ?? ?? ?? ?? 83 c0 01 09 00 2c 73 24}  //weight: 1, accuracy: Low
        $x_2_6 = {6a 04 50 56 ff d5 83 c7 04 4b 75 cf 1b 00 3d ?? ?? ?? ?? 74 09 35 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pirpi_N_2147656939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pirpi.N"
        threat_id = "2147656939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 02 74 04 3c 01 75 80 bc 24 ?? ?? 00 00 02 0f 85 ?? ?? 00 00 68 60 ea 00 00 ff 15 ?? ?? ?? ?? 8d 54 24 ?? 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 74 24 0c 85 f6 74 19 33 c0 85 f6 7e 13 8a 54 24 10 53 8a 1c 08 32 da 88 1c 08 40 3b c6 7c f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pirpi_J_2147696136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pirpi.J!dha"
        threat_id = "2147696136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f4 5e b9 22 00 00 00 33 c0 8d bd 78 ff ff ff f3 ab 8b 45 08 33 c9 66 8b 0c 45 ?? ?? ?? ?? 33 d2 66 8b 15 ?? ?? ?? ?? 33 ca 8b 45 08 33 d2 66 8b 14 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 83 fb ff 74 ?? 8d 84 24 98 00 00 00 50 53 e8 ?? ?? ?? ?? 85 c0 74 ?? 8b 35 ?? ?? ?? ?? 8d 4c 24 10 8d 54 24 0c 51 52 6a 4d e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

