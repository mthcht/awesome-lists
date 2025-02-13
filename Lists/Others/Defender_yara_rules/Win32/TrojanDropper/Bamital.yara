rule TrojanDropper_Win32_Bamital_G_2147634591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bamital.G"
        threat_id = "2147634591"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 81 7e 1a bb 07 74 0b 66 9d b8 01 00 00 00 c9 c2 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 07 5c c7 47 01 74 65 6d 70 c7 47 05 2e 74 6d 70 c6 47 09 00 6a 00}  //weight: 1, accuracy: High
        $x_1_3 = {3c 24 72 0c 3c 3d 77 08 04 30 04 07 04 06 eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bamital_B_2147636902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bamital.B"
        threat_id = "2147636902"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 3d 05 40 00 80 75 0a e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8a e0 88 21 8b 4d f8 83 c2 02 83 ea 01 58 8b c8 e2 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bamital_C_2147637455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bamital.C"
        threat_id = "2147637455"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 20 83 b8 ed 33 d2 8a 16 32 d0 d1 ea 73 02 33 d7 41 80 e1 07 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {83 c6 01 e2 f8 64 8b 15 30 00 00 00 8b 52 0c 8b 52 0c 8b 52 18 81 7a 20 bb 07 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d 08 89 0d ?? ?? ?? ?? b9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b d0 68 ?? ?? ?? ?? 6a 01 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bamital_D_2147646083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bamital.D"
        threat_id = "2147646083"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 70 6c 68 6c 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 52 00 50 00 43 00 20 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 73 00 70 00 6f 00 6f 00 6c 00 73 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 75 0c 80 3e e9 75 18 e8 ?? ?? ?? ?? 83 f8 05 75 07 ba 0a 00 00 00 eb 0c e9 a0 00 00 00 eb 05 ba 05 00 00 00 bb 00 00 00 00 8b 75 0c eb ?? e8 ?? ?? ?? ?? 83 f8 ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bamital_A_2147678300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bamital.gen!A"
        threat_id = "2147678300"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bamital"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a e9 75 08 8b 4d 0c 2b ca 01 4a 01 c9}  //weight: 1, accuracy: High
        $x_1_2 = {74 2b 8b 45 f4 83 78 04 04 75 11 ff 75 f4 e8 ?? ?? ?? ?? 8b 45 fc c9}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 0b c0 74 30 ff 15 ?? ?? ?? ?? 3c 05 75 09 c7 45 ec 01 00 00 00 eb 1b 8d 45 f4 50 6a 04 8d 45 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

