rule Backdoor_Win32_Moudoor_A_2147652729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Moudoor.A"
        threat_id = "2147652729"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Moudoor"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 69 6e 67 20 6c 6f 63 61 6c 68 6f 73 74 20 2d 6e 20 [0-2] 20 26 20 64 65 6c 20 22 25 73 22}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 33 c9 85 ff 76 1e 8b c1 bd 06 00 00 00 99 f7 fd 8a 04 31 80 c2 ?? 32 c2 88 04 31 41 3b cf 72 e6 8b 6c 24 ?? 8d 44 24 ?? 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Moudoor_A_2147652729_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Moudoor.A"
        threat_id = "2147652729"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Moudoor"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 f8 83 c2 01 89 55 f8 8b 45 f8 3b 45 f4 7d 2e 8b 4d fc 03 4d f8 0f be 11 81 ea ?? 00 00 00 8b 45 fc 03 45 f8 88 10 90 8b 4d fc 03 4d f8 0f be 11 83 f2 ?? 8b 45 fc 03 45 f8 88 10}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 f8 73 26 8b 4d ?? 03 4d fc 33 d2 8a 11 8b ca 8b 45 fc 99 be ?? 00 00 00 f7 fe 83 c2 ?? 33 ca 8b 55 ?? 03 55 fc 88 0a eb c9}  //weight: 2, accuracy: Low
        $x_1_3 = {55 70 64 61 74 65 57 69 6e 64 6f 77 00 00 00 00 61 75 74 6f 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_4 = {68 6f 73 74 2e 65 78 65 00 4d 69 63 72 6f 73 6f 66 74 20 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Moudoor_B_2147652730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Moudoor.B"
        threat_id = "2147652730"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Moudoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 6a 06 99 5b f7 fb 80 c2 66 30 14 31 41 3b cf 72 ed 8d 45}  //weight: 1, accuracy: High
        $x_1_2 = {8b c1 6a 06 99 5b f7 fb 80 c2 66 30 14 39 41 3b 4d}  //weight: 1, accuracy: High
        $x_1_3 = {75 70 2e 62 61 6b 00 00 55 70 64 61 74 65 57 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Moudoor_B_2147652730_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Moudoor.B"
        threat_id = "2147652730"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Moudoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "exe.yartexk" wide //weight: 1
        $x_1_2 = {6a 45 33 c0 59 8d bd e9 fe ff ff 88 9d e8 fe ff ff f3 ab 66 ab aa 8d 85 e8 fe ff ff c7 04 24 18 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b fb 83 c9 ff 33 c0 f2 ae f7 d1 49 83 f9 06 0f 86 ?? ?? 00 00 6a 3a 53 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

