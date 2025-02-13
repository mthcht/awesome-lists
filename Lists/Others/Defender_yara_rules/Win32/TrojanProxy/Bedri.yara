rule TrojanProxy_Win32_Bedri_A_2147682004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bedri.A"
        threat_id = "2147682004"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7c 73 30 63 6b 73 39 72 6f 78 [0-1] 7b 2d 2d 2d 7d [0-16] 7c ?? ?? 2d ?? ?? 2d ?? ?? 2d ?? ?? 2d ?? ?? 2d ?? ?? 7c [0-16] 7c}  //weight: 3, accuracy: Low
        $x_1_2 = {33 c0 8a 42 02 85 c0 74 ?? 8b 4d ?? 33 d2 8a 51 02 83 fa 02}  //weight: 1, accuracy: Low
        $x_1_3 = {48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e 0d 0a 0d 0a 3c 62 6f 64 79 3e 3c 68 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 68 31 3e 3c 2f 62 6f 64 79 3e 00 00 00 48 54 54 50 2f 31 2e 30 20 32 30 30 20 4f 4b 0d 0a 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Bedri_C_2147683044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bedri.C"
        threat_id = "2147683044"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 73 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 6b c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 39 c6 85 ?? ?? ff ff 72 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 78}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff 62 c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 72 c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 33 c6 85 ?? ?? ff ff 68 c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 62}  //weight: 1, accuracy: Low
        $x_1_3 = "<body><h1>403 Forbidden</h1></body>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Bedri_C_2147683044_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bedri.C"
        threat_id = "2147683044"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 06 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab 8d 85 ?? ?? ff ff 50 6a 00 68 03 00 1f 00 ff 15 0e 00 c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 00}  //weight: 2, accuracy: Low
        $x_1_2 = {0f be 08 83 f9 2f 74 0b 8b 55 ?? 83 ea 01 89 55 ?? eb ea}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 73 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 6b c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 39}  //weight: 1, accuracy: Low
        $x_1_4 = "%siexploror.exe" ascii //weight: 1
        $x_1_5 = {67 68 65 00 49 53 41 4c 49 56 45 00 63 63 31 00}  //weight: 1, accuracy: High
        $x_1_6 = {66 75 63 6b 20 79 6f 75 72 20 6d 75 6d 2c 20 6e 6f 64 33 32 00}  //weight: 1, accuracy: High
        $x_2_7 = {78 63 76 00 65 63 68 6f 20 6f 66 66 0d 0a 73 74 61 72 74 20 22 66 64 63 64 66 22}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Bedri_B_2147683045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bedri.B"
        threat_id = "2147683045"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 6a 00 68 03 00 1f 00 ff 15 ?? ?? ?? ?? 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff 00 74 1b 00 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 31 c6 85 ?? ?? ff ff 00 8d 85 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_2 = {0f be 02 83 f8 2f 74 11 8b 8d ?? ?? ff ff 83 e9 01 89 8d ?? ?? ff ff eb e1}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff 73 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 6b c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 39}  //weight: 1, accuracy: Low
        $x_1_4 = {62 6c 61 63 6b 5f 73 74 6f 63 6b 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 65 6c 00 62 63 63 00 6e 75 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_6 = {c6 45 ec 73 c6 45 ed 30 c6 45 ee 63 c6 45 ef 6b c6 45 f0 73 c6 45 f1 39 c6 45 f2 72 c6 45 f3 6f c6 45 f4 78}  //weight: 2, accuracy: High
        $x_2_7 = {50 6a 00 68 03 00 1f 00 ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d ?? 00 74 1b 00 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 31 80 a5 ?? ?? ff ff 00 8d 85 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_8 = {50 6a 00 68 03 00 1f 00 ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d ?? 00 74 0f 00 c6 45 ?? 30 c6 45 ?? 31 (c6 45|80 65) ?? 00 8d 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Bedri_F_2147688743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bedri.F"
        threat_id = "2147688743"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedri"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 85 dc fd ff ff 25 c6 85 dd fd ff ff 73 c6 85 de fd ff ff 5c c6 85 df fd ff ff 73 c6 85 e0 fd ff ff 68 c6 85 e1 fd ff ff 65 c6 85 e2 fd ff ff 6c c6 85 e3 fd ff ff 6c c6 85 e4 fd ff ff 5c c6 85 e5 fd ff ff 6f c6 85 e6 fd ff ff 70}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 78 fd ff ff 43 c6 85 79 fd ff ff 3a c6 85 7a fd ff ff 5c c6 85 7b fd ff ff 4d c6 85 7c fd ff ff 69 c6 85 7d fd ff ff 63 c6 85 7e fd ff ff 72 c6 85 7f fd ff ff 6f c6 85 80 fd ff ff 73 c6 85 81 fd ff ff 6f c6 85 82 fd ff ff 66 c6 85 83 fd ff ff 74}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 cc 43 c6 45 cd 3a c6 45 ce 5c c6 45 cf 4d c6 45 d0 69 c6 45 d1 63 c6 45 d2 72 c6 45 d3 6f c6 45 d4 73 c6 45 d5 6f c6 45 d6 66 c6 45 d7 74}  //weight: 1, accuracy: High
        $x_1_4 = {63 6c 61 72 6b 20 25 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 6f 73 74 00 48 00}  //weight: 1, accuracy: High
        $x_1_6 = {ff ff 5c c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 5c}  //weight: 1, accuracy: Low
        $x_1_7 = {c6 45 dc 5c c6 45 dd 69 c6 45 de 6e c6 45 df 63 c6 45 e0 5c}  //weight: 1, accuracy: High
        $x_1_8 = {4e 76 64 69 61 00}  //weight: 1, accuracy: High
        $x_1_9 = {c6 45 d4 5c c6 45 d5 69 c6 45 d6 6e c6 45 d7 63 c6 45 d8 6c c6 45 d9 75 c6 45 da 64 c6 45 db 65 c6 45 dc 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanProxy_Win32_Bedri_G_2147718119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bedri.G"
        threat_id = "2147718119"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 4c 49 56 45 7c 7b ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7d}  //weight: 2, accuracy: Low
        $x_1_2 = "s0cks9roxy" ascii //weight: 1
        $x_1_3 = "b8edri3h8nb" ascii //weight: 1
        $x_1_4 = "STARTOK|" ascii //weight: 1
        $x_1_5 = "550 clark.ini" ascii //weight: 1
        $x_1_6 = "Global\\disguise0501" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

