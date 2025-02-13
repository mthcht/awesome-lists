rule PWS_Win32_Sekur_A_2147689701_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sekur.A"
        threat_id = "2147689701"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sekur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 59 89 03 57 57 ff 75 08 68 50 24 b7 07 6a 0b e8 ?? ?? ?? ?? 59 59 ff d0 8b 0b 8b 16 89 04 91 85 c0 75 c2 d1 ef 8b 45 08 75 b6}  //weight: 1, accuracy: Low
        $x_1_2 = {57 8b 7d 0c ff 0e 8b 06 ff 34 87 68 04 27 f5 0e 6a 0b e8 ?? ?? ?? ?? 59 59 ff d0 83 3e 00 75 e4}  //weight: 1, accuracy: Low
        $x_10_3 = {8d 45 e8 50 8d 45 a4 50 33 c0 50 50 ff 75 08 50 50 50 ff 75 10 50 68 a1 64 e1 01 50 e8 ?? ?? ?? ?? 59 59 ff d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sekur_B_2147691165_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sekur.B"
        threat_id = "2147691165"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sekur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 6f 67 6f 6e 5f 70 61 73 73 77 6f 72 64 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {6c 00 6f 00 67 00 6f 00 6e 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 00 65 00 6b 00 75 00 72 00 4c 00 53 00 41 00 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 6f 00 6d 00 65 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 73 00 20 00 74 00 6f 00 20 00 65 00 6e 00 75 00 6d 00 65 00 72 00 61 00 74 00 65 00 20 00 63 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 2e 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "* Password :" wide //weight: 1
        $x_1_6 = "* RootKey  :" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

