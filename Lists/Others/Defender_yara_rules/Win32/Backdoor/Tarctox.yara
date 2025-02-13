rule Backdoor_Win32_Tarctox_B_2147678697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tarctox.B"
        threat_id = "2147678697"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarctox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 2b 45 08 c1 e8 02 89 45 fc 33 c0 8b 4d fc 51 8b d1 4a c1 e2 02 03 55 08 81 32 ?? ?? 00 00 59 49 0b c9 75 02 eb 02 eb e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Tarctox_B_2147678697_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tarctox.B"
        threat_id = "2147678697"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarctox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 08 85 c0 7f 07 b8 02 00 00 00 eb 4d 57 8d 44 24 1c 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8d 4c 24 24 51 56 ff d3 3b c6 75 90 8d 54 24 24 52 ff d5 03 f0 80 3e 22 75 36 83 c6 01 80 3e 22 74 0c 8d 64 24 00 83 c6 01 80 3e 22}  //weight: 1, accuracy: High
        $x_1_3 = {74 1b 85 c0 74 17 8d 4c 24 0c 51 8d 54 24 0c 52 50 e8}  //weight: 1, accuracy: High
        $x_1_4 = {75 09 68 88 13 00 00 ff d3 eb de 8d 4d d0 51 56 e8}  //weight: 1, accuracy: High
        $x_1_5 = {70 72 6f 66 69 6c 65 73 2e 69 6e 69 00 00 00 00 41 50 50 44 41 54 41 00 5c 70 72 65 66 73 2e 6a 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 74 79 70 65 00 00 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 00}  //weight: 1, accuracy: High
        $x_1_7 = {6f 00 63 00 78 00 73 00 74 00 61 00 74 00 65 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "SYS_%08X%08X%08X%08X%08X" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

