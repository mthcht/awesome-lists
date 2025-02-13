rule Worm_Win32_Macoute_A_2147686162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Macoute.A"
        threat_id = "2147686162"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Macoute"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 70 6f 35 00 25 73 5c 77 69 6e 00 25 73 5c 6d 73 6e 2e 65 78 65 00 52 65 67 4b 20 6e 6f 74 20}  //weight: 1, accuracy: High
        $x_1_2 = {2f 65 63 6f 75 74 65 2f 73 70 6f 6f 6c 2f 25 73 2d 25 6c 75 00 25 73 5c 69 6f 73 79 73 74 65 6d}  //weight: 1, accuracy: High
        $x_1_3 = {4d 53 4e 3b 25 73 3b 25 73 3b 25 73 0a 00 00 00 00 48 4f 4c 44 3b 25 73 0d 0a 00 51 55 49 54 00 25 64 7c 25 73 7c 25 6c 75 7c}  //weight: 1, accuracy: High
        $x_1_4 = {79 65 6c 7e 7d 6b 78 6f 76 67 43 49 58 45 59 45 4c 5e 76 7d 43 44 4e 45 5d 59 76 69 5f 58 58 4f 44 5e 7c 4f 58 59 43 45 44 76 78 5f 44 2a 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b 54 24 04 31 c0 80 3a 2a 74 0b 80 34 02 2a 40 80 3c 02 2a eb f3 80 34 02 2a c3}  //weight: 1, accuracy: High
        $x_1_6 = {89 e0 c6 44 ?? ?? 5a c6 44 ?? ?? 45 c6 44 ?? ?? 5c c6 44 ?? ?? 1f c6 44 ?? ?? 18 c6 44 ?? ?? 1a c6 44 ?? ?? 1a c6 44 ?? ?? 13 c6 44 ?? ?? 2a 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

