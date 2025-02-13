rule TrojanSpy_Win32_Winelpos_A_2147692418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Winelpos.A"
        threat_id = "2147692418"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Winelpos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 24 77 44 00 e9 56 85 fc ff 8b 54 24 08 8d 42 0c 8b 4a f8 33 c8 e8 b0 78 fe ff b8 9c 32 44 00 e9 08 b7 fe ff cc cc cc cc cc cc cc cc cc cc cc b8 54 77 44 00 e9 86 2d fd ff 8b 54 24 08 8d 42 0c 8b 4a f4 33 c8 e8 80 78 fe ff b8 c8 32 44 00 e9 d8 b6 fe ff cc cc cc cc cc cc cc cc cc cc cc b8 64 77 44 00 e9 56 2d fd ff}  //weight: 1, accuracy: High
        $x_1_2 = {72 31 5c 52 65 6c 65 61 73 65 5c 72 31 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 52 52 4c 4f 47 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 72 72 6f 72 3a 20 6e 6f 74 20 61 64 6d 69 6e 20 75 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4d 00 65 00 64 00 69 00 61 00 20 00 48 00 65 00 6c 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {3a 00 77 00 6e 00 68 00 65 00 6c 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

