rule TrojanSpy_Win32_Glyph_E_2147605106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Glyph.E"
        threat_id = "2147605106"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Glyph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 73 65 61 72 63 68 2e 63 72 73 6b 79 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 61 73 70 3f 6b 65 79 77 6f 72 64 3d 00 31 30 30 31 c6 c6 bd e2 c0 d6 d4 b0 00 68 74 74 70 3a 2f 2f 77 77 77 2e 73 7a 31 30 30 31 2e 6e 65 74 2f 73 65 61 72 63 68 2e 61 73 70 3f 6b 3d}  //weight: 1, accuracy: High
        $x_1_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 00 3b 00 5c 44 65 62 75 67 67 65 72 00 59 6f 75 72 20 49 6d 61 67 65 20 46 69 6c 65 20 4e 61 6d 65 20 48 65 72 65 20 77 69 74 68 6f 75 74 20 61 20 70 61 74}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 65 6e 74 72 79 2e 31 32 36 2e 63 6f 6d 2f 63 67 69 2f 6c 6f 67 69 6e 3f 76 65 72 69 66 79 63 6f 6f 6b 69 65 3d 31 26 6c 61 6e 67 75 61 67 65 3d 30 26 73 74 79 6c 65 3d 31 26 64 6f 6d 61 69 6e 3d 31 32 36 2e 63 6f 6d 26 62 43 6f 6f 6b 69 65 3d 26 75 73 65 72 3d 00 40 74 6f 6d 2e 63 6f 6d 00 68 74 74 70 3a 2f 2f 6c 6f 67 69 6e 2e 6d 61 69 6c 2e 74 6f 6d 2e 63 6f 6d 2f 63 67 69 2f 6c 6f 67 69 6e 3f 75 73 65 72 3d 00 40 32 31 63 6e 2e 63 6f 6d 00 26 70 61 73 73 77 64 3d}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 74 70 3a 2f 2f 77 65 62 6d 61 69 6c 2e 32 31 63 6e 2e 63 6f 6d 2f 4e 55 4c 4c 2f 4e 55 4c 4c 2f 4e 55 4c 4c 2f 4e 55 4c 4c 2f 4e 55 4c 4c 2f 53 69 67 6e 49 6e 2e 67 65 6e 3f 4c 6f 67 69 6e 4e 61 6d 65 3d 00 40 73 69 6e 61 2e 63 6f 6d 00 26 70 73 77 3d 00 68 74 74 70 3a 2f 2f 6d 61 69 6c 2e 73 69 6e 61 2e 63 6f 6d 2e 63 6e 2f 63 67 69 2d 62 69 6e 2f 6c 6f 67 69 6e 2e 63 67 69 3f 75 3d 00 40 32 36 33 2e 6e 65 74 00 68 74 74 70 3a 2f 2f 67 32 77 6d 2e 32 36 33 2e 6e 65 74 2f 78 6d 77 65 62 3f 75 73 65 72 3d 00 40 79 65 61 68 2e 6e 65 74 00 68 74 74 70 3a 2f 2f 77 65 62 2e 79 65 61 68 2e 6e 65 74 2f 63 67 69 2f 6c 6f 67 69 6e 3f 75 73 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

