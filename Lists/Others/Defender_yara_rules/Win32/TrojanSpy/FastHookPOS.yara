rule TrojanSpy_Win32_FastHookPOS_A_2147712571_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/FastHookPOS.A"
        threat_id = "2147712571"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "FastHookPOS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 43 50 41 4e 45 4c 20 2b 20 53 55 52 53 41 5c 73 75 72 73 61 5c 54 68 65 20 48 6f 6f 6b 5c 52 65 6c 65 61 73 65 5c 54 68 65 20 48 6f 6f 6b 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 63 63 65 73 73 20 44 65 6e 69 65 64 3a 20 52 69 67 68 74 20 43 6c 69 63 6b 20 2d 3e 20 52 75 6e 20 61 73 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 74 61 74 75 73 6c 6f 67 26 6c 6f 67 3d 47 65 74 4c 61 73 74 45 72 72 6f 72 2d 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {6e 65 77 26 75 73 65 72 6e 61 6d 65 3d 25 73 26 63 6f 6d 70 75 74 65 72 6e 61 6d 65 3d 25 73 26 6f 73 3d 25 73 26 61 72 63 68 69 74 65 63 74 75 72 65 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 6f 75 70 64 61 74 65 26 76 65 72 3d 33 00}  //weight: 1, accuracy: High
        $x_1_6 = {6b 65 79 26 6c 6f 67 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = {5b 6c 63 74 72 6c 5d 00}  //weight: 1, accuracy: High
        $x_1_8 = {61 64 64 26 6c 6f 67 3d 25 73 26 66 6f 75 6e 64 69 6e 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {8b 75 8c 8b 7d 9c 8a 41 ff 83 e9 02 3c 35 7c 45 eb 09 80 39 39 75 08 c6 01 30 49 3b cf 73 f3 3b cf 73 04 41 66 ff 06 fe 01 8b 45 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

