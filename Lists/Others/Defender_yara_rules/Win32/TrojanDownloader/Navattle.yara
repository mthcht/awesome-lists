rule TrojanDownloader_Win32_Navattle_A_2147669247_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Navattle.A"
        threat_id = "2147669247"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Navattle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 42 61 74 74 6c 65 2e 6e 65 74 00 00 43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e}  //weight: 1, accuracy: High
        $x_1_2 = {2e 6e 61 76 65 72 2e 63 6f 6d 2f 00 00 00 49 64 65 6e 74 69 74 79}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 00 2e 65 78 65 00 00 00 00 2e 67 69 66 00 00 00 00 52 75 6e 61 73}  //weight: 1, accuracy: High
        $x_1_4 = {5c 52 75 6e 00 00 00 6e 75 73 62 33 6d 6f 6e 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_5 = {8a 55 f8 88 11 8b 45 f4 83 c0 01 89 45 f4 8b 4d fc 83 c1 03 89 4d fc eb a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Navattle_B_2147679838_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Navattle.B"
        threat_id = "2147679838"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Navattle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 4d 53 76 63 48 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 74 73 6d 62 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 74 65 73 74 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 68 6e 4c 61 62 20 56 33 4c 69 74 65 20 55 70 64 61 74 65 20 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {b3 0a f6 eb 02 41 ff f6 eb 02 01 83 c1 03 04 30 88 04 16 8a 41 fe 46 84 c0 75 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

