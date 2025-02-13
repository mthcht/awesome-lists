rule TrojanDownloader_Win32_Nemim_A_2147679221_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nemim.gen!A"
        threat_id = "2147679221"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemim"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 74 24 0c bf 0d 00 00 00 8b 06 50 e8 eb 00 00 00 83 c4 04 83 c6 04 4f 75 ef}  //weight: 2, accuracy: High
        $x_2_2 = {55 8a 0c 37 32 d2 8d 44 24 11 bd 08 00 00 00 84 48 ff 8a 18 74 04 0a d3 eb 04 f6 d3 22 d3 83 c0 02 4d}  //weight: 2, accuracy: High
        $x_2_3 = {8a 10 8a 19 80 c2 17 32 da 40 88 19 41 4e 75 e6}  //weight: 2, accuracy: High
        $x_1_4 = {61 76 75 66 72 61 6b 5c 65 6a 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 56 42 66 72 61 6b 5c 65 6a 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 62 69 6e 2f 72 65 61 64 5f 69 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {73 74 65 70 32 2d 64 6f 77 6e 00}  //weight: 1, accuracy: High
        $x_1_8 = {25 73 3f 61 31 3d 25 73 26 61 32 3d 25 73 26 61 33 3d 25 73 26 61 34 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {6d 69 6e 6d 65 69 00}  //weight: 1, accuracy: High
        $x_1_10 = {eb 04 f6 d3 22 d3 83 c0 02 4d 75 eb 8b 44 24 24 88 14 37 47 3b f8 7c d1 5d 5b 8b fe 83 c9 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

