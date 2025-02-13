rule TrojanDownloader_Win32_Bagle_ACB_2147804005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bagle.ACB"
        threat_id = "2147804005"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bagle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3e 31 75 ?? 56 8b fe 46 eb 01 a4 80 3e 00 75 fa}  //weight: 1, accuracy: Low
        $x_1_2 = {74 19 57 53 e8 ?? ?? ?? ?? 0b c0 75 07 5f 5e 5b c9 c2 08 00 89 06 83 c6 04 eb da}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 41 56 41 53 75 ?? 66 a1 ?? ?? ?? ?? 66 83 e0 df 66 3d 54 21}  //weight: 1, accuracy: Low
        $x_1_4 = "S1o1f1t1w1a1r1e1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Bagle_A_2147804037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bagle.gen!A"
        threat_id = "2147804037"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bagle"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 61 73 70 65 72 73 6b 79 20 4c 61 62 0b 54 72 65 6e 64 20 4d 69 63 72 6f 0f 49 00 63 00 65 00 53 00 77 00 6f 00 72 00 64 15 53 00 61 00 74 00 69 00 6e 00 66 00 6f 00 20 00 53 00 2e 00 4c 1e 33 32 37 38 38 32 52 32 46 57 4a 46 57 5c 72 65 73 74 6f 72 65 5f 70 74 2e 76 62 73 ed 87 2e 43 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 52 75 6e 00 3a 5c 57 49 4e 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 5c 5c 2e 5c 00 53 31 6f 31 66 31 74 31 77 31 61 31 72 31 65 31 5c 31 62 31 69 31 73 31 6f 31 66 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 1e 33 32 37 38 38 32 52 32 46 57 4a 46 57 5c 72 65 73 74 6f 72 65 5f 70 74 2e 76 62 73 ed 87 2e 43 00 6f 00 6d 00 70 00 69 00 6c 00 65 00 64 00 53 00 63 00 72 00 69 00 70 00 74 00 00 00 41 00 75 00 74 00 6f 00 49 00 74 00 20 00 76 00 2d 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 20 00 4c 00 61 00 62 00 2c}  //weight: 1, accuracy: High
        $x_1_4 = {5c 53 76 63 00 45 6e 61 62 6c 65 4c 55 41 00 5c 2a 2e 2a 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 3a 5c 57 49 4e 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 5c 5c 2e 5c 00 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

