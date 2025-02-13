rule TrojanDownloader_Win32_WinReanimator_A_2147603018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/WinReanimator.A"
        threat_id = "2147603018"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "WinReanimator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 00 00 57 69 6e 72 65 61 6e 69 6d 61 74 6f 72 00 2f 75 6e 69 6e 73 74 61 6c 6c 00 2f 64 65 6c 65 74 65 00 00 00 00 f8 ff ff ff 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {30 00 00 00 18 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 77 69 6e 72 65 61 6e 69 6d 61 74 6f 72 2e 63 6f 6d 2f 57 69 6e 52 65 61 6e 69 6d 61 74 6f 72 2f 00 42 69 6e 61 72 69 65 73 31 2e 7a 69 70 00 42 69 6e 61 72 69 65 73 32 2e 7a 69 70 00 42 69 6e 61 72 69 65 73 33 2e 7a 69 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 00 47 45 54 00 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 52 65 61 6e 69 6d 61 74 6f 72 00 00 58 55 00 44 4c 4c 00 75 6e 2e 69 63 6f 00 5c 69 6e 73 74 61 6c 6c 2e 65 78 65 00 5c 57 69 6e 52 65 61 6e 69 6d 61 74 6f 72 2e 65 78 65 00 00 57 69 6e 52 65 61 6e 69 6d 61 74 6f 72 2e 65 78 65 20}  //weight: 1, accuracy: High
        $x_1_4 = {2f 66 69 72 73 74 20 2f 69 64 3d 25 64 20 2f 73 75 62 69 64 3d 25 73 00 2f 6d 65 6d 62 65 72 73 2f 75 70 64 61 74 65 5f 69 6e 73 74 2e 70 68 70 3f 77 6d 69 64 3d 25 64 26 73 75 62 69 64 3d 25 73 26 70 69 64 3d 25 64 26 6c 69 64 3d 25 64 26 68 73 3d 25 73 00 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_WinReanimator_B_2147603019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/WinReanimator.B"
        threat_id = "2147603019"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "WinReanimator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 00 00 43 3a 5c 57 69 6e 52 65 61 6e 69 6d 4d 48 43}  //weight: 1, accuracy: High
        $x_1_2 = {00 57 69 6e 52 65 61 6e 69 6d 61 74 6f 72 00 00 00 56 69 72 75 73 00 00 00 53 70 79 77 61 72 65 00 6f 70 65 6e 00 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 77 69 6e 72 65 61 6e 69 6d 61 74 6f 72 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_3 = {68 72 65 66 2d 64 69 61 6c 6f 67 2d 73 70 79 77 61 72 65 73 63 61 6e 00 72 00 75 00 6e 00 73 00 70 00 79 00 77 00 61 00 72 00 65 00 73 00 63 00 61 00 6e 00 5f 00 66 00 69 00 78 00 65 00 64}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 69 6e 72 65 61 6e 69 6d 61 74 6f 72 2e 63 6f 6d 2f 62 75 79 2e 68 74 6d 6c 00 00 00 48 54 4d 4c 5f 57 41 52 4e 5f 44 49 41 4c 4f 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

