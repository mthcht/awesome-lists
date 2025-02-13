rule TrojanDownloader_Win32_Deludru_2147617659_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deludru"
        threat_id = "2147617659"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deludru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {75 0d 8b 6c 24 18 25 ff 0f 00 00 03 c7 01 28 8b 41 04 46 83 e8 08 83 c2 02 d1 e8 3b f0 72}  //weight: 5, accuracy: High
        $x_1_2 = {00 64 6c 6c 5f 6c 6f 61 64 2e 64 6c 6c 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 44 6c 6c 57 69 6e [0-4] 54 68 65 20 57 69 6e 64 6f 77 00}  //weight: 1, accuracy: Low
        $x_1_5 = {00 4d 79 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 4e 7a 50 77 62 71 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

