rule TrojanDownloader_Win32_Wiret_A_2147581882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wiret.gen!A"
        threat_id = "2147581882"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wiret"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "757fe676-25f4-4f9f-aae7-8ae70d7b1d0e" ascii //weight: 5
        $x_5_2 = "3c406344-a1e4-4cbf-be0b-1f66bc0da4f4" ascii //weight: 5
        $x_20_3 = {57 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 85 c0 8b 2d ?? ?? ?? 00 8b 1d ?? ?? ?? 00 6a 00 74 16 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a ff ff d3 eb 08 ff d5 ff 15 ?? ?? ?? 00 8b 4c 24 1c 8b 54 24 18 8d 44 24 10 50 6a 00 51 52}  //weight: 20, accuracy: Low
        $x_20_4 = {6a 00 6a 00 ff 15 ?? ?? ?? 00 6a 00 6a 00 6a 00 6a 00 6a 00 8b f8 ff d6 85 c0 6a 00 74 1c 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a ff ff d3 8b c7 5f 5e 5d 5b 59 c3 ff d5 ff 15 ?? ?? ?? 00 8b c7 5f 5e 5d 5b}  //weight: 20, accuracy: Low
        $x_12_5 = "757fe676-25f4-4f9f-aae7-8ae70d7b" ascii //weight: 12
        $x_13_6 = {31 64 30 65 00 00 00 00 33 63 34 30 36 33 34 34 2d 61 31 65 34 2d 34 63 62 66 2d 62 65 30 62 2d 31 66 36 36 62 63 30 64 61 34 66 34 00 00 00 00}  //weight: 13, accuracy: High
        $x_15_7 = {57 41 4e 4e 41 00 00 00 69 73 68 6f 73 74 2e 65 78 65 00 00 5c 00 00 00 6f 73 74 2e 65 78 65 00 25 73 5c 25 73 00 00 00 42 55 54 54 4f 4e 00 00 43 4f 4d 53 50 45 43 00 4f 70 65 6e 00 00 00 00 20 3e 20 6e 75 6c 00 00 2f 63 20 64 65 6c 20 00 43 6c 6f 73 65 48 61 6e 64 6c 65 00 45 78 69 74 50 72 6f 63 65 73 73 00 44 65 6c 65 74 65 46 69 6c 65 41}  //weight: 15, accuracy: High
        $x_15_8 = {53 49 4c 4c 59 00 00 00 5c 00 00 00 69 73 68 6f 73 74 2e 65 78 65 00 00 25 73 5c 25 73 00 00 00 43 4f 4d 53 50 45 43 00 4f 70 65 6e 00 00 00 00 20 3e 20 6e 75 6c 00 00 2f 63 20 64 65 6c 20 00 43 6c 6f 73 65 48 61 6e 64 6c 65 00 45 78 69 74 50 72 6f 63 65 73 73 00 44 65 6c 65 74 65 46 69 6c 65 41 00 49 72 71 7d 6c 4a 75 79 6b 53 7a 5a 75 70 79 00 6b 65}  //weight: 15, accuracy: High
        $x_15_9 = {52 41 4c 4c 59 00 00 00 5c 00 00 00 69 73 68 6f 73 74 2e 65 78 65 00 00 25 73 5c 25 73 00 00 00 43 4f 4d 53 50 45 43 00 4f 70 65 6e 00 00 00 00 20 3e 20 6e 75 6c 00 00 2f 63 20 64 65 6c 20 00 43 6c 6f 73 65 48 61 6e 64 6c 65 00 45 78 69 74 50 72 6f 63 65 73 73 00 44 65 6c 65 74 65 46 69 6c 65 41 00 25 73 25 73 25 73 00 00 55 6e 6d 61 00 00 00 00 70 56}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_13_*) and 1 of ($x_12_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_13_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_13_*) and 1 of ($x_12_*))) or
            ((2 of ($x_15_*) and 1 of ($x_5_*))) or
            ((2 of ($x_15_*) and 1 of ($x_12_*))) or
            ((2 of ($x_15_*) and 1 of ($x_13_*))) or
            ((3 of ($x_15_*))) or
            ((1 of ($x_20_*) and 1 of ($x_12_*) and 1 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_13_*) and 1 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_13_*) and 1 of ($x_12_*))) or
            ((1 of ($x_20_*) and 1 of ($x_15_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

