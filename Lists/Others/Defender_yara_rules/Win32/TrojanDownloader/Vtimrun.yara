rule TrojanDownloader_Win32_Vtimrun_A_2147624652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vtimrun.A"
        threat_id = "2147624652"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vtimrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 10 0f b6 c0 69 c0 60 ea 00 00 50 ff 15 ?? ?? ?? ?? 8b 46 08 3b c3 75 11}  //weight: 3, accuracy: Low
        $x_3_2 = {50 6a 32 53 89 7c 24 2c ff 15 ?? ?? ?? ?? 8a 06 3a c3 88 44 24 13 8d 6e 01 0f 84 d0 02 00 00 eb 03}  //weight: 3, accuracy: Low
        $x_1_3 = "%svb%d.exe" ascii //weight: 1
        $x_1_4 = "{30658737-1F19-450e-B61D-C81A21C24298}" ascii //weight: 1
        $x_1_5 = "{A6DCE90B-7238-4909-AE20-550280DFD9F8}" ascii //weight: 1
        $x_1_6 = {49 6e 73 74 61 6c 6c 00 69 74 65 6d 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Vtimrun_B_2147625165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vtimrun.B"
        threat_id = "2147625165"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vtimrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3c 02 75 16 6a 03 53 53 ff 74 24 ?? 68 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? eb ?? 3c 03 75}  //weight: 2, accuracy: Low
        $x_2_2 = {81 fe b7 00 00 00 74 07 57 ff 15 ?? ?? ?? ?? 3b fb 74 16 81 fe b7 00 00 00 75 0e 38 5c 24 ?? 89 5c 24 ?? 0f 87 ?? ff ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = {49 6e 73 74 61 6c 6c 00 69 74 65 6d 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 70 70 4b 65 79 5c 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5f 49 6e 73 74 61 6c 6c 40 ?? ?? 5f 4d 69 73 73 69 6f 6e 42 72 69 65 66 69 6e 67 40 ?? ?? 5f 55 6e 69 6e 73 74 61 6c 6c 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

