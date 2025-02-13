rule TrojanDownloader_Win32_Yorobun_A_2147652038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Yorobun.A"
        threat_id = "2147652038"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Yorobun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 f8 d0 07 00 00 ff 15 08 10 40 00 ff 75 0c 8d 85 9c fe ff ff 50 ff 15 0c 10 40 00}  //weight: 5, accuracy: High
        $x_5_2 = {ff 15 2c 10 40 00 8b 3d 30 10 40 00 6a 04 89 45 08 8d 45 f8 50 6a 02 ff 75 0c ff d7}  //weight: 5, accuracy: High
        $x_5_3 = {ff 15 34 10 40 00 85 c0 74 2a 56 8d 45 f0 50 ff 75 fc 8d 85 9c fd ff ff 50 ff 75 f4 ff 15 14 10 40 00 6a 40 33 c0 39 75 fc 59 8d bd 9c fd ff ff f3 ab 75 bd}  //weight: 5, accuracy: High
        $x_5_4 = {ff 15 00 10 40 00 53 89 45 0c ff d7 81 7d 0c 01 04 00 00 73 0d 8d 85 9c fe ff ff 50 ff 15 1c 10 40 00 81 7d 0c 00 04 00 00 76 2d}  //weight: 5, accuracy: High
        $x_1_5 = {6d 76 63 62 6e 64 64 67 66 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {79 77 65 72 72 74 79 65 72 77 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {6a 79 68 67 6a 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {6d 68 67 66 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {6b 79 67 68 6a 64 72 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {79 72 65 74 67 74 79 72 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_3_11 = {2e 69 6e 66 6f 2f 3f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 [0-10] 2e 65 78 65 00}  //weight: 3, accuracy: Low
        $x_1_12 = "vgregwr.exe" ascii //weight: 1
        $x_1_13 = "bgdfcffc.exe" ascii //weight: 1
        $x_1_14 = "dwtetevf.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Yorobun_B_2147697392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Yorobun.B"
        threat_id = "2147697392"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Yorobun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://104.200.78.119/" ascii //weight: 2
        $x_1_2 = {62 68 74 79 64 72 68 62 74 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 72 79 65 68 72 65 74 67 77 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 67 64 66 63 66 66 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 77 74 65 74 65 76 66 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {76 67 72 65 67 77 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {76 2d 6a 10 59 33 c0 c7 45 9c 44 00 00 00 8d 7d a0}  //weight: 1, accuracy: High
        $x_1_8 = {6a 04 8d 45 f8 50 6a 05 ff 75 0c ff d7 56 68 80 00 00 00 6a 04 56 6a 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

