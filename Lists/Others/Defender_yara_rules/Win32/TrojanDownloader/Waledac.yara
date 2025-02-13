rule TrojanDownloader_Win32_Waledac_C_2147800834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waledac.C"
        threat_id = "2147800834"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waledac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 54 65 6d 70 5c 5f 65 78 2d 00 00 2e 65 78 65 00 00 00 00 2f}  //weight: 1, accuracy: High
        $x_1_2 = "/coragoa2_b.exe" ascii //weight: 1
        $x_1_3 = "/patch.exe" ascii //weight: 1
        $x_1_4 = "/outlook.exe" ascii //weight: 1
        $x_2_5 = {68 00 a0 1f 00 e8 ?? ?? ff ff a3 ?? ?? ?? ?? c7 04 24 00 90 01 00 e8}  //weight: 2, accuracy: Low
        $x_2_6 = {84 c0 75 13 53 ff d7 ff 45 fc 83 7d fc 0a 7c bd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Waledac_R_2147801476_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waledac.R"
        threat_id = "2147801476"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waledac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 00 90 01 00 eb 2d 7c 56 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {50 ff 75 f8 e8 ?? ?? ?? ?? 59 59 84 c0 75 13 53 ff d7 ff 45 fc 83 7d fc 0a 7c ?? 32 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waledac_AL_2147802632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waledac.AL"
        threat_id = "2147802632"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waledac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 02 72 0d 8b 4b 0c ba 4d 5a 00 00 66 39 11 75 bf 2b 43 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d e4 81 b9 d8 01 00 00 33 27 00 00 74}  //weight: 1, accuracy: High
        $x_1_3 = {62 61 64 20 61 6c 6c 6f 63 61 74 69 6f 6e 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 57 53 41 53 6f 63 6b 65 74 41}  //weight: 1, accuracy: High
        $x_1_4 = {74 65 6d 70 00 00 00 00 2e 65 78 65 00 00 00 00 2e 00 00 00 2f [0-48] 2e 65 78 65 [0-4] 47 45 54 20 00 00 00 00 3f 00 00 00 20 48 54 54 50 2f 31 2e 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waledac_AJ_2147803952_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waledac.AJ"
        threat_id = "2147803952"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waledac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 00 00 20 00 e8 ?? ?? ff ff a3 ?? ?? ?? ?? c7 04 24 00 90 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7c 24 10 03 7d 0c 68 ?? ?? ?? ?? 8d 44 24 28 50 ff d6 ff 44 24 10 c1 6c 24 14 08 83 7c 24 10 04 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 42 01 33 d2 f7 74 24 18 39 1c 95 ?? ?? ?? ?? 74 ?? 8d 04 95 ?? ?? ?? ?? 8b 08 89 18 88 5c 24 24 33 c0 8d 7c 24 25}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 31 2e 30 0d 0a [0-16] 74 65 6d 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 ff d6 e8 ?? ?? ?? ?? 8b c8 33 c0 33 db 88 5d f0 8d 7d f1 ab ab 66 ab aa 6a 0b 8d 45 f0 50 51 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

