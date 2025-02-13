rule TrojanDownloader_Win32_Asune_F_2147602652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Asune.F"
        threat_id = "2147602652"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Asune"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 ea 69 05 ?? ?? ?? ?? e8 03 00 00 46 89 04 24 e8 ?? ?? 00 00 83 ec 04 3b 35 ?? ?? ?? ?? 72 bc 8d 65 f8 31 c0 5b 5e 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 63 6f 6d 6d 83 ec 0c 89 85 ?? ?? ff ff b9 2f 63 20 64 ba 65 6c 20 00 89 8d ?? ?? ff ff b8 61 6e 64 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 04 38 5c 63 6c 2e ba 6c 6f 67 00 89 54 38 04 b8 ?? ?? ?? ?? 89 44 24 04 89 3c 24 e8 ?? ?? 00 00 85 c0 89 c6 0f 84 ?? ?? ff ff 89 34 24 b8 02 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 04 30 26 75 69 64 b9 ?? ?? ?? ?? 66 c7 44 30 04 3d 00 89 4c 24 04 89 34 24 e8 ?? ?? 00 00 89 34 24 e8 ?? ?? 00 00 c7 04 30 26 74 73 75 ba 69 64 3d 00}  //weight: 1, accuracy: Low
        $x_1_5 = {72 74 64 25 75 00 74 64 25 75 00 72 74 77 25 75 00 74 77 25 75 00 74 6d 25 75 00 72 74 6d 25 75 00 6d 6f 64 65 6d 00}  //weight: 1, accuracy: High
        $x_1_6 = {61 68 72 75 69 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

