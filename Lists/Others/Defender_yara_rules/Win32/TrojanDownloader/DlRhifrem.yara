rule TrojanDownloader_Win32_DlRhifrem_A_2147601497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/DlRhifrem.gen!A"
        threat_id = "2147601497"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "DlRhifrem"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d c8 00 00 00 0f 85 ?? ?? 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 10 02 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 02 00 00 00 c7 44 24 04 00 00 00 40 [0-6] 89 04 24 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {7d 3b 8b 45 ?? 03 45 e8 fe 08 8b 45 ec 8b 4d e8 01 c1 8b 45 08 8b 5d e8 01 c3 8b 55 e8 8d 45 f0 89 45 e4 89 d0 8b 75 e4 99 f7 3e 8b 45 0c 0f b6 04 10 32 03 88 01 8d 45 e8 ff 00 eb bd}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 ?? ?? ?? 0c 61 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_DlRhifrem_B_2147609264_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/DlRhifrem.gen!B"
        threat_id = "2147609264"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "DlRhifrem"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c7 45 f0 00 00 00 00 81 7d f0 ?? ?? 00 00 7f 1e 8b 45 f0 05 ?? ?? ?? ?? 80 38 ff 74 0a 8b 45 f0 05 ?? ?? ?? ?? fe 08 8d 45 f0 ff 00 eb d9 c7 44 24 10 00 00 00 00 8d 45 f8}  //weight: 3, accuracy: Low
        $x_1_2 = {c7 44 24 10 00 00 00 00 89 44 24 0c 8b 45 0c 89 44 24 08 8b 45 f4 89 44 24 04 8b 45 fc 89 04 24 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {89 44 24 10 89 54 24 0c c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 8b 45 fc 89 04 24 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 73 69 65 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 64 6f 62 65 20 41 63 72 6f 62 61 74 20 52 65 61 64 65 72 28 74 6d 29 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

