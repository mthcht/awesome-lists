rule TrojanDownloader_Win32_Flirtip_A_2147651924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Flirtip.A"
        threat_id = "2147651924"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Flirtip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 06 ff 50 04 8b 7d 10 8b 45 0c 8b 0e 8d 55 e0 52 57 50 56 89 5d e8 89 5d e4 89 5d e0 ff 91 ?? ?? ?? ?? 3b c3 7d 12}  //weight: 2, accuracy: Low
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 77 00 2e 00 71 00 71 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 70 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 46 00 69 00 6c 00 74 00 65 00 72 00 46 00 69 00 6c 00 65 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 68 65 63 6b 50 45 46 69 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

