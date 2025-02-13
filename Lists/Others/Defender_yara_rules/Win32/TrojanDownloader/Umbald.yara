rule TrojanDownloader_Win32_Umbald_A_2147650391_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Umbald.A"
        threat_id = "2147650391"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Umbald"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 6f 00 64 00 65 00 3d 00 [0-2] 26 00 55 00 49 00 44 00 3d 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 6f 64 65 3d [0-2] 26 55 49 44 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 6f 77 6e 6c 6f 61 64 26 45 78 65 63 75 74 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 6c 75 67 69 6e 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 50 61 6e 65 6c 2f 62 6f 74 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

