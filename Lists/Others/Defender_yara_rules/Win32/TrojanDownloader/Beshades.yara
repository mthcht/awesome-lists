rule TrojanDownloader_Win32_Beshades_A_2147655205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Beshades.A"
        threat_id = "2147655205"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Beshades"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 25 49 92 24 f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 04 8d 14 c5 00 00 00 00 2b d0 03 d2 03 d2 b8 90 a1 41 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 b0 a1 41 00 ff 15 8c f0 41 00 6a 00 68 00 00 00 80 6a 00 6a 00 8b f8 55 57 89 7c 24 30 ff 15 90 f0 41 00 6a 01 8b d8 ff 15 14 a0 41 00 85 ff 74 c6 85 db 74 c2 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

