rule TrojanDownloader_Win32_Gojalda_A_2147652748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gojalda.A"
        threat_id = "2147652748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gojalda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 ec 4d c6 45 ed 41 c6 45 ee 6f c6 45 ef 67 c6 45 f0 61 c6 45 f1 65}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 08 03 55 fc 0f be 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c6}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 d4 53 c6 45 d5 68 c6 45 d6 65 c6 45 d7 6c c6 45 d8 6c c6 45 d9 45 c6 45 da 78}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 f8 50 c6 45 f9 4f c6 45 fa 53 c6 45 fb 54 c6 45 fc 00 68}  //weight: 1, accuracy: High
        $x_1_5 = {2b 44 24 04 c6 01 e9 83 e8 05 8b d0 c1 ea 08 88 51 02 8b d0 88 41 01 c1 ea 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

