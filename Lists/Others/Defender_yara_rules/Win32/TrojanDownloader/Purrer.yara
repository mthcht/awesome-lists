rule TrojanDownloader_Win32_Purrer_A_2147594571_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Purrer.A"
        threat_id = "2147594571"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Purrer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a 00 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65}  //weight: 1, accuracy: High
        $x_1_2 = {68 80 00 00 00 f3 ab 66 ab aa 8d 45 80 33 f6 50 6a 0a 68 00 04 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8a 5d 0c 83 c6 04 32 d8 8b 06 88 19 41 83 f8 ff 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

