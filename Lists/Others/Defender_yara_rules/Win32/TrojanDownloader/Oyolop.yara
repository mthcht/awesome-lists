rule TrojanDownloader_Win32_Oyolop_A_2147656965_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Oyolop.A"
        threat_id = "2147656965"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Oyolop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f4 c1 e1 06 89 4d f4 90 90 90 8b 55 fc 0f be 42 02 83 f8 3d}  //weight: 1, accuracy: High
        $x_1_2 = {b9 09 00 00 00 33 c0 8d bd 09 70 ff ff f3 ab 66 ab aa 8d 85 00 a0 ff ff 50}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 f4 c1 e0 06 89 45 f4 8b 4d fc 8a 51 01 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

