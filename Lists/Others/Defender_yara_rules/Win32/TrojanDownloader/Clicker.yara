rule TrojanDownloader_Win32_Clicker_B_2147659439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Clicker.B"
        threat_id = "2147659439"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Clicker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 45 47 49 4e 00 00 00 31 00 00 00 54 59 50 45 00 00 00 00 63 6c 69 63 6b 3d 25 73 0a 00 00 00 43 4c 49 43 4b 00 00 00 52 6f 6f 74 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 5b 66 66 7d 54 04 03 5c 5b 45 34 61 7d 7d 79 33 26 26}  //weight: 1, accuracy: High
        $x_1_3 = {04 03 4a 45 40 4a 42 34 (04 03 5d 50 59|61 7d 7d 79 33)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

