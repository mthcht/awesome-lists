rule TrojanDownloader_Win32_Halnine_B_2147665063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Halnine.B"
        threat_id = "2147665063"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Halnine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 06 d0 fa 80 e2 7f 41 88 10 8b 54 24 10 40 3b ca 72 ec}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 18 c7 44 24 14 00 00 00 00 85 c0 75 21 81 fd 00 00 02 00 b8 00 00 02 00 7f 02}  //weight: 1, accuracy: High
        $x_1_3 = {73 0e 6a 32 ff 15 28 50 40 00 ff 44 24 10 eb a7 85 c0 c7 44 24 14 00 00 00 00 0f 84 b4 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

