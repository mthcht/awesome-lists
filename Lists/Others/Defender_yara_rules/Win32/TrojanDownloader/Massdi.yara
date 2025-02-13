rule TrojanDownloader_Win32_Massdi_C_2147645961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Massdi.C"
        threat_id = "2147645961"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Massdi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 77 77 77 31 2e 65 2d 73 6f 73 6f 2e 63 6f 6d 2f 70 6f 70 2f 67 75 61 67 75 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 31 2e 65 2d 73 6f 73 6f 2e 63 6f 6d 2f 74 6a 2f 54 4a [0-5] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 41 62 6f 72 74 5d 20 b7 c5 c6 fa b0 b2 d7 b0 a3 ac 0d 0a 20 5b 52 65 74 72 79 5d 20 d6 d8 d0 c2 b3 a2 ca d4 d0 b4 c8 eb ce c4 bc fc fe a3 ac bb f2 0d 0a 20 5b 49 67 6e 6f 72 65 5d 20 ba f6 c2 d4 d5 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

