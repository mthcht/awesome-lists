rule TrojanDownloader_Win32_Chevaloi_A_2147599223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chevaloi.A"
        threat_id = "2147599223"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chevaloi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 76 6d 63 5f 74 65 72 6d [0-16] 72 75 6e 64 6c 6c 33 32 2e 65 78 65 [0-16] 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_2 = {4d 6f 7a 69 6c 6c 61 55 49 57 69 6e 64 6f 77 43 6c 61 73 73 [0-16] 64 6c 6c 5f 69 6e 6a 65 63 74}  //weight: 2, accuracy: Low
        $x_2_3 = {66 69 72 65 66 6f 78 2e 65 78 65 00 62 75 74 74 6f 6e [0-16] 22 25 73 22 20 2d 6e 65 77 2d 77 69 6e 64 6f 77}  //weight: 2, accuracy: Low
        $x_1_4 = {73 65 72 76 69 63 65 73 2e 65 78 65 00 00 00 00 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_5 = "http://%s:%i%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

