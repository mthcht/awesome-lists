rule TrojanDownloader_Win32_Jubxi_B_2147609018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jubxi.B"
        threat_id = "2147609018"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jubxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 5c 25 30 38 58 00 43 3a 5c 25 30 38 58 00 5f 5f 4e 42 41 5f 4d 55 54 45 58 5f 5f}  //weight: 1, accuracy: High
        $x_1_2 = {43 6f 6d 6d 6f 6e 20 53 74 61 72 74 75 70 00 00 53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73}  //weight: 1, accuracy: High
        $x_1_3 = {42 65 65 70 00 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 69 6e 74 61 72 6f 6f 2e 6e 65 74 2f}  //weight: 1, accuracy: High
        $x_1_4 = {54 48 49 4e 4b 00 00 00 5c 44 72 69 76 65 72 73 5c 42 65 65 70 2e 73 79 73 00 00 00 5c 5c 2e 5c 4e 42 41 5f 53 4f 46 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

