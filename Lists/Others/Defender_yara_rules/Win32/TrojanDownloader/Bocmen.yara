rule TrojanDownloader_Win32_Bocmen_A_2147602125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bocmen.A"
        threat_id = "2147602125"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bocmen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 3a 5c 62 6f 6f 74 2e 62 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 73 79 73 74 65 6d 33 32 5c 4d 69 63 72 6f 73 6f 66 74 5c 73 76 63 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 6f 74 63 6d 64 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 4e 44 66 69 6c 65 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 6f 73 3d 4d 61 63 58 50 57 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

