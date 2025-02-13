rule TrojanDownloader_Win32_Trotoawny_2147633894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Trotoawny"
        threat_id = "2147633894"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Trotoawny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 75 6c 6c 73 6f 66 74 [0-18] 76 32 2e 34 36}  //weight: 1, accuracy: Low
        $x_1_2 = {fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 6d 6f 64 72 69 74 65 2e 69 6e 66 6f 2f [0-6] 2f [0-6] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

