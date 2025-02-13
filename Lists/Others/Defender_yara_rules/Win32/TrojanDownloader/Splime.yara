rule TrojanDownloader_Win32_Splime_A_2147710228_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Splime.A"
        threat_id = "2147710228"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Splime"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 63 6d 64 20 2f 63 20 22 00 9d 00 [0-32] 5c 00 00 00 [0-16] 01 00 00 00 4d 00 [0-16] 01 00 00 00 69 00 [0-16] 01 00 00 00 63 00 [0-16] 01 00 00 00 72 00 [0-16] 01 00 00 00 6f 00 [0-16] 01 00 00 00 73 00 [0-16] 01 00 00 00 66 00}  //weight: 2, accuracy: Low
        $x_1_2 = {00 5c 77 69 6e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 63 6d 64 20 2f 63 20 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

