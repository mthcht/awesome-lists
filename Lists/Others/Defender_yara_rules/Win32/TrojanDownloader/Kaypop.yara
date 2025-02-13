rule TrojanDownloader_Win32_Kaypop_A_2147683582_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kaypop.A"
        threat_id = "2147683582"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kaypop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {53 6f 66 74 77 61 72 65 5c 62 6b 70 6f 70 65 00}  //weight: 5, accuracy: High
        $x_1_2 = {73 74 65 61 6d 73 65 00 70 70 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 64 6f 77 6e 6c 6f 61 64 5f 76 69 65 77 2f 00 2f 64 61 74 61 2f 66 69 6c 65 73 2f 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 4d 41 43 3d 25 73 26 69 50 49 44 3d 25 73 26 6d 6f 64 65 41 63 74 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 25 64 2f 6c 6f 67 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

