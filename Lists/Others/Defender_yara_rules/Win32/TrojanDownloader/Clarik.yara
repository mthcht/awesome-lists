rule TrojanDownloader_Win32_Clarik_A_2147671590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Clarik.A"
        threat_id = "2147671590"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Clarik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 74 70 74 72 61 6e 73 66 65 72 2e ?? ?? ?? 00 4d 79 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 10, accuracy: Low
        $x_1_2 = {77 73 63 72 69 70 74 2e 65 78 65 20 22 25 73 62 62 2e 6a 73 22 00}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\intel" ascii //weight: 1
        $x_1_4 = {00 63 6c 61 72 6b 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_5 = {35 35 30 20 63 6c 61 72 6b 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 20 53 50 25 64 20 28 42 75 69 6c 64 20 25 64 29 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 6c 6f 62 61 6c 5c}  //weight: 1, accuracy: High
        $x_1_8 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

