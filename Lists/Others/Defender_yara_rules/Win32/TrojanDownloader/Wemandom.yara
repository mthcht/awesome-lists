rule TrojanDownloader_Win32_Wemandom_A_2147644304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wemandom.A"
        threat_id = "2147644304"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wemandom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 31 33 30 38 30 2f 31 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {3a 31 33 30 38 30 2f 79 6b 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {3a 31 33 30 38 30 2f 71 71 2f 51 51 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {77 69 6e 64 6f 77 73 5c 61 61 65 6d 6d 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 69 6e 64 6f 77 73 5c 61 61 65 6d 6d 61 31 31 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {77 69 6e 64 6f 77 73 5c 65 6d 6d 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

