rule TrojanDownloader_Win32_Tecstech_A_2147724557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tecstech.A!bit"
        threat_id = "2147724557"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tecstech"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Server File Downloader" wide //weight: 1
        $x_2_2 = {74 00 65 00 63 00 2e 00 69 00 6c 00 69 00 6f 00 73 00 74 00 65 00 63 00 68 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_3 = "aHR0cDovL3RlYy5pbGlvc3RlY2hzLmNvbS9wYXQxMDEwLmV4ZQ==" wide //weight: 2
        $x_1_4 = {54 69 6d 65 72 31 00 00 54 69 6d 65 72 32 00 00 54 69 6d 65 72 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

