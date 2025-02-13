rule TrojanDownloader_Win32_Bumoru_A_2147726392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bumoru.A"
        threat_id = "2147726392"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bumoru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 70 00 75 00 62 00 70 00 72 00 6e 00 2e 00 76 00 62 00 73 00 [0-32] 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 [0-32] 20 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 70 00 75 00 62 00 70 00 72 00 6e 00 2e 00 76 00 62 00 73 00 [0-32] 20 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 [0-32] 20 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

