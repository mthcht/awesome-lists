rule TrojanDownloader_Win32_Simdown_A_2147685963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Simdown.A"
        threat_id = "2147685963"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Simdown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6f 70 65 6e 00 00 00 00 ff ff ff ff 0b 00 00 00 2f 72 65 70 6f 72 74 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 35 2e 31 34 39 2e 32 34 38 2e 38 35 2f 66 6c 61 73 68 75 70 64 61 74 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 35 2e 31 34 39 2e 32 34 38 2e 38 35 2f 66 6c 61 73 68 73 65 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 74 70 3a 2f 2f 35 2e 31 34 39 2e 32 34 38 2e 38 35 2f 69 6e 66 6f 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 2f 66 6c 61 73 68 73 65 63 2e 65 78 65 00 00 00 ff ff ff ff 0d 00 00 00 2f 73 74 61 72 74 73 65 63 2e 76 62 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

