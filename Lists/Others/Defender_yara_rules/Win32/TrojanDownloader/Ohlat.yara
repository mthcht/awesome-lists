rule TrojanDownloader_Win32_Ohlat_A_2147678653_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ohlat.A"
        threat_id = "2147678653"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ohlat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 05 83 e8 04 8b 00 8b f0 85 f6 7e 28 bb 01 00 00 00 8d 45 f0 8b 55 fc 0f b6 54 1a ff 2b d3 2b d7 e8}  //weight: 1, accuracy: High
        $x_1_2 = {5f 6c 6c 65 69 68 42 69 6d 71 6b 7a 00}  //weight: 1, accuracy: High
        $x_1_3 = {6b 6d 6c 65 41 68 6c 70 6a 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {70 62 6b 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 6c 66 6f 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 41 74 61 6c 68 6f 5f 2e 70 69 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

