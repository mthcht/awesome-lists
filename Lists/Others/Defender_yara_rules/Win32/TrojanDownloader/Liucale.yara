rule TrojanDownloader_Win32_Liucale_A_2147607823_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Liucale.A"
        threat_id = "2147607823"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Liucale"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 2d 8b 84 24 20 04 00 00 8d 8c 24 18 02 00 00 50 51 e8 ?? ?? ?? ?? 83 c4 08 85 c0 75 11 8d 94 24 18 02 00 00 55 52 e8 ?? ?? ?? ?? 83 c4 08 f6 46 0c 10 74 99}  //weight: 1, accuracy: Low
        $x_1_2 = {b3 0a 81 fe 00 04 00 00 7d 47 6a 00 8d 4c 24 17 6a 01 51 55 ff 15 ?? ?? ?? ?? 8a 54 24 13 88 94 34 ?? ?? 00 00 46 83 fe 04 7c d7}  //weight: 1, accuracy: Low
        $x_1_3 = "Count.Asp?a=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

