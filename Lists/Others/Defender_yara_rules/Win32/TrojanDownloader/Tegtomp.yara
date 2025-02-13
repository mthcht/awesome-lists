rule TrojanDownloader_Win32_Tegtomp_A_2147647295_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tegtomp.A"
        threat_id = "2147647295"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tegtomp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 8c 04 00 00 8d 6c 24 fc a1 ?? ?? ?? 00 33 c5 89 85 8c 04 00 00 6a 20 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 9d 0c 01 00 00 83 65 f0 00 8d 7d d0 89 5d ec e8}  //weight: 1, accuracy: High
        $x_1_3 = {33 f6 89 75 fc 56 6a 2d 8b cf 89 7d ec 89 75 f0 e8 7c 5b fd ff}  //weight: 1, accuracy: High
        $x_1_4 = {89 75 fc c7 45 f0 01 00 00 00 8a 9e ?? ?? ?? 00 56 8b cf 80 f3 49 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c4 18 c7 07 44 00 00 00 38 5d 10 74 ?? 33 c0 c7 46 4c 01 00 00 00 66 89 46 50 8b 45 cc 83 78 18 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

