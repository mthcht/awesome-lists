rule TrojanDownloader_Win32_Phabeload_A_2147708346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phabeload.A"
        threat_id = "2147708346"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phabeload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {8b 45 fc 0f b7 00 85 c0 75 04 33 c0 eb 28 8b 45 fc 2d ?? ?? 40 00 d1 e8 8b 4d f8 8b 55 08 66 8b 04 45 ?? ?? 40 00 66 89 04 4a 8b 45 f8 40 89 45 f8 eb}  //weight: 8, accuracy: Low
        $x_8_2 = {8b 45 fc 8b 4d 08 66 8b 14 41 b9 ?? ?? 40 00 e8 ?? ?? ?? ?? 89 45 f8 83 7d f8 00 75 04 33 c0 eb 21 8b 45 f8 2d ?? ?? 40 00 d1 e8 8b 4d fc 8b 55 08 66 8b 04 45 c8 34 40 00 66 89 04 4a eb}  //weight: 8, accuracy: Low
        $x_1_3 = {b9 00 01 80 00 b8 ?? ?? ?? ?? 0f 45 c1 50 53 53 53 ff 75 ?? 68 ?? ?? ?? ?? ff 75 ?? ff 15 ?? ?? ?? ?? 89 45 f4 85 c0 0f 84 ?? ?? ?? ?? 38 5d ff 74 16 6a 04 8d 4d ?? c7 45 ?? 00 33 00 00 51 6a 1f 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 00 01 80 00 b8 ?? ?? ?? ?? 0f 45 c2 50 53 53 53 ff 75 ?? 68 ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 8b f0 85 f6 0f 84 ?? ?? ?? ?? 38 5d ff 74 16 6a 04 8d 45 ?? c7 45 ?? 00 33 00 00 50 6a 1f 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_1_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}

