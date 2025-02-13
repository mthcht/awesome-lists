rule TrojanDownloader_Win32_Dyfrop_B_2147683376_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dyfrop.B"
        threat_id = "2147683376"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyfrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 3d e4 30 41 00 23 de 27 0f 75 25 8b 15 60 30 41 00 52 8b 45 e0 50 8b 4d dc 51 8b 55 fc 52 68 c9 b0 9c 28 e8 e6 c9 ff ff 83 c4 14 89 45 c0 eb 38 83 7d 08 00 75 25 83 7d f8 00 75 1f a1 94 30 41 00 69 c0 2a 81 16 60 0f af 05 84 30 41 00 85 c0 75 09 c7 45 bc 00 00 00 00 eb 07}  //weight: 1, accuracy: High
        $x_1_2 = {68 55 38 b4 07 e8 0c 37 00 00 83 c4 08 89 45 fc 8b 4d fc 51 8b 55 0c 52 8b 45 18 50 8b 4d 10 51 68 0c da ae 50 8b 55 fc 52 e8 72 11 00 00 83 c4 18 89 45 fc 8b 45 fc 2d b8 99 4a 14 2b 05 d4 30 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

