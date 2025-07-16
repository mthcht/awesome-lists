rule TrojanDownloader_Linux_Snowlight_A_2147946395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/Snowlight.A!MTB"
        threat_id = "2147946395"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "Snowlight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 57 41 89 ff 41 56 49 89 f6 41 55 49 89 d5 41 54 4c 8d 25 f0 01 20 00 55 48 8d 2d f0 01 20 00 53 4c 29 e5 31 db 48 c1 fd 03 48 83 ec 08 e8 0d fc ff ff 48 85 ed 74 1e 0f 1f 84 00 00 00 00 00 4c 89 ea 4c 89 f6 44 89 ff 41 ff 14 dc 48 83 c3 01 48 39 eb 75 ea}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 b9 00 04 00 00 48 89 ef f3 ab 89 df e8 e4 fd ff ff 48 8b 15 bd 05 20 00 48 8d 74 24 08 44 89 e7 31 c0 48 c7 44 24 08 3d 0b 40 00 48 c7 44 24 10 00 00 00 00 e8 fc fd ff ff 48 81 c4 50 10 00 00 31 c0 5b 5d 41 5c c3 31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 49 c7 c0 20 0b 40 00 48 c7 c1 b0 0a 40 00 48 c7 c7 00 08 40 00 e8 95 fd ff ff f4 0f 1f 40 00 b8 47 0f 60 00 55 48 2d 40 0f 60 00 48 83 f8 0e 48 89 e5 76 1b b8 00 00 00 00 48 85 c0 74 11 5d bf 40 0f 60 00 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

