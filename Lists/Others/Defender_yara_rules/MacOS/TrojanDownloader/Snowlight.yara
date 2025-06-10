rule TrojanDownloader_MacOS_Snowlight_A_2147943308_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Snowlight.A!MTB"
        threat_id = "2147943308"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Snowlight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 00 04 00 00 31 c9 e8 ad 03 00 00 48 8d bd e0 fb ff ff 31 f6 ba 00 04 00 00 e8 82 03 00 00 c7 85 84 e3 ff ff ff ff ff ff c7 85 80 e3 ff ff 00 00 00 00 8b bd 94 e3 ff ff 48 8d b5 e0 f7 ff ff ba 01 00 00 00 31 c9 e8 61 03 00 00 89 85 84 e3 ff ff 83 bd 84 e3 ff ff 01 0f 8d 05 00 00 00 e9 9c 00 00 00 8a 8d e0 f7 ff ff 48 63 85 80 e3 ff ff 88 8c 05 e0 f7 ff ff 48 63 85 80 e3 ff ff 0f be 84 05 e0 f7 ff ff 83 f8 0a 0f 85 59 00 00 00 8b 85 80 e3 ff ff 83 e8 01 48 98 0f be 84 05 e0 f7 ff ff 83 f8 0d 0f 85 3d 00 00 00 8b 85 80 e3 ff ff 83 e8 02 48 98 0f be 84 05 e0 f7 ff ff 83 f8 0a 0f 85 21 00 00 00 8b 85 80 e3 ff ff 83 e8 03 48 98 0f be 84 05 e0 f7 ff ff 83 f8 0d 0f 85 05 00 00 00 e9 17 00 00 00 8b 85 84 e3 ff ff 03 85 80 e3 ff ff 89 85 80 e3 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 c7 85 78 e3 ff ff 00 00 00 00 48 8b bd a8 e3 ff ff 48 8d 35 88 03 00 00 e8 65 02 00 00 48 89 85 78 e3 ff ff 48 83 bd 78 e3 ff ff 00 0f 85 4a 00 00 00 48 8d 05 69 03 00 00 48 89 85 a8 e3 ff ff 48 8b bd a8 e3 ff ff 48 8d 35 52 03 00 00 e8 2f 02 00 00 48 89 85 78 e3 ff ff 48 83 bd 78 e3 ff ff 00 0f 85 0f 00 00 00 c7 85 cc e3 ff ff 00 00 00 00 e9 67 01 00 00 e9 00 00 00 00 48 8b bd a8 e3 ff ff be c0 01 00 00 e8 d1 01 00 00 8b bd 94 e3 ff ff 48 8d b5 e0 e7 ff ff ba 00 10 00 00 31 c9 e8 06 02 00 00 89 85 84 e3 ff ff 83 bd 84 e3 ff ff 01 0f 8d 05 00 00 00 e9 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {a0 a3 5d 78 d4 00 00 94 e0 5f 00 b9 01 00 00 14 e3 3b 40 f9 ea 5f 40 b9 e8 33 40 f9 ec 6f 40 b9 eb 47 40 f9 ed 43 40 f9 ee 3f 40 f9 e9 03 00 91 2e 01 00 f9 2d 05 00 f9 2b 09 00 f9 eb 03 0c aa 6b 3d 40 92 6b 3d 40 92 2b 0d 00 f9 28 11 00 f9 e8 03 0a aa 08 3d 40 92 08 3d 40 92 28 15 00 f9 e0 07 40 91 00 60 24 91 e0 2b 00 f9 01 00 80 52 e1 47 00 b9 02 80 80 d2 e2 27 00 f9 bf 00 00 94 e3 47 40 b9 e1 2b 40 f9 e2 27 40 f9 e0 bf 40 b9 f0 00 00 94 e1 27 40 f9 e0 2b 40 f9 c0 00 00 94 08 00 80 12 e8 af 00 b9 ff ab 00 b9 01 00 00 14}  //weight: 1, accuracy: High
        $x_1_4 = {e9 4b 40 f9 e8 07 40 91 08 61 14 91 29 01 40 39 eb ab 80 b9 ea 03 08 aa 4a 01 0b 8b 49 01 00 39 e9 ab 80 b9 08 69 e9 38 08 29 00 71 61 03 00 54 01 00 00 14 e8 ab 40 b9 09 05 00 71 e8 07 40 91 08 61 14 91 08 c9 e9 38 08 35 00 71 61 02 00 54 01 00 00 14 e8 ab 40 b9 09 09 00 71 e8 07 40 91 08 61 14 91 08 c9 e9 38 08 29 00 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

