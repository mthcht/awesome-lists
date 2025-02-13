rule TrojanDownloader_MacOS_Banshee_A_2147923948_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Banshee.A!MTB"
        threat_id = "2147923948"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Banshee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 56 53 48 81 ec 80 01 00 00 48 89 f3 41 89 fe 48 8b 05 85 08 00 00 48 8b 00 48 89 45 e8 c7 85 88 fe ff ff 0b 00 00 00 8b 85 88 fe ff ff 48 83 f8 13 77 24 48 8d 0d 81 02 00 00 48 63 04 81 48 01 c8 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 0d 9f 06 00 00 48 8b 09 48 3b 4d e8 75 7a 48 81 c4 80 01 00 00 5b 41 5e 5d c3 48 b8 ce 70 a5 00 bc 05 cb 65 48 8d b5 70 fe ff ff 48 89 06 c6 46 08 6c 48 8b 1b 4c 8d b5 88 fe ff ff 4c 89 f7 e8 ec 02 00 00 41 f6 06 01 74 09 48 8b 95 98 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Banshee_B_2147933109_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Banshee.B!MTB"
        threat_id = "2147933109"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Banshee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 00 90 00 80 3d 91 dc 00 00 94 e1 a3 00 91 e0 03 14 aa 02 00 80 52 de 00 00 94 e8 01 80 52 e8 2b 00 b9 e8 2b 40 b9 1f 4d 00 71}  //weight: 1, accuracy: High
        $x_1_2 = {88 0d 80 52 e8 63 00 39 08 00 00 90 08 39 3c 91 08 01 40 f9 e8 0b 00 f9 73 02 40 f9 f4 a3 00 91 e8 a3 00 91 e0 43 00 91 65 00 00 94 e8 ff c0 39 e9 17 40 f9 1f 01 00 71 28 b1 94 9a e8 7f 00 a9 e0 03 13 aa e1 03 13 aa 9b 00 00 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

