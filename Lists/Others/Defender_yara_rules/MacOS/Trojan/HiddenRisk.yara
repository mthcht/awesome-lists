rule Trojan_MacOS_HiddenRisk_A_2147927316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/HiddenRisk.A!MTB"
        threat_id = "2147927316"
        type = "Trojan"
        platform = "MacOS: "
        family = "HiddenRisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 aa 37 00 00 48 8b 3d 57 9b 00 00 e8 b8 38 00 00 48 8b 35 93 9a 00 00 48 89 c7 e8 9d 38 00 00 48 89 c7 e8 a7 38 00 00 49 89 c6 4c 8b 6d 88 e8 81 37 00 00 49 89 c7 49 89 dd e8 76 37 00 00 49 89 c4 48 c7 45 b8 00 00 00 00 48 8b 35 92 9a 00 00 ?? ?? ?? ?? 4c 89 f7 4c 89 fa 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 0f 0c 00 00 be 40 00 00 00 ba 07 00 00 00 48 89 c7 e8 4b 35 00 00 49 89 c6 48 c7 40 10 01 00 00 00 48 c7 40 18 02 00 00 00 48 8b 05 a3 52 00 00 49 89 46 38 48 b8 1d 00 00 00 00 00 00 d0 49 89 46 20 ?? ?? ?? ?? ?? ?? ?? 48 b9 00 00 00 00 00 00 00 80 48 09 c1 49 89 4e 28 be 20 00 00 00 b9 0a 00 00 00 4c 89 f7 48 ba 00 00 00 00 00 00 00 e1 49 89 d0 e8 da 33 00 00 48 8b 85 70 ff ff ff 48 8b 58 08 4c 89 e7 4c 8b 7d 80}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 85 70 ff ff ff 48 8b 58 08 48 8b bd 68 ff ff ff 4c 8b 75 80 4c 89 f6 ff d3 48 8b 7d 88 4c 89 f6 ff d3 48 8b bd 60 ff ff ff ff 15 b4 54 00 00 48 8b bd 78 ff ff ff e8 7a 35 00 00 e9 b6 fb ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {fc 03 00 aa 40 00 00 d0 00 c0 3a 91 23 03 00 94 01 08 80 52 e2 00 80 52 dc 0d 00 94 fa 03 00 aa 28 00 00 90 00 21 c1 3d 00 04 80 3d 08 00 fc d2 bf 23 39 a9 b4 c3 01 d1 60 02 80 52 31 0d 00 94 a0 83 59 f8 d7 0d 00 94}  //weight: 1, accuracy: High
        $x_1_5 = {e0 03 1b aa 9a 0d 00 94 48 00 00 d0 00 e9 42 f9 24 0e 00 94 48 00 00 d0 01 8d 42 f9 1b 0e 00 94 fd 03 1d aa 28 0e 00 94 f5 03 00 aa f4 03 16 aa 92 0d 00 94 fc 03 00 aa f4 03 18 aa 8f 0d 00 94 f4 03 00 aa bf 03 19 f8 48 00 00 d0 01 a9 42 f9 a4 c3 01 d1 e0 03 15 aa e2 03 1c aa e3 03 14 aa}  //weight: 1, accuracy: High
        $x_1_6 = {48 83 f9 22 75 85 48 8d bd 21 d4 ff ff a8 01 74 07 48 8b bd 30 d4 ff ff ba 22 00 00 00 48 8d 35 23 29 00 00 e8 10 22 00 00 85 c0 0f 85 5a ff ff ff}  //weight: 1, accuracy: High
        $x_1_7 = {48 29 c4 58 49 89 f6 49 89 fc 48 8b 05 ec 2d 00 00 48 8b 00 48 89 45 d0 48 8d 3d 3f 2a 00 00 48 8d 9d c8 d3 ff ff 48 89 de 31 d2 e8 ba 23 00 00 48 8b 43 08 48 8b 30 ?? ?? ?? ?? ?? ?? ?? e8 8e 0a 00 00 48 89 df e8 a5 23 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

