rule Trojan_Linux_SNOWLIGHT_DA_2147975104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SNOWLIGHT.DA!MTB"
        threat_id = "2147975104"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SNOWLIGHT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 10 00 00 00 00 e8 84 fd ff ff 48 81 c4 58 14 00 00 31 c0 5b 5d 41 5c 41 5d c3 31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 49 c7 c0 c0 0c 40 00 48 c7 c1 50 0c 40 00 48 c7 c7 50 09 40 00 e8 1b fd ff ff f4 66 2e 0f 1f 84 00 00 00 00 00 b8 af 12 60 00 55 48 2d a8 12 60 00 48 83 f8 0e 48 89 e5 76 1b b8 00 00 00 00 48 85 c0 74 11 5d bf a8 12 60 00 ff e0 66 0f}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 75 0a 83 ec 0c 6a 00 e8 d3 fe ff ff b8 21 00 00 00 8d bd c7 eb ff ff 89 c1 be 8c 8a 04 08 f3 a4 83 ec 0c 89 c8 8d bd b4 eb ff ff b1 04 8d b5 c7 eb ff ff f3 ab 56 66 c7 85 b4 eb ff ff 02 00 66 c7 85 b6 eb ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {63 03 a9 94 00 00 b0 98 00 00 b0 18 03 00 91 94 22 00 91 94 02 18 cb 94 fe 43 93 f5 5b 02 a9 f7 03 00 2a f6 03 01 aa f5 03 02 aa 13 00 80 d2 b1 fe ff 97 34 01 00 b4 03 7b 73 f8 e0 03 17 2a e1 03 16 aa}  //weight: 1, accuracy: High
        $x_1_4 = {fc ff ff 48 81 c4 38 1c 00 00 31 c0 5b 5d 41 5c 41 5d c3 31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 49 c7 c0 80 0d 40 00 48 c7 c1 10 0d 40 00 48 c7 c7 a0 09 40 00 e8 97 fc ff ff f4 66 0f 1f 44 00 00 b8 b7 12 60 00 55 48 2d b0 12 60 00 48 83 f8 0e 48 89 e5 76 1b b8 00 00 00 00 48 85 c0 74 11 5d bf b0 12 60 00 ff e0}  //weight: 1, accuracy: High
        $x_1_5 = {1f d6 90 00 00 b0 11 46 41 f9 10 22 0a 91 20 02 1f d6 90 00 00 b0 11 4a 41 f9 10 42 0a 91 20 02 1f d6 90 00 00 b0 11 4e 41 f9 10 62 0a 91 20 02 1f d6 90 00 00 b0 11 52 41 f9 10 82 0a 91 20 02 1f d6 90 00 00 b0 11 56 41 f9 10 a2 0a 91 20 02 1f d6 90 00 00 b0 11 5a 41 f9 10 c2 0a 91 20 02 1f d6 ff 07 40 d1 00 00 00 90 ff 03 31 d1 00 20 3a 91 fd 7b bd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

