rule Trojan_Win64_RedlineStealer_NIT_2147954383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedlineStealer.NIT!MTB"
        threat_id = "2147954383"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 05 55 c0 0b 00 4a 8b 04 28 48 01 d8 ff d0 48 8b 05 45 c0 0b 00 48 b9 ba 0f 32 1c 7a 84 e8 c0 48 8b 04 08 48 01 d8 48 8d 8c 24 b8 00 00 00 ff d0 48 8b 0d 23 c0 0b 00 48 ba e2 10 32 1c 7a 84 e8 c0 4c 8b 0c 11 49 01 d9 48 89 c1 48 89 b4 24 90 00 00 00 48 89 f2 49 89 f8 41 ff d1 48 8b 05 f7 bf 0b 00 4a 8b 04 28 48 01 d8}  //weight: 2, accuracy: High
        $x_3_2 = {48 89 c5 48 8b 05 e4 bd 0b 00 48 8b 04 30 48 01 d8 ff d0 48 8b 0d d4 bd 0b 00 48 ba f2 0f 32 1c 7a 84 e8 c0 4c 8b 14 11 49 01 da 48 8d 4c 24 58 48 89 4c 24 48 48 8d 8c 24 d0 00 00 00 48 89 4c 24 40 48 89 44 24 38 48 89 6c 24 30 c7 44 24 28 04 00 00 00 c7 44 24 20 01 00 00 00 4c 89 f1 4c 89 fa 49 be 92 0f 32 1c 7a 84 e8 c0 4d 89 e0 49 89 fc 4d 89 e9 41 ff d2 31 c9 85 c0 0f 94 c1 c1 e1 05 48 81 c9 88 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

