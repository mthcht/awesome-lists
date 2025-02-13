rule Trojan_Win64_Shodi_A_2147922416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shodi.A!MTB"
        threat_id = "2147922416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shodi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7c 24 20 45 8b cc 45 8b c5 48 8d 15 fe 67 09 00 48 8b 0d 07 2e 0c 00 e8 fa 76 02 00 44 8b 5c 24 3c 44 89 5c 24 20 44 8b 4c 24 38 44 8b 44 24 34 48 8d 15 07 68 09 00 48 8b 0d e0 2d 0c 00 e8 d3 76 02 00 44 8b 5c 24 34 45 3b dd 0f 92 c2 45 3b dd 75 0c 44 39 64 24 38 73 05 40 8a cf eb 02 8a cb 45 3b dd 75 13 44 39 64 24 38 75 0c 44 39 7c 24 3c 73 05 40 8a c7 eb 02 8a c3 3a d3 75 1f 3a cb 75 1b 3a c3 75 17 48 8d 15 10 68 09 00 48 8b 0d 89 2d 0c 00}  //weight: 1, accuracy: High
        $x_1_2 = {e8 80 71 02 00 8b fb eb 1a 48 8d 15 b9 67 09 00 48 8b 0d 72 2d 0c 00 e8 69 71 02 00 eb 05 bf 02 00 00 00 48 8b ce ff 15 b5 c8 08 00 eb 18 48 8d 15 14 68 09 00 48 8b 0d 4d 2d 0c 00 e8 44 71 02 00 bf 02 00 00 00 44 3a f3 74 4f 3b fb 74 4b 41 83 fd 02 75 45 b9 40 08 00 00 e8 7a 19 04 00 48 89 44 24 50 48 3b c3 74 1a 4c 8d 0d 21 68 09 00 ba 03 10 00 00 44 8b c2 48 8b c8 e8 91 f3 ff ff 48 8b d8 48 89 5c 24 48 48 8d 15 ea 96 0b 00 48 8d 4c 24 48 e8 f8 74 04 00 cc 44 8b c7 48 8d 15 0d 69 09 00 48 8b 0d de 2c 0c 00 e8 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

