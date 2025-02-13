rule Trojan_Win64_Meduza_RPX_2147893309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meduza.RPX!MTB"
        threat_id = "2147893309"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meduza"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 6e 3c 49 03 ee 81 7d 00 50 45 00 00 74 0a b8 fe ff ff ff e9 20 02 00 00 48 89 7c 24 48 48 8d 94 24 40 07 00 00 48 89 74 24 40 45 33 c9 4c 89 bc 24 70 19 00 00 45 33 c0 45 33 ff 33 c9 4c 89 7c 24 38 4c 89 7c 24 30 c7 44 24 28 04 00 00 00 c7 44 24 20 01 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {49 8b df 66 44 3b 7d 06 73 4c 49 8b f7 49 63 46 3c 48 8b 0f 48 03 c6 4c 89 7c 24 20 46 8b 84 30 1c 01 00 00 42 8b 94 30 14 01 00 00 4d 03 c6 48 03 54 24 50 46 8b 8c 30 18 01 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Meduza_ZY_2147926275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meduza.ZY!MTB"
        threat_id = "2147926275"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meduza"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {38 65 03 fa 61 03 38 c1 02 60 69 03 44 6d 03 c2 79 03 c8 85 03 6d 02 89 03 3e 8d 03 22 95 03 70 99 03 42 9d 03 26 99 03 1a a1 03 c6 a9 03 6c 99 03 94 b1 03 2c 99 03 20 b5 03 c6 bd 03 84 99 03 15 04 d5 03 5a 99 03 1c 95 03 2c 89 03 1c 85 03 3e 79 03 a4 6d 03 a4 c1 02 e4 b5 02 8a a9 02 8a a1 02 88 8c 18 38 b2 06 b2 00 3d 02 06 0c 10 0c 06 0c 38 0c 10 3a 3e 2e 4c 20 56 0c 8c 0c 38 3a 9c 0c ac 00 ca 40 cb 62 0b e0 cc 24 ee 25 4b 80 c8 c0 cc 20 cb 61 ea 82 ea 43 af a0 cf e2 e1 90 22 02 90 20 c3 10 24 e7 10 25 41 d0 20 c1 90 21 e3 10 20 c8 c0 cf a3 a9 c0 ca 00 ca 40 cb 62 0b e0 cc 24 ee 25 4b 80 c8 c0 cc 20 cb 61 ea 82 ea 43 aa 50 22 ec 90 22 cd 02 24 e9 02 20 fd 02 0c 65 03 20 69 03 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

