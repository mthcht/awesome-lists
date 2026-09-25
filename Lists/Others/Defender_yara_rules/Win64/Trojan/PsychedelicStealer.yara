rule Trojan_Win64_PsychedelicStealer_DA_2147978860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PsychedelicStealer.DA!MTB"
        threat_id = "2147978860"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PsychedelicStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {49 b5 f4 3a 9b b6 49 48 38 1e 86 96 f3 8e 0c 71 4c 82 56 2f ae 6d 75 9c e9 92 67 7b 8f 4d 78 47 40 84 5d 17 82 ef be f2 05 07 b8 c2 c9 31 77 34 4f 81 b7 44 ff 77 79 52 2b 8b 20 f5 1b 5f 29 92 49 b5 f4 3a 9b b6 49 48 38 cf be 3a 46 0d 41 7f 40 8a f5 0d f3 5a 00 5c c8 4e cb 49 a9 f9 c4 c4 44 b2 13 6b f8 aa 9a c6 9c}  //weight: 10, accuracy: High
        $x_10_2 = {8d 47 00 13 9e 5a 00 0f af 69 00 1c c0 85 00 1e d1 a3 00 1d e2 c0 00 1e f3 de 00 2c 04 0a 01 0e 15 18 01 0b 26 23 01 06 37 29 01 0d 48 36 01 0a 59 40 01 09 6a 49 01 17 7b 60 01 07 8c 67 01 07 9d 6e 01 0c ae 7a 01 0a bf 84 01 20 d0 a4 01 20 e1 c4 01 20 f2 e4 01 20 03 04 02 20 14 24 02 20 25}  //weight: 10, accuracy: High
        $x_10_3 = {51 23 26 93 94 55 50 b1 52 b6 61 8b b5 23 ef 22 42 07 2f f4 e6 2a d9 ad f8 5d 4b 76 ab 9e 8a 5c 5d 09 29 a2 eb 72 b0 78 1d 1e bb aa fc 6c e8 bd ba 8e d9 2b 1c e6 47 cf 2b 76 43 f5 bf c8 80 1b c6 3a 80 e4 81 0e 60 a9 d1 84 c9 23 c1 25 2f 45 15 92 92 39 b1 43 2c b7 02 55 71 fe}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

