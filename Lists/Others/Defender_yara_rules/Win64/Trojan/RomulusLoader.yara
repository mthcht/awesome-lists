rule Trojan_Win64_RomulusLoader_DA_2147974873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RomulusLoader.DA!MTB"
        threat_id = "2147974873"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RomulusLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 b5 b8 06 a4 75 65 f4 30 d3 9a 48 2c 2a f5 6a 47 04 cf 33 50 8d c2 98 9c e8 93 e2 91 c9 ab a4 9c e1 9d 0c 50 32 f0 3d a3 f0 6c 5f 79 85 bb 52 05 70 7c 10 6d a5 90 ab 0e 55 c0 fc 87 aa 49 88 c8 de 6b 28 2e c3 97 30 ec d6 e3 f4}  //weight: 1, accuracy: High
        $x_1_2 = {3f 5f dc d4 99 ac ad d7 af 4b 9a 82 75 22 86 9c 38 25 12 0b dd 38 ea 7a dc 91 8b 49 c1 49 a4 fa c6 5c d4 dd 2b 91 75 11 1c d1 be eb d4 c8 c1 38 80 c4 5b b1 9c 31 a4 1f 6b d7 d1 e2 78 de 96 fe e4 d9 99 28 d7 60 ce 82 da f9 85 56}  //weight: 1, accuracy: High
        $x_1_3 = {67 6b 23 43 ea fa d5 6c f2 43 f5 58 f4 f1 91 bb 2a 3e 7e cb 87 49 93 91 17 4a 9e c5 67 34 da fa 60 6b d8 f5 0c 11 ee 62 af af 0a 93 4c 65 22 66 9d 30 a7 e7 5b dc 40 b8 59 78 0f c2 e6 42 a0 56 8d d8 b3 4a 50 2b e0 c3 f4 1b 5a e6 35 8f b8 82 4a d1 90 b3 49 44 2c 2e b5 b5 8f fa}  //weight: 1, accuracy: High
        $x_1_4 = {4b 4d 6d f1 c7 18 92 72 ac 2d 85 7d 04 66 98 63 64 1c 4a cc 4e 08 27 4f f6 5c 6a 40 95 e9 36 8e f6 d5 d2 7c cc b9 1e ce 1a ab dd 30 1e f7 8b 08 e1 ae 5a a4 fa 9e 85 17 d9 a7 6e b7 5a 97 1e e3 d5 8d e6 e3 2b 67 fd 09 3d dc 97 4c 1a 73 8f 1d 39 88 b1 bf 69 30 42 03 d6}  //weight: 1, accuracy: High
        $x_1_5 = {aa 47 15 a3 68 be 00 05 17 bf 01 6c 49 6c 65 6e 57 41 2c 28 d8 09 56 21 50 01 23 15 76 01 42 05 dc be 97 4d 6f 64 75 1a 46 69 bf 2a 68 b7 2e 21 53 09 65 70 06 05 5d 14 14 83 73 54 05 82 fe 00 5c 4c 69 62 72 76 b6 f9 ac b5 43 38 49 4d 63 61 74 4c 6f 1b 5b b0 ae 4b 0d 43 2a 74 31 0d 57 ed ed 02 41 97 43 68 19 54 6f 4d 60 52 11 b8 f6 74 69 42 79 1a 14 8f b1 0b 04 b5 15 b4 6f 6c 6b 7b db de 6f 7f 45 6e 64 4f 66 7e 0d 48 37 70 52 65 9a b7 cd fd 05 0c 53 69 7a 16 12 6c 18 73 65 f9 cd ff f2 53 52 57 4c 6b}  //weight: 1, accuracy: High
        $x_1_6 = {17 95 a4 98 b1 dd 09 9b 41 b4 73 31 5b 74 07 bb 33 48 17 8c 31 f3 0b de e0 e5 d9 ee 64 07 32 08 07 31 32 77 40 32 cd 20 dd c9 7b 32 8c 17 f2 f4 e1 74 dd ee 84 33 c7 e4 07 e2 35 b3 d6 0b 35 6c bb 66 b9 e5 37 84 e8 07 a8 38 0b c4 db 35 db cf 07 69 39 0b f0 6c 07 3d 3a 5f 76 67 3b 73 8c d7 07 11 3b 0b 14 07 e3 3f 35 5b d3 dc 47 4c d7 3f 44 0b 6c e8 d9 76 9d db 07 55 47 77 0b 58 07 4c 4a 0b c0 b6 6b b6 9f 07 89 4b 53 14 8c 07 d7 4c 0b ae d9 76 cd 2c d8 07 0f 4f 23 1c 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

