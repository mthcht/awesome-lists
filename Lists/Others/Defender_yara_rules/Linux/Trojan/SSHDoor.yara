rule Trojan_Linux_SSHDoor_D_2147846544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SSHDoor.D!MTB"
        threat_id = "2147846544"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SSHDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 18 89 f1 31 d2 ?? ?? ?? ?? ?? 64 48 8b 04 25 28 00 00 00 48 89 44 24 08 31 c0 e8 2e fc ff ff 89 c2 b8 ff ff ff ff 85 d2 0f 45 44 24 04 48 8b 54 24 08 64 48 33 14 25 28 00 00 00 75 ?? 48 83 c4 18}  //weight: 1, accuracy: Low
        $x_1_2 = {41 80 3c 24 58 0f 85 ?? ?? ?? ?? 0f 1f 44 00 00 e8 0b eb ff ff 0f b7 c8 b8 4f ec c4 4e f7 e1 b8 34 00 00 00 c1 ea 04 0f af d0 29 d1 89 ca ?? ?? ?? ?? ?? ?? 83 fa 19 0f 4f c1 41 88 04 24 49 83 ec 01 4c 39 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SSHDoor_C_2147914066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SSHDoor.C!MTB"
        threat_id = "2147914066"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SSHDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 57 41 56 49 89 f6 41 55 41 54 55 89 fd 53 48 81 ec 98 09 00 00 48 8b 3e 64 48 8b 04 25 28 00 00 00 48 89 84 24 88 09 00 00 31 c0 c7 44 24 34 01 00 00 00 c7 44 24 60 ff ff ff ff c7 44 24 64 ff ff ff ff e8 37 ae 04 00 8d 7d 01}  //weight: 1, accuracy: High
        $x_1_2 = {53 31 c9 ba 01 00 00 00 31 f6 48 89 fb 48 83 ec 10 64 48 8b 04 25 28 00 00 00 48 89 44 24 08 31 c0 e8 0a fc ff ff 31 d2 85 c0 48 0f 45 d3 48 8b 4c 24 08 64 48 33 0c 25 28 00 00 00 75 09 48 83 c4 10 48 89 d0 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SSHDoor_F_2147926258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SSHDoor.F!MTB"
        threat_id = "2147926258"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SSHDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 d3 03 b6 95 78 9e 7c 1c c4 2c 19 86 7e 6a 9e be f8 df 0f 3f 7e 96 7c c3 3b 79 1c a1 9f a9 0f 43 66 4b 10 9e fb 6e 0f a2 5a ef 90 f9 2c 58 be 41 4d 9d 7c 25 a7 1b e0 a7 9b 93 1c d1 5f 39 0f be 86 ef 0e b9 2b 6b 15 3a 0d 85 b3 50 b5 a8 10 cf 4a ae ff 08 2c ae ff cb 44 77 12 4e 69 da b0 11 89 99 7c 71 93 c5 ba 52 8c 28 21 01 23 f9 a4 ea 3d 9d 7c f9 6b 2e 8c 60 98 ef 12 49 eb db 08 cf da 93 1c 38 40 0c af 6a 65 5d 14 19 dc 77 89 0b 0f b5 a5 7d 1b 76}  //weight: 1, accuracy: High
        $x_1_2 = {66 49 49 22 c5 9f 2c fc 25 56 36 64 12 16 01 a9 ef 21 63 0f 8e 68 b0 6e bc 8b a8 af 81 74 82 0d 46 a4 81 10 6a f6 a3 b6 40 8f 1d fd 7b c7 54 d2 86 23 b6 b1 57 db 93 1c b5 e9 5a f1 36 15 15 65 72 47 9c 7c 84 9b 87 ff 95 b1 5d e0 b3 15 9a 7c 9a 91 08 ff e4 9e e0 ff 97 2b 26 fe c0 e5 95 7c d3 33 b2 a3 28 aa 3f 7e d6 0e 3f 0f 05 50 85 1b 26 76 fa 3b ef 0b 51 f9 be 27 15 36 d8 ec 70 ac 67 55 61 10}  //weight: 1, accuracy: High
        $x_1_3 = {11 0f 7d 60 9c 7c 0c df 03 ab ae 60 87 ff e6 65 84 ba ac 3a 80 0f e9 44 6d 77 cf 38 39 0f 30 20 fe 0f 4e 88 e0 09 19 d1 78 85 6a 4e c2 ba e3 ad c6 1b ef b7 06 1e 20 cf 09 fd 94 19 68 f6 c5 b9 9c 40 5c c0 09 3e 55 cc 0a 83 56 33 66 0f 47 01 75 0f 26 21 67 69 b1 b0 a8 94 8f f5 c8 87 e4 de 93 1c 2a 9e 07 fd 51 ee 11 e3 ad 70 0e af fe ec 84 14 d2 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

