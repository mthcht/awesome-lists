rule Adware_AndroidOS_Zadmo_A_346678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Zadmo.A!MTB"
        threat_id = "346678"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Zadmo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 54 a0 d9 51 df 47 ab 4a de 50 f7 3c ca 19 60 d9 56 93 09 a4 31 47 25 4b cc b1 54 8e 9a c2 2e c7 9d 3a 68 3b ae 1b 13 30 c2 47 2a 13 80 dd 13 f0 e4 7b c4 13 79 ec 3a 8d b1 7c e7 4b 71 d4 4e 5d a3 c2 5f ab 1e 49 ea e1 52 8f 6b 28 82 6b 09 93 08 5d 6a 25 60 c8 38 e8 87 94 a8 8f c6 d1 ec 27 3c 3d 2a f8 72 5d f7 cc 31}  //weight: 1, accuracy: High
        $x_1_2 = {44 40 08 9d eb 18 1b 19 79 4c 1b 19 f3 41 1c 18 01 b4 08 bc 53 40 63 40 14 9d 69 18 c9 18 75 4b c9 18 f9 41 09 19 c3 43 0b 43 63 40 0d 9d aa 18 d2 18 71 4b d2 18 1a 23 04 93 da 41 52 18 e3 43 13 43 4b 40 09 9d 28 18 c0 18 6c 4b c0 18 16 23 03 93 d8 41 83 18 c8 43 18 43 50 40 06 9d 2c 19 20 18 67 4c 00 19 11 24 09 94 e0 41 c4 18 d0 43 20 43 58 40 0c 9f 79 18 08 18 62 49 40 18 0b 26 f0 41 0d 96 07 19 d8 43 38 43 60 40 07 99 8a 18 10 18 5d 4a 80 18 04 99 c8 41 c2 19 e0 43 10 43 78 40 0f 99 cb 18 18 18 58 4b c0 18 03 9d e8 41 83 18 f8 43 18 43 50 40 0a 99 0c 19 20 18 54 4c 00 19 09 99 c8 41 c4 18 d0 43 20 43 58 40 12 99 cf 19 38 18 4f 4f c0 19 f0 41 07 19 d8 43 38 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Adware_AndroidOS_Zadmo_B_346679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Zadmo.B!MTB"
        threat_id = "346679"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Zadmo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 70 20 8d f8 68 71 8d f8 69 41 69 24 8d f8 6a 71 8d f8 6b 31 8d f8 6c 21 8d f8 6d b1 4f f0 2d 0b 8d f8 6e 21 8d f8 6f 61 8d f8 70 51 63 25 8d f8 71 c1 8d f8 72 31 8d f8 73 01 8d f8 74 e1 4f f0 76 0e 8d f8 88 81 4f f0 64 08 8d f8 75 41 8d f8 76 e1 8d f8 77 b1 4f f0 68 0b 8d f8 48 51 36 25 8d f8 49 b1 8d f8 4a c1 8d f8 4b 91 8d f8 4c 81 8d f8 4d 71 8d f8 4e 51 34 25 8d f8 4f 51 8d f8 50 51 79 25 8d f8 51 71 8d f8 52 31 8d f8 53}  //weight: 1, accuracy: High
        $x_1_2 = {44 5b 87 9a 36 d0 86 f8 4c b9 ea 80 fc 5e 5e 76 6a c1 40 ae e3 6a e4 70 0a f6 92 74 67 d8 73 91 b6 89 72 9c d5 e8 87 71 cc 49 09 7a ce d1 76 52 9a 73 a1 b3 15 5a 17 6b 58 7b da 54 ed 6e f4 e8 e3 3c 3b 8c 85 46 2a f8 0f f2 da c0 5a b9}  //weight: 1, accuracy: High
        $x_1_3 = {ea d8 99 b9 0c f1 9f 38 93 97 85 d9 69 90 be 9f 8f 2f 61 4b 0d 98 91 ff 28 66 46 e0 a6 b2 95 fc 5b c3 1f d7 5c 51 02 88 5e e9 3a 34 23 90 7c 6d d9 2b a2 41 b2 1b ca 9a d2 e7 e0 b5 b9 6f f0 ee d4 4b 11 3f 2c e5 35 09 29 ef 8f bd 2a d2 8e 63 b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Adware_AndroidOS_Zadmo_C_346983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Zadmo.C!MTB"
        threat_id = "346983"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Zadmo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 04 00 4d 45 54 41 2d 49 4e 46 2f 4d 41 4e 49 46 45 53 54 2e 4d 46 fe ca 00 00 65 8d 31 0b c2 30 10 85 f7 40 fe c3 8d 8a 24 b4 0e 56 b3 d5 ba 08 8a 83 e2 2a 67 73 c5 42 9a 94 24 43 fd f7 a6 45 50 28 b7 bd f7 be ef ce 68 db 86 42 14 77 f2 a1 75 56 41 2e 33 ce 8e 5d 6f a8 23 1b 31 a6 30 95 56 3b af c0 05 e2 ac b4 7f eb b2 c7 fa 45 90 b2 04 ee e4 66 86 de da 68 e8 4b ce ac bf 97 e3 71 76 a0 41 9c 5c 3d d5 0a 6a 83 21 50 90 9a 06 ce ae 84 86 b4 82 06 cd a8 aa 3c 61 24 2d f6 ef}  //weight: 1, accuracy: High
        $x_1_2 = {41 0e d0 15 48 0e c0 15 02 46 0e cc 15 48 0e d0 15 48 0e c0 15 4d 0e c8 15 41 0e cc 15 41 0e d0 15 48 0e c0 15 43 0e c8 15 41 0e cc 15 44 0e d0 15 48 0e c0 15 47 0e c4 15 4e 0e c8 15 41 0e cc 15 42 0e d0 15 48 0e c0 15 5f 0e c4 15 41 0e c8 15 41 0e cc 15 42 0e d0 15 48 0e c0 15 43 0e c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

