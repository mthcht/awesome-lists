rule Trojan_Win32_Shelcod_A_2147599231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelcod.A"
        threat_id = "2147599231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelcod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 58 58 58 58 80 e8 e7 31 c9 66 81 e9 ac fe 80 30 92 40 e2 fa 7a a2 92 92 92 d1 df d6 92 75 eb 54 eb 7e 6b 38 f2 4b 9b 67 3f 59 7f 6e a9 1c dc 9c 7e ec 4a 70 e1 3f 4b 97 5c e0 6c 21 84 c5 c1 a0 cd a1 a0 bc d6 de de 92 93 c9 c6 1b 77 1b cf 92 f8 a2 cb f6 19 93 19 d2 9e 19 e2 8e 3f 19 ca}  //weight: 1, accuracy: High
        $x_1_2 = {c1 6d a6 1d 7a 1a 92 92 92 cb 1b 96 1c 70 79 a3 6d f4 13 7e 02 93 c6 fa 93 93 92 92 6d c7 8a c5 c5 c5 c5 d5 c5 d5 c5 6d c7 86 1b 51 a3 6d fa df df df df fa 90 92 b0 83 1b 73 f8 82 c3 c1 6d c7 82 17 52 e7 db 1f ae b6 a3 52 f8 87 cb 61 39 54 d6 b6 82 d6 f4 55 d6 b6 ae 93 93 1b ce b6 da 1b}  //weight: 1, accuracy: High
        $x_1_3 = {fa 6d 6d 6d 6d 6d a3 6d c7 b6 c5 6d c7 9e 6d c7 b2 c1 c7 c4 c5 19 fe b6 8a 19 d7 ae 19 c6 97 ea 93 78 19 d8 8a 19 c8 b2 93 79 71 a0 db 19 a6 19 93 7c a3 6d 6e a3 52 3e aa 72 e6 95 53 5d 9f 93 55 79 60 a9 ee b6 86 e7 73 19 c8 b6 93 79 f4 19 9e d9 19 c8 8e 93 79 19 96 19 93 7a 79 90 a3 52}  //weight: 1, accuracy: High
        $x_1_4 = {58 80 e8 e7 31 c9 66 81 e9 97 fe 80 30 92 40 e2 fa 7a aa 92 92 92 d1 df d6 92 75 eb 54 eb 77 db 14 db 36 3f bc 7b 36 88 e2 55 4b 9b 67 3f 59 7f 6e a9 1c dc 9c 7e ec 4a 70 e1 3f 4b 97 5c e0 6c 21 84 c5 c1 a0 cd a1 a0 bc d6 de de 92 93 c9 c6 1b 77 1b cf 92 f8 a2 cb f6 19 93 19 d2 9e 19 e2}  //weight: 1, accuracy: High
        $x_1_5 = {1c 70 79 a3 6d f4 13 7e 02 93 c6 fa 93 93 92 92 6d c7 b2 c5 c5 c5 c5 d5 c5 d5 c5 6d c7 8e 1b 51 a3 6d c5 c5 fa 90 92 83 ce 1b 74 f8 82 c4 c1 6d c7 8a c5 c1 6d c7 86 c5 c4 c1 6d c7 82 1b 50 f4 13 7e c6 92 1f ae b6 a3 52 f8 87 cb 61 39 1b 45 54 d6 b6 82 d6 f4 55 d6 b6 ae 93 93 1b ee b6 da}  //weight: 1, accuracy: High
        $x_1_6 = {c7 ba c1 c7 c4 c5 19 fe b6 8a 19 d7 ae 19 c6 97 ea 93 78 19 d8 8a 19 c8 b2 93 79 71 a0 db 19 a6 19 93 7c a3 6d 6e a3 52 3e aa 72 e6 95 53 5d 9f 93 55 79 60 a9 ee b6 86 e7 73 19 c8 b6 93 79 f4 19 9e d9 19 c8 8e 93 79 19 96 19 93 7a 79 90 a3 52 1b 78 cd cc cf c9 50 9a 92 65 6d 44 58 4f 52}  //weight: 1, accuracy: High
        $x_1_7 = {eb 0f 58 80 30 17 40 81 38 6d 30 30 21 75 f4 eb 05 e8 ec ff ff ff fe 94 16 17 17 4a 42 26 cc 73 9c 14 57 84 9c 54 e8 57 62 ee 9c 44 14 71 26 c5 71 af 17 07 71 96 2d 5a 4d 63 10 3e d5 fe e5 e8 e8 e8 9e c4 9c 6d 2b 16 c0 14 48 6f 9c 5c 0f 9c 64 37 9c 6c 33 16 c1 16 c0 eb}  //weight: 1, accuracy: High
        $x_1_8 = {1d 81 4e 90 ea 63 05 50 50 f5 f1 a9 18 17 17 17 3e d9 3e e0 fe ff e8 e8 e8 26 d7 71 9c 10 d6 f7 15 9c 64 0b 16 c1 16 d1 ba 16 c7 9e d1 9e c0 4a 9a 92 b7 17 17 17 57 97 2f 16 62 ed d1 17 17 9a 92 0b 17 17 17 47 40 e8 c1 7f 13 17 17 17 7f 17 07 17 17 7f 68 81 8f 17 7f 17}  //weight: 1, accuracy: High
        $x_1_9 = {78 64 72 17 40 7e 79 52 6f 72 74 17 52 6f 7e 63 47 65 78 74 72 64 64 17 40 7e 79 5e 79 72 63 17 5e 79 63 72 65 79 72 63 58 67 72 79 56 17 5e 79 63 72 65 79 72 63 58 67 72 79 42 65 7b 56 17 5e 79 63 72 65 79 72 63 45 72 76 73 51 7e 7b 72 17 17 17 17 17 17 17 17 17 7a 27}  //weight: 1, accuracy: High
        $x_1_10 = {66 81 ec 80 00 89 e6 e8 b7 00 00 00 89 06 89 c3 53 68 7e d8 e2 73 e8 bd 00 00 00 89 46 0c 53 68 8e 4e 0e ec e8 af 00 00 00 89 46 08 31 db 53 68 70 69 33 32 68 6e 65 74 61 54 ff d0 89 46 04 89 c3 53 68 5e df 7c cd e8 8c 00 00 00 89 46 10 53 68 d7 3d 0c c3 e8 7e 00 00 00 89 46 14 31 c0 31}  //weight: 1, accuracy: High
        $x_1_11 = {db 43 50 68 72 00 73 00 68 74 00 6f 00 68 72 00 61 00 68 73 00 74 00 68 6e 00 69 00 68 6d 00 69 00 68 41 00 64 00 89 66 1c 50 68 58 00 00 00 89 e1 89 4e 18 68 00 00 5c 00 50 53 50 50 53 50 51 51 89 e1 50 54 51 53 50 ff 56 10 8b 4e 18 49 49 51 89 e1 6a 01 51 6a 03 ff 76 1c 6a 00 ff 56 14}  //weight: 1, accuracy: High
        $x_1_12 = {ad 8b 40 08 5e c2 04 00 53 55 56 57 8b 6c 24 18 8b 45 3c 8b 54 05 78 01 ea 8b 4a 18 8b 5a 20 01 eb e3 32 49 8b 34 8b 01 ee 31 ff fc 31 c0 ac 38 e0 74 07 c1 cf 0d 01 c7 eb f2 3b 7c 24 14 75 e1 8b 5a 24 01 eb 66 8b 0c 4b 8b 5a 1c 01 eb 8b 04 8b 01 e8 eb 02 31 c0 89 ea 5f 5e 5d 5b c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

