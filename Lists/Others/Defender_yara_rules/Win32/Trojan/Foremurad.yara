rule Trojan_Win32_Foremurad_2147729861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foremurad!dha"
        threat_id = "2147729861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foremurad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 48 8b 47 38 48 85 c0 48 0f 44 c1 48 8b 4f 40 48 89 47 38 ff 57 30 48 85 c0 75 05 8d 58 fc eb 2c 48 89 47 28 89 18 48 89 98 f8 2a 00 00 c7 80 0c ab 00 00 01 00 00 00 48 c7 80 00 2b 00 00 01 00 00 00 c7 80 08 2b 00 00 0f 00 00 00 8b c3 48 8b 5c 24 30 48 83 c4 20 5f c3 cc cc 40 53 48 83 ec 20 48 8b d9 48 85 c9 75 05 8d 41 fe eb 17 48 8b 51 28 48 85 d2 74 0c 48 8b 49 40 ff 53 38 48 83}  //weight: 1, accuracy: High
        $x_1_2 = {b8 f8 ff ff ff 48 23 d0 48 03 d1 8b 01 48 83 c1 08 41 89 03 8b 41 fc 49 83 c3 08 41 89 43 fc 48 3b ca 72 e7 41 83 e5 07 4c 89 5c 24 30 41 83 fd 03 73 2b 45 85 ed 0f 84 f7 fa ff ff 8a 01 41 88 03 41 83 fd 01 76 07 8a 41 01 41 88 43 01 41 8b c5 4c 03 d8 4c 89 5c 24 30 e9 d5 fa ff ff 8a 01 41 83 c5 fd 48 83 c1 03 41 88 03 8a 41 fe 49 83 c3 03 41 88 43 fe 8a 41 ff 41 88 43 ff 41 83 fd 02}  //weight: 1, accuracy: High
        $x_1_3 = {e0 4c 0b f0 83 fe 0f 0f 82 70 ff ff ff eb 20 0f b6 55 01 0f b6 45 00 8d 4e 08 48 d3 e2 8b ce 48 83 c5 02 48 d3 e0 48 0b d0 4c 0b f2 83 c6 10 49 8b c6 25 ff 03 00 00 44 0f bf ac 47 68 01 00 00 45 85 ed 78 0f 41 8b cd c1 f9 09 41 81 e5 ff 01 00 00 eb 27 b9 0a 00 00 00 41 f7 d5 49 8b d6 48 d3 ea 49 63 c5 ff c1 83 e2 01 48 03 d0 44 0f bf ac 57 68 09 00 00 45 85 ed 78 de 41 b9 00 01}  //weight: 1, accuracy: High
        $x_1_4 = {48 3b d3 0f 83 ae 0a 00 00 0f b6 02 48 8d 6a 01 e9 bc 0a 00 00 83 e8 27 0f 84 03 11 00 00 ff c8 0f 84 f3 10 00 00 ff c8 0f 84 47 10 00 00 ff c8 0f 84 31 10 00 00 83 e8 09 74 4f ff c8 0f 84 95 00 00 00 ff c8 0f 85 dc 10 00 00 4c 8b 4c 24 58 4c 8b 54 24 60 4c 3b 5c 24 38 0f 83 57 0f 00 00 41 8b c0 48 2b c8 49 23 c9 42 8a 04 11 48 8b 4c 24 50 41 88 03 49 ff c3 48 ff c1 48 89 4c 24 50 4c}  //weight: 1, accuracy: High
        $x_1_5 = {48 89 4c 24 50 4c 89 5c 24 30 e9 4b 0c 00 00 48 3b d3 73 09 0f b6 02 48 8d 6a 01 eb 11 f6 84 24 a0 01 00 00 02 0f 85 b0 0f 00 00 41 8b c7 8b ce 83 c6 08 48 d3 e0 4c 0b f0 83 fe 08 0f 82 f6 0d 00 00 48 8b 44 24 38 45 0f b6 c6 b9 f8 ff ff ff 49 c1 ee 08 44 89 44 24 28 03 f1 eb 05 48 8b 44 24 38 4c 3b d8 0f 83 5f 0f 00 00 45 88 03 49 ff c3 41 ff cd 44 89 6c 24 20 4c 89 5c 24 30 45 85 ed}  //weight: 1, accuracy: High
        $x_1_6 = {48 8b ec 48 83 ec 50 45 33 ff 48 8b f1 41 be 08 00 00 00 48 85 c9 0f 84 eb 02 00 00 4c 8b 61 28 4d 85 e4 0f 84 de 02 00 00 45 8d 6e f9 45 8d 4e fa 41 3b d5 41 0f 44 d1 85 d2 74 0e 41 3b d1 74 09 83 fa 04 0f 85 bd 02 00 00 45 39 bc 24 08 2b 00 00 45 8b 84 24 00 2b 00 00 b8 09 00 00 00 44 0f 4f f0 8b 41 08 45 89 bc 24 00 2b 00 00 48 89 45 58 45 39 bc 24 0c ab 00 00 7d 0a b8 fd ff ff ff}  //weight: 1, accuracy: High
        $x_1_7 = {41 8b cd 41 83 ed 02 eb 03 0f bf c8 48 ff ca 75 ca 41 d1 e9 41 83 e1 01 41 2b c9 48 63 c1 b9 8f 04 00 00 48 2b c8 66 41 89 1c 4e 8b 47 18 ff c3 3b 5c 87 2c 0f 82 ed fe ff ff 83 7f 18 02 0f 85 61 02 00 00 4c 8b 74 24 40 45 8b ef 44 89 7c 24 20 8b 47 30 03 47 2c 44 3b e8 0f 83 03 02 00 00 83 fe 0f 0f 83 c7 00 00 00 48 8b 5c 24 48 48 8b c3 48 2b c5 48 83 f8 02 0f 8d 92 00 00 00 49 8b c6}  //weight: 1, accuracy: High
        $x_1_8 = {44 00 00 cc cc 48 89 5c 24 08 57 48 83 ec 20 33 db 48 8b f9 48 85 c9 75 08 8d 59 fe e9 85 00 00 00 48 8b 41 30 48 89 59 48 48 89 59 20 48 85 c0 89 59 0c 89 59 1c 89 59 50 48 8d 0d a9 ff ff ff ba 01 00 00 00 48 0f 44 c1 48 8d 0d a9 ff ff ff 41 b8 10 ab 00 00 48 89 47 30 48 8b 47 38 48 85 c0 48 0f 44 c1 48 8b 4f 40 48 89 47 38 ff 57 30 48 85 c0 75 05 8d 58 fc eb 2c 48 89 47 28 89 18 48}  //weight: 1, accuracy: High
        $x_1_9 = {45 88 43 01 49 83 c3 02 4c 89 5c 24 30 e9 0c ff ff ff 83 fe 0f 0f 83 bc 00 00 00 48 83 f9 02 0f 8d 92 00 00 00 49 8b c6 25 ff 03 00 00 44 0f bf 84 47 68 01 00 00 45 85 c0 78 14 41 c1 f8 09 45 85 c0 74 3e 41 3b f0 0f 83 8a 00 00 00 eb 33 83 fe 0a 76 2e b9 0a 00 00 00 41 f7 d0 49 8b d6 48 d3 ea 49 63 c0 ff c1 83 e2 01 48 03 d0 44 0f bf 84 57 68 09 00 00 45 85 c0 79 5c 8d 41 01 3b f0 73}  //weight: 1, accuracy: High
        $x_1_10 = {58 00 00 83 e1 07 83 c6 fd 41 ff c5 4c 89 74 24 40 88 8c 38 88 1b 00 00 44 89 6c 24 20 e9 0d ff ff ff c7 47 34 13 00 00 00 44 39 7f 18 0f 8c 59 04 00 00 8b 47 18 33 d2 48 8d 8c 24 e0 00 00 00 44 8d 42 40 48 69 c0 a0 0d 00 00 4c 8d 74 38 48 e8 b5 22 00 00 49 8d 8e 20 01 00 00 33 d2 41 b8 00 08 00 00 e8 a1 22 00 00 49 8d 8e 20 09 00 00 33 d2 41 b8 80 04 00 00 e8 8d 22 00 00 44 8b 5f 18}  //weight: 1, accuracy: High
        $x_1_11 = {5c 24 48 4d 8b d8 4c 89 44 24 30 74 05 49 8b c4 eb 0b 49 8b c0 48 2b c6 48 8d 44 08 ff 4c 8d 50 01 48 89 44 24 58 4c 85 d0 0f 85 fe 15 00 00 4c 3b c6 0f 82 f5 15 00 00 8b 4f 28 8b 07 44 8b 47 20 44 8b 6f 24 8b 77 04 4c 8b 77 38 89 4c 24 24 48 8b 4f 40 45 33 ff 44 89 44 24 28 44 89 6c 24 20 48 89 4c 24 50 83 f8 18 0f 87 93 02 00 00 0f 84 5c 0d 00 00 83 f8 0a 0f 87 e7 01 00 00 0f 84 d2}  //weight: 1, accuracy: High
        $x_1_12 = {5e 41 5d 41 5c 5f 5e 5d c3 48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 57 48 81 ec 80 00 00 00 48 8b fa 33 d2 49 8b f0 48 8b e9 44 8d 42 58 48 8d 48 98 41 8b d9 e8 4a 02 00 00 44 8b 1f 41 8b c3 0b c3 83 f8 ff 76 07 b8 f0 d8 ff ff eb 5f 48 8d 4c 24 20 48 89 74 24 20 89 5c 24 28 48 89 6c 24 30 44 89 5c 24 38 e8 85 d6 ff ff 85 c0 75 3e 8d 50 04 48 8d 4c 24 20 e8 58 fc ff ff 48 8d 4c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

