rule Virus_Win32_Pririm_A_2147924686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Pririm.A!MTB"
        threat_id = "2147924686"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Pririm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 a8 9b 49 1c 76 dd f5 a7 a5 8c ca 7e f8 a6 23 41 1d 9f 87 22 a3 9e 30 54 d3 a1 8a 45 1f bc c7 1d e9 6e 0e 22 26 90 cc 5d 80 49 93 d0 1a 95 b2 c8 5b d2 9c f1 33 7d d1 c7 af a5 24 8c 21 8b 83 92 69 ee 1b 10 f2 ac 46 79 a3 70 c7 2c 41 f7 14 c8 9b e6 c9 e4 d3 f8 6e 48 aa 33 7a 92 b3 1d d8 c7 15 13 fd e3 57 c8 03 b0 aa 33 ff}  //weight: 1, accuracy: High
        $x_1_2 = {4f 33 2d 26 cf 01 fd 16 19 2e 10 fa 40 5e ca 8c ec b1 f9 b5 2d 0c 86 24 fa b9 02 c8 42 ad 9d b0 1d 71 50 12 13 c7 14 22 0c 67 6c 6e f7 fe 64 08 fa 96 22 6c 0d 43 9e 5a 10 e6 48 b3 4d 29 5e 11 4a 0b 18 fa a1 6d 90 6a 04 2c cd 2f 25 10 5d 1b 7b 5b 0d c8 2b 4a 2c 7a 1e 5e 21 cf 64 4b cc 10 32 24 24 f9 38 15 cb cb 19 b3 35 13 69 6a 6f}  //weight: 1, accuracy: High
        $x_1_3 = {33 8c d5 88 61 c9 cb 82 40 3d 49 c0 a9 b2 44 92 89 02 0c a7 42 bc d4 d0 e1 a3 04 ae ef ad 45 e5 ee 76 1d 57 19 fa 0a 23 63 1a f0 1b 69 e9 de a4 07 33 09 24 c7 af 42 05 44 58 23 67 a8 1c 1a b0 8a a1 02 be 3e 94 34 6b 1c b9 da 36 1e 49 ea 68 1d 88 7c d0 57 3b 48 f4 06 ab ca e7 21 17 ef 37 e9 53 cd 29 27 05 40 0b d2 ab c2 b9 cc 8d d4 d5 a4 32 45 5d aa 02 f6 a4 69 92 3e 33 93 55 e7 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

