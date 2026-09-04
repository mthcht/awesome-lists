rule Trojan_MSIL_EtherRAT_DA_2147977479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/EtherRAT.DA!MTB"
        threat_id = "2147977479"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EtherRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {95 7d d6 52 1e 3c 2d ce 95 87 95 af e5 98 92 1e 95 7d da 62 3d 10 13 fb b8 b1 81 a9 c5 b5 be 32 dc 86 5a d1 de e1 f7 a9 38 1a 6d 09 ce 0a 06 14 f8 56 6b 09 41 d0 36 6f 8c 8c ca 2b 74 c1 0d 9a 9e 21 ed f0 59 63 5b 0e 42 b7 cc fe 96 c5 bf ed ca 95 7e 26 f5 bd 9a 3a fc c6 c0 b7 ce 00 00 00 95 7d da 62 3d 10 13 fb b8 b1 81 a7 c0 b7 bf 2e ca 9a 60 e6 ce e5 d7 83 00 0e 58 39 d6 0c 43 55 b3 06 28 38 22 87 02 31 d1 d5 93 34 18 8c 2c c0 b5}  //weight: 10, accuracy: High
        $x_10_2 = {23 eb 00 95 7d f2 3e 1e 51 22 d9 fd 92 e4 c7 90 95 f8 70 94 c1 35 a4 a5 9f 87 dd 52 52 02 0b bb 7d 06 15 f5 57 00 0e 31 a1 47 3f 95 7d bf 48 1f 20 52 de fd e0 f0 a9 99 e4 fa 6c 8d b0 31 a7 bf f0 89 db 25 4c 6a 7f bd 7b 06 1e f8 56 03 7e 40 a1 00 00 95 7d cc 61 3e 12 05 ee a3 bb b3 d0 e8 b0 a0 28 d7 9c 75 e6 e0 d3 ca 82 16 40 41 2f fd 75 00 00 95 7d e6 61 3e 57 56 b4 ae b8 b1 00}  //weight: 10, accuracy: High
        $x_10_3 = {2b 23 08 11 05 8f 08 00 00 01 25 71 08 00 00 01 07 11 05 07 8e 69 5d 91 61 d2 81 08 00 00 01 11 05 17 58 13 05 11 05 08 8e 69 32 d6 16 8d 09 00 00 01 13 06 09 2c 47 09 8e 69 16 31 41 16 13 07 2b 23 09 11 07 8f 08 00 00 01 25 71 08 00 00 01 07 11 07 07 8e 69 5d 91 61 d2 81 08 00 00 01 11 07 17 58 13 07 11 07 09 8e 69 32 d6 28 08 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

