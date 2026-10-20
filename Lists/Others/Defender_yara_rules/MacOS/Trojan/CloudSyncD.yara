rule Trojan_MacOS_CloudSyncD_DA_2147980607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/CloudSyncD.DA!MTB"
        threat_id = "2147980607"
        type = "Trojan"
        platform = "MacOS: "
        family = "CloudSyncD"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {74 34 65 84 57 c3 e5 d2 f4 12 0f c1 94 1d 8b 49 1a 0f 5c f6 b2 2d 5c 71 d8 3a 29 eb 27 e9 81 e0 6e af 32 c0 4c b1 d3 3c 25 bf 45 f5 40 31 e6 3c 48 69 12 eb fe 58 64 d0 c2 28 4d 5b 36 5c c3 da 99 5e 30 fe 0d 9c 23 4b 7c 4d d5 50 fa 48 7e 90 46 b8 49 4f 94 0d a3 87 2c 9a 29 2c ea 41 bf c2 6b 57 bc a5 9c 16 07 26 ff 6a a2 ba 66 59 b8 76 e8 ba 2b e1 01 0a 74 44 ea 5b e5 6c 10 74 d0 81 59 cc 5e 3f 62 d4 2d 11 80 29 3f 1f 8a c6 7d e6 60 dd 72 af f5 ed 44 2b 4a 89 7d 28 bd 64 c9 91 8a d7 27 19 c2 70 86 9e aa ea ca bd ec 10 3c fa de 0c}  //weight: 10, accuracy: High
        $x_10_2 = {47 6a 35 71 ac fd 8f 78 17 e1 89 08 6c 3f 19 f1 7c d7 8b 24 d6 a9 21 28 62 63 bc 80 5c 0d 97 65 61 a4 71 85 f6 e9 57 43 3b 7f 4e 72 c6 8e d2 38 a1 d7 5c 62 a7 25 ab 2f c2 f3 38 ca 78 08 83 9e b4 4e ad 1b 3b 14 b5 d9 6c 6b e5 c4 ec 9e 1a b1 bb cc}  //weight: 10, accuracy: High
        $x_10_3 = {cb bf e5 45 fe 52 a0 73 9d cb 9a 11 fc a9 e4 84 e8 2f 42 25 d7 2a 28 4a 87 6d 59 d2 4d ef af cd 9f 70 59 0f a5 aa 08 2d 27 32 62 d3 55 ab 34 98 f6 47 d2 58 16 f6 07 18 68 47 d3 17 d8 83 2a ba 20 17 67 0d 83}  //weight: 10, accuracy: High
        $x_10_4 = {22 3a 99 17 f9 b6 da b4 28 40 45 19 30 af 6e 35 b8 6d b2 35 63 fd 9c f5 58 b2 cd 28 30 87 45 7b c3 1a b8 77 98 96 fb 54 09 60 24 79 11 8f 8f d5 99 4d d3 55 42 dd 7d 15 79 d2 ac 08 11 67 fa 51}  //weight: 10, accuracy: High
        $x_10_5 = "ZZN14cloudsync_impl4sobf3cfg19APP_OPS_CHACHA_IV_cEvE3buf$tlv$init" ascii //weight: 10
        $x_10_6 = "GVZN14cloudsync_impl4sobf3cfg19APP_OPS_CHACHA_IV_cEvE3buf$tlv$in" ascii //weight: 10
        $x_10_7 = {9f 62 d4 c5 76 5b ed 91 a5 ee 78 c3 ca f4 40 9a 43 cc fb 4a 29 8f d6 be f7 9f 42 43 dc 9f cc 62 0a f8 d9 8a 5e 43 0c 04 29 a7 16 44 30 8f 21 c6 87 46 8b 09 2f 3a 28 bd ca b4 ef 12 8d 50 43 f0 ca 55 3f 1a ad 1a 38 5a 5c 79 eb 26 a0 a4 09 49 4c d2 25 73 9c 0f 23 e4 f1 af 65 58 ff 93 b1 2f a6 35 8a 68 f9 81 b7 ce 5e 4d 3f eb 9a b2 e3 b8 b9 f8 07 b7 1a}  //weight: 10, accuracy: High
        $x_10_8 = {06 ee 73 b9 8e 34 ff 29 55 be 42 41 c9 ac 14 eb cc 0e 40 c2 dc eb 60 ea 95 7a 1b 1f 65 e3 6c 4a cc bb a0 ff 2d a6 ed 3a a5 16 ae 97 75 93 fe ed 73 02 36 70 bd 90 51 3f 12 3c 85 49 10 fd f2 80 03 d6 75 9a 5c 5f d3 0f 66 de f1 da d8 a0 1d 03 6a 31 c0 f3 d6 07 16 57 68 fc ab d7 1c aa 36 ef a7 64 58 15 67 1a}  //weight: 10, accuracy: High
        $x_10_9 = {81 e0 6e af 32 c0 4c b1 d3 3c 25 bf 45 f5 40 31 e6 3c 48 69 12 eb fe 58 64 d0 c2 28 4d 5b 36 5c c3 da 99 5e 30 fe 0d 9c 23 4b 7c 4d d5 50 fa 48 7e 90 46 b8 49 4f 94 0d a3 87 2c 9a 29 2c ea 41 bf c2 6b 57 bc a5 9c 16 07 26 ff 6a a2 ba}  //weight: 10, accuracy: High
        $x_10_10 = {64 9b 22 3a 99 17 f9 b6 da b4 28 40 45 19 30 af 6e 35 b8 6d b2 35 63 fd 9c f5 58 b2 cd 28 30 87 45 7b c3 1a b8 77 98 96 fb 54 09 60 24 79 11 8f 8f d5 99 4d d3 55 42 dd 7d 15 79 d2 ac 08 11 67}  //weight: 10, accuracy: High
        $x_10_11 = {1b 24 b3 d6 a7 9c cf a2 e6 d2 25 90 21 2e 3d 3b 8f 8d 40 28 9d bf 02 2b f1 45 81 6b 9f 95 bf 9c 65 4d 71 9b 51 86 13 d3 cf 75 48 9b e6 d9 13 16 b5 ea 88 6b 37 13 46 92 84 5a 15 b1 44 22 d2 38}  //weight: 10, accuracy: High
        $x_10_12 = {35 71 ac fd 8f 78 17 e1 89 08 6c 3f 19 f1 7c d7 8b 24 d6 a9 21 28 62 63 bc 80 5c 0d 97 65 61 a4 71 85 f6 e9 57 43 3b 7f 4e 72 c6 8e d2 38 a1 d7 5c 62 a7 25 ab 2f c2 f3 38 ca 78 08 83 9e b4 4e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

