rule Ransom_Win32_PrinzEugen_DA_2147972246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PrinzEugen.DA!MTB"
        threat_id = "2147972246"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PrinzEugen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 e5 13 4d 83 cf 42 fb e3 8a ab 0a ae 14 2f d2 83 59 14 f6 55 87 82 2b c9 c3 fa b3 b6 5f 2e b8 60 17 f3 fc bb 49 0f 59 6d a2 53 d3 ab 82 fc b2 93 1f b0 9c 72 0f 6d 90 5f 34 03 5c c9 ef c6 ce 48 da 7a d4 fa 0c 1e 22 2e da fa 10 f9 09 ae 54 ef 5d fa 41 26 b8 c5 ca 57}  //weight: 1, accuracy: High
        $x_1_2 = {79 58 7f 5d d0 8f 4f d7 02 5d d0 e7 97 12 f1 b1 fe 36 0b ba d2 79 a7 b6 8c fb 31 df 76 b7 d1 84 aa 72 cb b7 01 5f da 77 e8 da fb 29 e2 9e 48 46 1e 0e dd e2 fb 1b b4 fd a2 53 40 af fe 78 19 0f 4d 9c 43 0e f1 93 a9 e0 fe 1d c5 55 5c cb e2 cc 5b ab}  //weight: 1, accuracy: High
        $x_1_3 = {0f 69 69 b9 72 a1 53 fb 4e f4 6a b8 ac 0e cd 3e 41 75 a1 4f ba 1c f9 dc 5c d4 87 ab 24 9a 33 f1 ab ec a5 ce 55 f4 a4 30 8c e1 55 f1 5b b4 9a ab f4 05 44 ac 70 b5 1c d5 d5 e0 5b 5a 67 35 e5 1c 39 ce b1 6d 09 fe f0 68 0d f0 d7 50 a1 b8 1d 59 9e}  //weight: 1, accuracy: High
        $x_1_4 = {7c 87 8b a4 67 92 1e fc c3 bc 8d 67 f4 b9 a4 2f c4 3f 6a a1 fc 0b a5 57 16 49 af 2e 92 9e 2e 92 3e 58 24 7d b8 48 7a b6 40 ba ea b1 5c d2 c3 f9 5a d6 4b 0d 3a 22 44 eb a4 c4 37 56 d2 82 50 e5 3d 68 3f b8 3c 86 0b a4 6b 7e 99 a4 bf a3 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

