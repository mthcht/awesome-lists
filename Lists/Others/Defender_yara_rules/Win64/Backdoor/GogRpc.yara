rule Backdoor_Win64_GogRpc_DA_2147978575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/GogRpc.DA!MTB"
        threat_id = "2147978575"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "GogRpc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 29 29 28 69 76 3b 20 3a 25 20 2c 68 32 38 30 25 76 0d 0a 20 09 4f 4b 7c 30 7c 31 3e 0a 28 22 22 29 29 20 29 0a 20 20 20 2b 3a 0a 20 40 73 20 20 50 42 20 6e 3d 5d 5b 7d 0a 5d 0a 3e 20 5b 20 20 5d 0a 20 09 20 31 33 32 35 4c 6c 4c 74 4c 75 4d 6e 43 63 69 64 22 0a 30 62 30 78 30 58 30 6f 4f 55 43 4e 53 54 3d 23 5c 22 54 6f 41 34 56 31 56 36 56 32 56 33 56 35 41 33}  //weight: 10, accuracy: High
        $x_10_2 = {2b 00 30 d0 65 00 60 e0 2b 00 3a e5 2b 00 a8 d0 65 00 40 e5 2b 00 45 e8 2b 00 a8 d0 65 00 60 e8 2b 00 dd e9 2b 00 18 d0 65 00 e0 e9 2b 00 13 ea 2b 00 0c d0 65 00 20 ea 2b 00 53 eb 2b 00 18 d0 65 00 60 eb 2b 00 52 ec 2b 00 18 d0 65 00 60 ec 2b 00 dc ed 2b 00 24 d0 65 00 e0 ed 2b 00 55 ef 2b 00 24 d0 65 00 60 ef 2b 00 3d f1 2b 00 24 d0 65 00 40 f1 2b 00 77 f5 2b 00 24 d0 65 00 80 f5 2b 00 86 f6 2b 00 18 d0 65 00 a0 f6 2b 00 cf f7 2b 00 18 d0 65 00 e0 f7 2b 00 1a f8 2b 00 0c d0 65 00 20 f8 2b 00 26 f9 2b 00 18 d0 65 00 20 66 18 00 95 66}  //weight: 10, accuracy: High
        $x_10_3 = "p= sp: lr: fp= gp= mp=) m=sha1AVX2ermsfsrmsse3avx2bmi1bmi2asn1quitint8chanfunccallkind != bitsNameTypeFrometagfromvaryxn--time," ascii //weight: 10
        $x_10_4 = {27 00 4e cb 27 00 24 d0 65 00 60 cb 27 00 16 ce 27 00 24 d0 65 00 20 ce 27 00 0f cf 27 00 18 d0 65 00 20 cf 27 00 52 d1 27 00 24 d0 65 00 60 d1 27 00 49 d3 27 00 24 d0 65 00 60 d3 27 00 35 d4 27 00 30 d0 65 00 80 d4 27 00 65 d6 27 00 18 d0 65 00 80 d6 27 00 ae d7 27 00 18 d0 65 00 c0 d7 27 00 95 d8 27 00 30 d0 65 00 e0 d8 27 00 e5 da 27 00 18 d0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

