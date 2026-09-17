rule Trojan_Win64_VectraRat_DA_2147978356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VectraRat.DA!MTB"
        threat_id = "2147978356"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VectraRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {09 00 89 5a 5e f9 05 04 c9 03 02 c5 02 04 cd 06 0a 88 0c 84 0a b9 04 0e 7c 10 ad 02 12 0d 02 14 45 07 16 89 02 14 81 06 0a 76 06 4d 02 22 a5 02 24 a2 26 76 28 3c 26 f2 28 36 26 05 04 20 b1 03 2c b0 2e 8e 30 48 32 0d 09 06 39 03 42 a4 0a d9 02 08 65 02 0a 25 04 4a 24 48 38 00 4e 02 5a 04 34 06 32 08 34 10 68 16 0c 2c 16 32 34 3a 3e 0c 3e 00 36 48 3c 02 19 0b 03 00 0b 82 07 50 06 30 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {4c 5e f9 03 02 25 02 06 79 02 02 66 08 4c 06 60 0a 82 0c f1 03 02 dd 04 0e 15 06 10 a6 12 62 0e d5 02 14 98 12 d4 16 c4 18 b5 02 16 38 1a 85 05 1c 7d 02 0e 6a 1e 66 20 ad 02 1e 36 22 45 05 24 82 0e 9d 05 1e c4 26 ad 02 1e 36 22 61 05 24 36 0e 40 28 a1 02 0e c6 2c 98 12 62 0e 15 02 02 86 00 88 02 16 04 16 06 16 10 16 14 16 28 32 2c 16 0e 00 01 0a 02 00 0a 92 06 50 19 28 09 00 1a}  //weight: 10, accuracy: High
        $x_10_3 = {3a 90 ae 00 00 c1 03 3a 90 ae 00 00 41 03 3a 90 ae 00 00 c1 05 3a 90 ae 00 00 41 04 3a 90 ae 00 00 e0 45 04 90 ae 00 00 41 03 42 90 ae 00 00 c1 03 3a 90 ae 00 00 41 02 32 ae 00 34 02 ac 04 1c 06 54 08 d8 0a 2a 0c 2a 0e 2a 10 2e 12 4e 14 76 12 21 11 02 c9 04 16 2c 18 2c 1a 84 18 bd 07 02 c9 04 16 2c 18 2c 1a 84 18 c1 06 02 aa 00 3a 04 19 2e 09 00 1d 64 86 00 1d 34 85 00 1d 01 80 00 0e e0 0c 70}  //weight: 10, accuracy: High
        $x_10_4 = {92 04 fa 06 2a 04 f8 08 66 0a 28 08 a2 04 1e 0c 9a 10 52 12 26 10 0d 02 14 6c 16 28 14 1d 02 18 da 10 70 14 62 1a 6d 02 10 32 14 62 1a fc 1c d8 1e 28 1c 4d 02 20 6a 22 28 20 85 02 1c 30 20 62 22 9c 1c 20 24 2c 26 62 28 7d 02 1c 2e 2a 62 2c ac 1c 32 20 62 22 92 1c 32 20 62 22 92 1c 32 20 62 22 92 1c 32 20 62 22 92 1c 32 20 62 22 9e 1c 88 00 32 1c 19 25 07 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

