rule Backdoor_Win32_GoldenLight_A_2147690304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/GoldenLight.A"
        threat_id = "2147690304"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "GoldenLight"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 41 24 33 d2 bd 1c 00 00 00 f7 f5 89 51 ?? 8a 44 11 04 8a 14 3e 32 c2 8a 51 ?? 32 c2 34 cc 88 04 3e 8b 51 ?? 46 42 3b f3 89 51 ?? 7c d2}  //weight: 4, accuracy: Low
        $x_2_2 = {8a 54 34 18 32 d0 88 54 34 18 46 83 fe 2b 7c ?? 8d 44 24 18 6a 46 50 8b cb e8 ?? ?? ?? ?? 83 f8 46 0f 85 a5 01 00 00 8d 4c 24 10 6a 05 51 8b cb e8 ?? ?? ?? 83 f8 05 0f 85 8e 01 00 00 80 7c 24 10 16 0f 85 83 01 00 00 8b 54 24 13 52 ff 15 ?? ?? ?? ?? 66 8b f0 81 e6 ff ff 00 00 81 fe f9 3f 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 04 0e 8a d3 32 01 f6 d2 32 c2 88 01 75 02 88 11 43 41 83 fb 1c 7c e8}  //weight: 2, accuracy: High
        $x_1_4 = "**txtx**" ascii //weight: 1
        $x_1_5 = "\\alg.exe" ascii //weight: 1
        $x_1_6 = "TMP.BAT" ascii //weight: 1
        $x_1_7 = "imrpi.exe" ascii //weight: 1
        $x_1_8 = "~DCXAO8.tmp" ascii //weight: 1
        $x_1_9 = "C:\\TEMP\\History\\History.IE5\\wsnctfy.exe" ascii //weight: 1
        $x_1_10 = "sOftWarE\\MIcrOsOft\\WIndOwS\\CurRenTVeRsiOn\\RuN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_GoldenLight_B_2147690305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/GoldenLight.B"
        threat_id = "2147690305"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "GoldenLight"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {68 23 f1 de bc ff 15 ?? ?? ?? ?? 8b 74 24 ?? 83 c9 ff 8b fe 33 c0 83 c4 04 33 db f2 ae f7 d1 49 74 2a 55 8b 2d ?? ?? ?? ?? ff d5 8a 0c 33 8b fe c1 f8 0c 32 c1 83 c9 ff 32 c3 34 a9 88 04 33 33 c0 43 f2 ae f7 d1 49 3b d9 72 de}  //weight: 4, accuracy: Low
        $x_4_2 = {8a 04 0e 8a d3 32 01 f6 d2 32 c2 88 01 75 02 88 11 43 41 83 fb 1c 7c e8}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_GoldenLight_A_2147690398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/GoldenLight.A!cc"
        threat_id = "2147690398"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "GoldenLight"
        severity = "Critical"
        info = "cc: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 03 00 00 41 01 00 00 3d 03 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 16 00 04 00 05 00 0a 00 09 00 64 00 62 00 03 00 06 00 13 00 12 00 63 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {16 03 00 01 04 10 00 01 00 00 15 b3 76 32 9f 46 4f 39 99 3b 84 ad 2d 5c bd da e2 2b 3e b3 19 04 7b 9a 70 09 52 a7 ae 42 d0 73 cf 78 1a 88 de eb 6e 25 9b 01 3d 3e 38 ad 41 4b 5c 7a 40 a7 d7 16 fa 7b 06 43 29 0a 88 63 23 33 9d 5f 8f dd 5e 9e ee 12 3e 07 ef 27 94 8d 8e 8f 6f 43 c2 45 ec ac 14 55 d7 8e d9 29 4f a0 16 24 cf 19 5c fd 86 42 0b ac 30 04 2f 2f 9a 45 76 2c d1}  //weight: 1, accuracy: High
        $x_1_3 = {27 99 71 c8 8b 8b 75 52 66 7a 47 94 57 02 4e 6b 56 63 94 ae fe 21 14 4a c2 06 3c f4 e9 a2 a9 0a df a5 61 72 24 f8 d1 2f 0d f0 40 46 e3 f8 f2 f0 a5 10 ca b5 5b 9e 23 9a c8 d4 79 b1 d2 93 bf 53 8b 75 ba bb 5f 86 60 fb 70 7b ff 21 2c 4e 30 40 07 4f 07 e3 e1 3c 6b 2d 7d 20 6a 5a 75 45 d9 2b c6 a6 f1 32 13 6d d7 aa b4 0b 49 0c c7 89 1e da cf 8c cc af 0a 4a 4e 9c 1c f3 07 99 d2 c0 e0 9f c7 fd 42 7a 48 ee be d6 95 5c 08 ee af 3d 14 03 00 00 01 01 16 03 00 00 38 aa 10 a9 b1 7d d1 a9 33 0b 29 7a 01 74 51 9b 82 8a 37 b8 f1 8a 1f 35 4e c8 27 1a a7 0b 68 bc 35 29 9e bb 02 d4 76 2d 4a d0 de 82 ed 42 5b d0 dc 9b cf e8 ba cf 27 7c a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_GoldenLight_A_2147690399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/GoldenLight.A!sc"
        threat_id = "2147690399"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "GoldenLight"
        severity = "Critical"
        info = "sc: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 03 00 15 65 02 00 00 46 03 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 04 00 0b 00 15 13 00 15 10 00 06 78}  //weight: 1, accuracy: Low
        $x_1_2 = {48 86 f7 0d 01 01 05 05 00 30 81 80 31 13 30 11 06 0a 09 92 26 89 93 f2 2c 64 01 19 16 03 63 6f 18 e0 b8 b4 00 01 00 00 31 d1 30 0d 06 09 2a 86 6d 31 19 30 17 06 0a 09 92 26 89 3f 22 c6 40 11 91 60 96 d6 96 37 26 f7 36 f6 67 43 11 43 01 20 60 a0 99 22 68 99 3f 22 c6 40 11 91 60 46 36 f7 27 03 11 73 01 50 60 a0 99 22 68 99 3f 22 c6 40 11 91 60 77 26 56 6d 6f 6e 64 31 1f 30 1d 06 03 55 04 03 13 16 4d 53 49 54 20 4d 61 63 68 69 6e 65 20 41 75 74 68 20 43 41 20 32}  //weight: 1, accuracy: High
        $x_1_3 = {30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 9f a1 e1 b4 3b 3a 57 0e d0 cf 54 bc cd 18 d8 b2 12 13 31 a4 4c 37 3d 09 3e ef 3d d6 42 36 18 e9 51 fe 46 c8 d4 05 26 26 ed e0 e8 2b f4 c2 ac f8 6f d4 13 e8 17 57 48 4f 96 03 15 0c ff 29 38 99 fd 47 86 42 6d 6d 2c 2e 71 b0 10 02 d8 2a d2 20 b5 bb a9 83 0d 1f 6b 25 fc d5 01 e1 52 92 1a bc 88 61 87 51 54 77 6e 66 51 64 00 79 b1 c1 c9 b1 c9 0b 7a 05 0c a4 5e 5e c6 36 47 ed 88 96 6d}  //weight: 1, accuracy: High
        $x_1_4 = {55 c8 bf 65 13 da 06 b1 67 91 98 d9 09 b2 47 f9 c6 9c 74 bf d8 66 05 32 cf 54 01 b2 20 5e 53 c0 5d 5a 95 d5 d3 df ae d2 ef a4 06 1a 7e 94 9c 8d 0e e4 2b 9a ec 65 35 24 35 66 6c fb ac d2 48 11 4d ac ef c9 6e 20 d7 b8 c6 16 d3 49 f2 e3 75 2a 95 7e d3 67 c0 7b e8 e6 42 b2 aa 15 c4 96 e5 56 1e c8 d1 60 dc 0c 5c 08 ad 25 a2 50 41 5c f6 2d 39 83 58 38 f7 12 bc 63 bb 69 87 cb 5b c2 ff 02 03 01 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

