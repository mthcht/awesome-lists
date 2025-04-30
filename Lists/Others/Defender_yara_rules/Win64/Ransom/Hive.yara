rule Ransom_Win64_Hive_ZZ_2147799663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.ZZ"
        threat_id = "2147799663"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 83 ec 38 48 89 6c 24 30 48 8d 6c 24 30 48 8d 05 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 44 24 18 c6 00 ?? 48 8d 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 44 24 28 48 c7 00 00 00 00 00 48 8d 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 44 24 20 48 8d 05 ?? ?? ?? ?? 0f 1f 00 e8 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 48 89 08 83 ?? ?? ?? ?? 00 00 75 20 48 8b 4c 24 28 48 89 48 08 48 8b 5c 24 18 48 89 58 10 48 8b 5c 24 20 48 89 58 18 48 89 03 eb 35}  //weight: 10, accuracy: Low
        $x_10_2 = {48 83 ec 30 48 89 6c 24 28 48 8d 6c 24 28 48 89 44 24 20 0f 1f 00 e8 ?? ?? ?? ?? 48 85 c0 0f 85 8b 00 00 00 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 85 c0 74 0a 48 8b 6c 24 28 48 83 c4 30 c3 48 89 44 24 10 48 89 5c 24 18 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 89 c3 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 ?? e8 ?? ?? ?? ?? 48 8b 44 24 10 48 8b 5c 24 18 48 8b 6c 24 28 48 83 c4 30 c3}  //weight: 10, accuracy: Low
        $x_1_3 = {48 0f ba e0 3f 73}  //weight: 1, accuracy: High
        $x_1_4 = {48 bf 80 7f b1 d7 0d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 0f b6 04 0f 49 89 c9 48 31 c1 41 01 c8 46 88 04 0f 49 8d 49 01}  //weight: 1, accuracy: High
        $n_1_6 = {66 81 39 77 67}  //weight: -1, accuracy: High
        $n_1_7 = {80 79 02 73}  //weight: -1, accuracy: High
        $n_1_8 = {81 39 68 74 74 70}  //weight: -1, accuracy: High
        $n_1_9 = {80 79 04 73}  //weight: -1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win64_Hive_ZY_2147799668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.ZY"
        threat_id = "2147799668"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "231"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {48 83 ec 68 48 89 6c 24 60 48 8d 6c 24 60 4c 8b 42 10 4c 8b 4a 18 48 8b 52 08 48 8b 4a 08 48 8d 71 01 48 8b 1a 48 8b 7a 10 45 0f b6 10 41 01 c2 48 39 f7 73 64 88 44 24 70 48 89 54 24 58 4c 89 44 24 48 4c 89 4c 24 50 44 88 54 24 47 48 8d 05 ?? ?? ?? ?? 66 ?? e8 ?? ?? ?? ?? 48 8b 7c 24 58 48 89 4f 10 83 ?? ?? ?? ?? 00 00 75 09 48 89 07 eb 09}  //weight: 100, accuracy: Low
        $x_100_3 = {48 83 ec 30 48 89 6c 24 28 48 8d 6c 24 28 48 89 44 24 20 0f 1f 00 e8 ?? ?? ?? ?? 48 85 c0 0f 85 8b 00 00 00 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 85 c0 74 0a 48 8b 6c 24 28 48 83 c4 30 c3 48 89 44 24 10 48 89 5c 24 18 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 89 c3 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 e8 ?? ?? ?? ?? 48 8b 44 24 20 ?? e8 ?? ?? ?? ?? 48 8b 44 24 10 48 8b 5c 24 18 48 8b 6c 24 28 48 83 c4 30 c3}  //weight: 100, accuracy: Low
        $x_10_4 = {48 0f ba e0 3f 73}  //weight: 10, accuracy: High
        $x_10_5 = {48 bf 80 7f b1 d7 0d 00 00 00}  //weight: 10, accuracy: High
        $x_10_6 = {44 0f b6 04 0f 49 89 c9 48 31 c1 41 01 c8 46 88 04 0f 49 8d 49 01}  //weight: 10, accuracy: High
        $n_1_7 = {66 81 39 77 67}  //weight: -1, accuracy: High
        $n_1_8 = {80 79 02 73}  //weight: -1, accuracy: High
        $n_1_9 = {81 39 68 74 74 70}  //weight: -1, accuracy: High
        $n_1_10 = {80 79 04 73}  //weight: -1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win64_Hive_E_2147815389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.E"
        threat_id = "2147815389"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 65 72 72 6f 72 3a 20 6e 6f 20 66 6c 61 67 20 2d 75 20 3c 6c 6f 67 69 6e 3e 3a 3c 70 61 73 73 77 6f 72 ?? 3e 20 70 72 6f 76 69 64 65 64}  //weight: 1, accuracy: Low
        $x_1_2 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 ?? 61 6e 64 20 33 32 2d 62 79 74 65 20 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Hive_F_2147818482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.F"
        threat_id = "2147818482"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "windows_encrypt.dll" ascii //weight: 1
        $x_1_2 = {00 63 6c 6f 73 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = "dllinstall" ascii //weight: 1
        $x_1_5 = "expand 32-byte kexpand 32-byte k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Hive_B_2147839086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.B"
        threat_id = "2147839086"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b1 01 48 ba 09 2a 86 48 86 f7 0d 00 41 88 4d 18 41 89 55 19 48 89 d1 48 c1 e9 30 41 88 4d 1f 48 c1 ea 20 66 41 89 55 1d 49 89 75 20 49 89 6d 30 4d 89 4d 48 49 89 45 50}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 c9 48 c1 e1 08 40 0f b6 fe 48 09 cf 48 c1 e3 20 0f b6 f2 48 c1 e6 18 48 09 de 48 09 fe}  //weight: 1, accuracy: High
        $x_1_3 = "windows_encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Hive_ZX_2147839303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.ZX"
        threat_id = "2147839303"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 81 ec d8 00 00 00 48 89 ce 0f 28 05 ?? ?? ?? ?? 0f 29 44 24 50 48 8b 05 ?? ?? ?? ?? 48 85 c0 74 6c 48 89 d7 b9 ff ff ff ff 49 39 c9 b9 ff ff ff ff 41 0f 42 c9 0f 57 c0 0f 11 44 24 38 4c 89 44 24 28 48 8d 54 24 50 48 89 54 24 20 89 4c 24 30 48 89 f9 31 d2 45 31 c0 45 31 c9 ff d0 3d 03 01 00 00 75 18 48 89 f9 ba ff ff ff ff e8 ?? ?? ?? ?? 8b 44 24 50 3d 03 01 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {b9 46 02 00 00 b2 01 e8 ?? ?? ?? ?? 48 89 [0-3] 03 07 07 07 48 89 [0-3] 31 c9 31 c9 48 89 [0-3] 49 89 [0-3] 31 c9 48 89 c2 41 b8 46 02 00 00 41 b9 02 00 00 00 e8 ?? ?? ?? ?? b9 46 02 00 00 b2 01 e8 ?? ?? ?? ?? 48 89 [0-3] 03 02 05 05 31 c9 49 89 [0-3] 48 89 [0-3] (31 c9|48 89 (??|?? ??)) 48 89 c2 41 b8 46 02 00 00 41 b9 02 00 00 00 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Hive_DAA_2147848835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.DAA!MTB"
        threat_id = "2147848835"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 31 da 48 89 94 24 [0-4] 0f b6 54 08 0a 0f b7 44 08 08 35 bd 3c 00 00 66 89 84 24 [0-4] 80 f2 4d 88 94 24 4a 08 00 00 41 b9 0b 00 00 00 4c 89 e1 4c 89 fa 49 89 f0 e8 [0-4] 84 c0 48 8d 35 [0-4] 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Hive_YAA_2147891837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.YAA!MTB"
        threat_id = "2147891837"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b 6c 11 08 48 33 6c 08 08 48 89 ac 0c ?? ?? ?? ?? 48 83 c1 08 48 83 f9 28 72}  //weight: 5, accuracy: Low
        $x_1_2 = {0f 92 c2 c0 e2 ?? 08 ca 8a 8c 04 ?? ?? ?? ?? 8d 59 ?? 80 fb ?? 0f 92 c3 c0 e3 ?? 08 cb 48 ?? ?? 38 da 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Hive_YY_2147894671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.YY!MTB"
        threat_id = "2147894671"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 04 13 48 8b 94 24 ?? 00 00 00 32 04 0a 48 8b 4c 24 ?? 30 04 29 48 ff c5 49 39 ef 48 8b 9c 24 d8 00 00 00 49 39 ec 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Hive_AF_2147907980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.AF!MTB"
        threat_id = "2147907980"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {47 0f b6 24 39 41 31 fc 4d 39 d0 77}  //weight: 2, accuracy: High
        $x_1_2 = "H4FAr4lQluM6QPWeV2d1/LY_BBfuGQbYRuWj4KPvD/69qVJ-VHV7LkDAMPzw9F/PdGgCmqa42Uq5tK0UsRg" ascii //weight: 1
        $x_1_3 = "main.malicious" ascii //weight: 1
        $x_1_4 = "main.infectBinaries" ascii //weight: 1
        $x_1_5 = "main.notInfectBin" ascii //weight: 1
        $x_1_6 = "main.xor" ascii //weight: 1
        $x_1_7 = "main.runHost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Hive_AHVI_2147940323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hive.AHVI!MTB"
        threat_id = "2147940323"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 d0 4d 29 d0 4d 89 c1 49 f7 d8 49 c1 f8 3f 4d 21 d0 4c 8b 5c 24 48 4b 8d 3c 03 4c 8b 64 24 38 66 ?? 49 39 cc 72 74 48 89 44 24 30 4d 29 d4 49 8d 51 e0 49 89 d2 48 f7 da 48 c1 fa 3f 48 21 d1 4a 8d 04 19 49 8d 5c 24 e0 4c 89 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

