rule Backdoor_Win64_Bedep_A_2147690266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bedep.A"
        threat_id = "2147690266"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bedep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 48 89 5c 24 20 48 8d 4c 24 08 55 56 57 41 54 41 55 41 56 41 57 e8 00 00 00 00 5a 48 83 ec 20 e8 fd 21 00 00 48 83 c4 58 48 33 c0 c3 e8 00 00 00 00 5e 48 81 ee 40 00 00 00 48 8b f9 48 8d 41 5a b9 1c 00 00 00 fc f3 48 a5 ff e0 48 8b f2 49 8b c8 49 8b f9 48 c1 e9 03 f3 48 a5 4c 8b 7c 24 28 48 8b 5c 24 30 4c 8b 4c 24 38 48 83 ec 28 48 8b ca 48 33 d2 49 c7 c0 00 80 00 00 41 ff d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bedep_A_2147690266_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bedep.A"
        threat_id = "2147690266"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bedep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 fc 0f be 1e f6 ea [0-3] 8a d3 2a d0 8b 45 fc [0-6] 80 ea 43 [0-3] 46 88 11 [0-6] 41 ff 4d 08 8b d3 [0-3] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 c4 28 48 85 c0 75 01 c3 48 8b c8 48 ?? ?? ?? ?? ?? ?? f7 c1 01 00 00 00 74 0d 48 ?? ?? ?? ?? ?? ?? 83 f1 01 48 33 d2 ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 83 c4 28 48 83 f8 01 76 08 48 8b c8 e9 35 00 00 00 c3 [0-4] 48 83 c4 08 48 8b d3 ff d0}  //weight: 1, accuracy: Low
        $x_2_4 = {74 12 44 3b cd 75 31 48 83 c1 02 48 3b cb 0f 87 db fb ff ff 66 0f ba e2 08 73 13 49 63 c1 48 c1 f8 03 48 03 c8 48 3b cb 0f 87 c1 fb ff ff 49 2b cf 8b c1 e9 ba fb ff ff 48 83 c1 04 eb cd}  //weight: 2, accuracy: High
        $x_1_5 = {83 e8 63 83 f8 0a 72 e4 48 3b cb 74 24 e8 ?? ?? ?? ?? 44 8b d8 8b c7 4c 33 d8 49 81 f3 c2 7a ba 1f 4d 69 db 81 3d 66 00 49 c1 eb 20 44 89 1e eb 02 33 db}  //weight: 1, accuracy: Low
        $x_2_6 = {8d 46 04 49 8b cc 42 c6 04 20 00 42 c7 04 26 2e 64 6c 6c e8 ?? ?? ?? ?? 48 85 c0 4c 8b d8 75 10 49 8b cc e8 ?? ?? ?? ?? 48 85 c0 4c 8b d8 74 2d 80 7f 01 23 74 2b}  //weight: 2, accuracy: Low
        $x_2_7 = {bf 7b 00 00 c0 78 ?? 81 39 2a d8 12 1c}  //weight: 2, accuracy: Low
        $x_2_8 = {81 fa 96 02 04 7c 75 06 89 5c 24 ?? eb ?? 81 fa a3 46 41 9f}  //weight: 2, accuracy: Low
        $x_2_9 = {81 fa 96 02 04 7c 75 ?? 44 89 84 24 ?? ?? ?? ?? eb ?? 81 fa a3 46 41 9f}  //weight: 2, accuracy: Low
        $x_1_10 = {40 8a 39 40 80 ff 0f 75 23 49 8d 47 0f 49 03 cb 48 3b c8 77 cf 0f b6 39 48 8d 15 ?? ?? ?? ?? 45 8b f3 0f b7 94 7a ?? ?? ?? ?? eb 1c 40 0f b6 c7 48 8d 15}  //weight: 1, accuracy: Low
        $x_1_11 = {66 0f ba e2 08 73 13 49 63 c1 48 c1 f8 03 48 03 c8 48 3b ?? 0f 87 ?? fb ff ff [0-6] 8b c1 e9 ?? fb ff ff 48 83 c1 04 eb}  //weight: 1, accuracy: Low
        $x_2_12 = {bf 7b 00 00 c0 78 ?? 81 39 2a d8 12 1c 75}  //weight: 2, accuracy: Low
        $x_1_13 = {eb 08 48 8d 44 24 48 48 01 38 48 8b 6c 24 60 48 8b c3 48 8b 5c 24 58 48 83 c4 30 41 5c 5f 5e c3}  //weight: 1, accuracy: High
        $x_1_14 = {75 0e 41 83 e9 02 45 85 c9 7f cb 48 8b c2 eb 07 48 8b 12 eb a9}  //weight: 1, accuracy: High
        $x_1_15 = {eb 60 44 0f b7 47 58 4a 8d 4c 20 fe 66 44 89 39 44 89 40 18 48 8b d1 49 2b d0 48 89 50 10 0f b7 47 48 48 2b c8 89 43 08 4c 8b c0 48 89 0b 48 8b 57 50 e8 ?? ?? ?? ?? 4d 3b ef 74 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win64_Bedep_A_2147690320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bedep.A!!Bedep.gen!A"
        threat_id = "2147690320"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bedep"
        severity = "Critical"
        info = "Bedep: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 fc 0f be 1e f6 ea [0-3] 8a d3 2a d0 8b 45 fc [0-6] 80 ea 43 [0-3] 46 88 11 [0-6] 41 ff 4d 08 8b d3 [0-3] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 c4 28 48 85 c0 75 01 c3 48 8b c8 48 ?? ?? ?? ?? ?? ?? f7 c1 01 00 00 00 74 0d 48 ?? ?? ?? ?? ?? ?? 83 f1 01 48 33 d2 ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 83 c4 28 48 83 f8 01 76 08 48 8b c8 e9 35 00 00 00 c3 [0-4] 48 83 c4 08 48 8b d3 ff d0}  //weight: 1, accuracy: Low
        $x_2_4 = {74 12 44 3b cd 75 31 48 83 c1 02 48 3b cb 0f 87 db fb ff ff 66 0f ba e2 08 73 13 49 63 c1 48 c1 f8 03 48 03 c8 48 3b cb 0f 87 c1 fb ff ff 49 2b cf 8b c1 e9 ba fb ff ff 48 83 c1 04 eb cd}  //weight: 2, accuracy: High
        $x_1_5 = {83 e8 63 83 f8 0a 72 e4 48 3b cb 74 24 e8 ?? ?? ?? ?? 44 8b d8 8b c7 4c 33 d8 49 81 f3 c2 7a ba 1f 4d 69 db 81 3d 66 00 49 c1 eb 20 44 89 1e eb 02 33 db}  //weight: 1, accuracy: Low
        $x_2_6 = {8d 46 04 49 8b cc 42 c6 04 20 00 42 c7 04 26 2e 64 6c 6c e8 ?? ?? ?? ?? 48 85 c0 4c 8b d8 75 10 49 8b cc e8 ?? ?? ?? ?? 48 85 c0 4c 8b d8 74 2d 80 7f 01 23 74 2b}  //weight: 2, accuracy: Low
        $x_2_7 = {bf 7b 00 00 c0 78 ?? 81 39 2a d8 12 1c}  //weight: 2, accuracy: Low
        $x_2_8 = {81 fa 96 02 04 7c 75 06 89 5c 24 ?? eb ?? 81 fa a3 46 41 9f}  //weight: 2, accuracy: Low
        $x_2_9 = {81 fa 96 02 04 7c 75 ?? 44 89 84 24 ?? ?? ?? ?? eb ?? 81 fa a3 46 41 9f}  //weight: 2, accuracy: Low
        $x_1_10 = {40 8a 39 40 80 ff 0f 75 23 49 8d 47 0f 49 03 cb 48 3b c8 77 cf 0f b6 39 48 8d 15 ?? ?? ?? ?? 45 8b f3 0f b7 94 7a ?? ?? ?? ?? eb 1c 40 0f b6 c7 48 8d 15}  //weight: 1, accuracy: Low
        $x_1_11 = {66 0f ba e2 08 73 13 49 63 c1 48 c1 f8 03 48 03 c8 48 3b ?? 0f 87 ?? fb ff ff [0-6] 8b c1 e9 ?? fb ff ff 48 83 c1 04 eb}  //weight: 1, accuracy: Low
        $x_2_12 = {bf 7b 00 00 c0 78 ?? 81 39 2a d8 12 1c 75}  //weight: 2, accuracy: Low
        $x_1_13 = {eb 08 48 8d 44 24 48 48 01 38 48 8b 6c 24 60 48 8b c3 48 8b 5c 24 58 48 83 c4 30 41 5c 5f 5e c3}  //weight: 1, accuracy: High
        $x_1_14 = {75 0e 41 83 e9 02 45 85 c9 7f cb 48 8b c2 eb 07 48 8b 12 eb a9}  //weight: 1, accuracy: High
        $x_1_15 = {eb 60 44 0f b7 47 58 4a 8d 4c 20 fe 66 44 89 39 44 89 40 18 48 8b d1 49 2b d0 48 89 50 10 0f b7 47 48 48 2b c8 89 43 08 4c 8b c0 48 89 0b 48 8b 57 50 e8 ?? ?? ?? ?? 4d 3b ef 74 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

