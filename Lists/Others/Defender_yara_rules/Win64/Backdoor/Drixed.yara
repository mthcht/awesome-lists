rule Backdoor_Win64_Drixed_A_2147689743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Drixed.A"
        threat_id = "2147689743"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 01 40 32 c7 75 03 [0-20] 40 38 3c 10 74 ?? 48 8d 1c 10 8a ?? 40 32}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8b 4b 58 8a 83 9c 00 00 00 30 04 39 48 ff c7 48 3b 7b 60 72 ea}  //weight: 2, accuracy: High
        $x_2_3 = {83 ee 05 b2 90 89 75 38 e8 ?? ?? ?? ?? 45 8d 44 24 fc 48 8d 55 38 48 8d 4d c1 c6 45 c0 e9}  //weight: 2, accuracy: Low
        $x_1_4 = {48 63 79 3c 48 03 f9 81 3f 50 45 00 00 75 df 8b 57 50 48 8b 4f 30 bb 04 00 00 00 44 8b cb 41 b8 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {62 6f 74 5f 78 33 32 00}  //weight: 1, accuracy: High
        $x_1_6 = {62 6f 74 5f 78 36 34 00}  //weight: 1, accuracy: High
        $x_1_7 = {66 6f 72 6d 67 72 61 62 62 65 72 00}  //weight: 1, accuracy: High
        $x_1_8 = {63 6c 69 63 6b 73 68 6f 74 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {68 74 74 70 69 6e 6a 65 63 74 73 00}  //weight: 1, accuracy: High
        $x_1_10 = {68 74 74 70 73 68 6f 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win64_Drixed_C_2147696314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Drixed.C"
        threat_id = "2147696314"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Drixed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 fa 03 75 07 e8 ?? ?? ?? ?? eb ?? 85 d2 75 ?? 3d ee ac ff e7 75}  //weight: 5, accuracy: Low
        $x_1_2 = {81 bb 00 04 00 00 ef be ad de}  //weight: 1, accuracy: High
        $x_1_3 = {63 6c 69 63 6b 73 68 6f 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win64_Drixed_Q_2147794853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Drixed.Q!MTB"
        threat_id = "2147794853"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Drixed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4c 8b 5c 24 28 43 8a 1c 13 45 89 c0 44 89 c6 2a 1c 31 48 8b 4c 24 18 42 88 1c 11 01 d0 8b 54 24 24 39 d0 89 44 24 04}  //weight: 10, accuracy: High
        $x_10_2 = {4c 8b 44 24 30 4c 8b 4c 24 30 4c 8b 54 24 10 47 8a 1c 02 4c 8b 04 24 47 88 1c 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

