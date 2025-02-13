rule Backdoor_Win64_Mozaakai_A_2147754311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.A"
        threat_id = "2147754311"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 6c 00 74 00 65 00 73 00 74 00 [0-4] 20 00 2f 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 5f 00 74 00 72 00 75 00 73 00 74 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 5f 00 74 00 72 00 75 00 73 00 74 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 6c 74 65 73 74 [0-4] 20 2f 64 6f 6d 61 69 6e 5f 74 72 75 73 74 73 20 2f 61 6c 6c 5f 74 72 75 73 74 73}  //weight: 1, accuracy: Low
        $x_1_3 = "net view /all /domain" ascii //weight: 1
        $x_1_4 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 [0-48] 2d 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 6c 00 69 00 63 00 79 00 20 00 42 00 79 00 70 00 61 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 6f 77 65 72 53 68 65 6c 6c 2e 65 78 65 20 [0-48] 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73}  //weight: 1, accuracy: Low
        $x_1_6 = {6f 00 73 00 5b 00 31 00 5d 00 3d 00 [0-16] 26 00 6f 00 73 00 5b 00 32 00 5d 00 3d 00 [0-16] 26 00 6f 00 73 00 5b 00 33 00 5d 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6f 73 5b 31 5d 3d [0-16] 26 6f 73 5b 32 5d 3d [0-16] 26 6f 73 5b 33 5d 3d}  //weight: 1, accuracy: Low
        $x_1_8 = ".bazar/api/v" ascii //weight: 1
        $x_1_9 = "newgame.bazar" ascii //weight: 1
        $x_1_10 = "thegame.bazar" ascii //weight: 1
        $x_1_11 = "portgame.bazar" ascii //weight: 1
        $x_1_12 = {38 41 8b c3 f7 f3 [0-3] 30 44 8b d8 [0-3] 39 ?? ?? 41 8a c1 34 01 c0 e0 05 04 07 02}  //weight: 1, accuracy: Low
        $x_1_13 = {83 79 3c 00 75 e3 3c 49 0f 84 b0 00 00 00 3c 4c 0f 84 9f 00 00 00 3c 54 0f 84 8e 00 00 00 3c 68 74 6c 3c 6a 74 5c 3c 6c 74 34 3c 74 74 24 3c 77 74 14 3c 7a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win64_Mozaakai_B_2147754313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.B"
        threat_id = "2147754313"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".bazar/api/v" ascii //weight: 3
        $x_2_2 = "d_debuglog.txt" ascii //weight: 2
        $x_1_3 = "bestgame.bazar" ascii //weight: 1
        $x_1_4 = "forgame.bazar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Mozaakai_A_2147754315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.A!!Mozaakai.A"
        threat_id = "2147754315"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "Mozaakai: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 6c 00 74 00 65 00 73 00 74 00 [0-4] 20 00 2f 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 5f 00 74 00 72 00 75 00 73 00 74 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 5f 00 74 00 72 00 75 00 73 00 74 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 6c 74 65 73 74 [0-4] 20 2f 64 6f 6d 61 69 6e 5f 74 72 75 73 74 73 20 2f 61 6c 6c 5f 74 72 75 73 74 73}  //weight: 1, accuracy: Low
        $x_1_3 = "net view /all /domain" ascii //weight: 1
        $x_1_4 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 [0-48] 2d 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 6c 00 69 00 63 00 79 00 20 00 42 00 79 00 70 00 61 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 6f 77 65 72 53 68 65 6c 6c 2e 65 78 65 20 [0-48] 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73}  //weight: 1, accuracy: Low
        $x_1_6 = {6f 00 73 00 5b 00 31 00 5d 00 3d 00 [0-16] 26 00 6f 00 73 00 5b 00 32 00 5d 00 3d 00 [0-16] 26 00 6f 00 73 00 5b 00 33 00 5d 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6f 73 5b 31 5d 3d [0-16] 26 6f 73 5b 32 5d 3d [0-16] 26 6f 73 5b 33 5d 3d}  //weight: 1, accuracy: Low
        $x_1_8 = ".bazar/api/v" ascii //weight: 1
        $x_1_9 = "newgame.bazar" ascii //weight: 1
        $x_1_10 = "thegame.bazar" ascii //weight: 1
        $x_1_11 = "portgame.bazar" ascii //weight: 1
        $x_1_12 = {38 41 8b c3 f7 f3 [0-3] 30 44 8b d8 [0-3] 39 ?? ?? 41 8a c1 34 01 c0 e0 05 04 07 02}  //weight: 1, accuracy: Low
        $x_1_13 = {83 79 3c 00 75 e3 3c 49 0f 84 b0 00 00 00 3c 4c 0f 84 9f 00 00 00 3c 54 0f 84 8e 00 00 00 3c 68 74 6c 3c 6a 74 5c 3c 6c 74 34 3c 74 74 24 3c 77 74 14 3c 7a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win64_Mozaakai_MK_2147773199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.MK!MTB"
        threat_id = "2147773199"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 02 48 8d 52 ff 42 88 44 31 0c 48 ff c1 48 3b cb 7c ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Mozaakai_MK_2147773199_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.MK!MTB"
        threat_id = "2147773199"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 0a 48 8d 52 ff 42 88 4c 30 0c 48 ff c0 48 3b c7 7c ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Mozaakai_MK_2147773199_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.MK!MTB"
        threat_id = "2147773199"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 05 07 19 00 00 89 c1 80 f1 [0-1] 20 c1 89 c8 b2 [0-1] 20 d0 30 d1 08 c1 88 0d f0 [0-3] b8 [0-4] 45 31 ed e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 84 48 89 ca f7 d2 81 e2 [0-4] 81 e1 [0-4] 09 d1 81 f1 [0-4] 89 [0-3] 48 85 c0 b8 [0-2] 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Mozaakai_MK_2147773199_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.MK!MTB"
        threat_id = "2147773199"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 83 f8 [0-1] 74 [0-1] 8b 44 24 [0-1] 39 05 1b 97 02 00 8b 0d [0-4] 48 8b 44 24 [0-1] c6 04 08 [0-1] c7 44 24 [0-3] 00 00 e8 [0-4] c7 44 24 [0-3] 00 00 8b 05 [0-4] 83 c0 01 89 05 [0-4] eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 05 e6 d7 [0-2] 8b 0d f0 d7 00 33 c8 48 8b 05 3b d8 00 89 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Mozaakai_MAK_2147773857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.MAK!MTB"
        threat_id = "2147773857"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 c6 b9 [0-4] 2b c8 b8 [0-4] 8d 3c [0-1] c1 e7 [0-1] f7 ef 03 d7 c1 fa [0-1] 8b c2 c1 e8 [0-1] 03 d0 6b c2 [0-1] 2b f8 b8 01 83 c7 06 f7 ef 03 d7 c1 fa [0-1] 8b c2 c1 e8 05 03 d0 6b c2 06 2b f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Mozaakai_MBK_2147773929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.MBK!MTB"
        threat_id = "2147773929"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ee 89 e8 35 [0-4] 21 e8 f7 d5 81 e5 [0-4] 21 fe 09 ee 31 fe 89 f5 21 c5 31 f0 09 e8 89 84 [0-5] 4c 29 c3 4c 29 cb 4c 01 c3 4c 01 cb 48 ff c3 48 ff c1 48 83 f9 [0-1] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f2 89 f7 81 f7 [0-4] 21 f7 31 de 81 e6 [0-4] 44 21 fa 09 f2 44 31 fa 89 d6 21 fe 31 d7 09 f7 89 fa 31 da 81 e2 [0-4] 81 e7 [0-4] 09 d7 81 f7 [0-4] 89 7c [0-2] 4c 29 e9 4c 29 f1 4c 01 e9 4c 01 f1 48 ff c1 48 ff c0 48 83 f8 [0-1] 75}  //weight: 1, accuracy: Low
        $x_1_3 = {31 da 89 d7 21 ef 09 ea 31 fa 89 d7 31 df 81 e2 [0-4] 81 e7 [0-4] 09 d7 81 f7 [0-4] 89 7c [0-2] 48 ff c1 48 ff c0 48 83 f8 [0-1] 75}  //weight: 1, accuracy: Low
        $x_1_4 = {89 fd f7 d5 81 e5 [0-4] 89 fe 21 c6 09 ee 31 c6 81 e7 [0-4] 09 f7 89 [0-6] 48 ff c1 48 83 f9 [0-1] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win64_Mozaakai_ZY_2147778714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.ZY!MTB"
        threat_id = "2147778714"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 00 48 83 c2 01 49 83 e8 01 48 3b d7 88 44 32 [0-1] 7c ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Mozaakai_ZX_2147779742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.ZX!MTB"
        threat_id = "2147779742"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 00 48 ff c2 49 ff c8 48 3b d7 88 44 32 [0-1] 7c ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Mozaakai_BB_2147781649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.BB!MTB"
        threat_id = "2147781649"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 44 24 51 c6 44 24 52 2f c6 44 24 53 39 88 44 24 54 b0 3e 88 44 24 55 c6 44 24 56 0e c6 44 24 57 50 c6 44 24 58 5a c6 44 24 59 52 88 44 24 5a 88 44 24 5b c6 44 24 5c 4e}  //weight: 1, accuracy: High
        $x_1_2 = {48 c1 e9 20 01 d9 83 c1 [0-1] 89 ca c1 ea [0-1] c1 f9 [0-1] 01 d1 89 ca c1 e2 [0-1] 29 d1 01 d9 83 c1 00 88 4c 04 [0-1] 48 ff c0 48 83 f8 [0-1] 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 07 42 c6 47 01 22 c6 47 02 4f c6 47 03 59 c6 47 04 5e c6 47 05 79 b0 31 88 47 06 c6 47 07 58 88 47 08 88 47 09 c6 47 0a 40 c6 47 0b 04 c6 47 0c 11}  //weight: 1, accuracy: High
        $x_1_4 = {48 c1 e9 20 01 f9 83 c1 [0-1] 89 ca c1 ea [0-1] c1 f9 [0-1] 01 d1 89 ca c1 e2 [0-1] 29 d1 01 f9 83 c1 00 88 4c 04 50 48 ff c0 48 83 f8 [0-1] 75 82}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 44 24 50 23 c6 44 24 51 29 b3 68 88 5c 24 52 c6 44 24 53 76 c6 44 24 54 7d c6 44 24 55 70 c6 44 24 56 3e c6 44 24 57 32 88 5c 24 58 b3 0d 88 5c 24 59 88 5c 24 5a c6 44 24 5b 44}  //weight: 1, accuracy: High
        $x_1_6 = {48 c1 eb 20 01 d3 81 c3 [0-4] 89 df c1 ef [0-1] c1 fb [0-1] 01 fb 89 df c1 e7 [0-1] 29 fb 01 da 81 c2 00 88 54 0c [0-1] 48 ff c1 48 83 f9 [0-1] 75 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win64_Mozaakai_SD_2147914505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Mozaakai.SD!MTB"
        threat_id = "2147914505"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Mozaakai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 ca 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 41 ff c2 48 f7 e1 48 c1 ea ?? 48 8d 04 52 48 c1 e0 ?? 48 2b c8 49 2b cb 8a 44 0c ?? 42 32 04 0b 41 88 01 49 ff c1 45 3b d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

