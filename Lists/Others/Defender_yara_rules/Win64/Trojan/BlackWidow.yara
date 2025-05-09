rule Trojan_Win64_BlackWidow_RPZ_2147910377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.RPZ!MTB"
        threat_id = "2147910377"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 05 00 30 00 00 48 8b 8c 24 f0 00 00 00 48 89 81 b0 00 00 00 8b 44 24 44 35 1b 0f 00 00 89 44 24 44 8b 44 24 50 35 ca 05 00 00 89 84 24 84 00 00 00 8b 44 24 54 2d 29 05 00 00 89 84 24 80 00 00 00 8b 44 24 54 05 b1 00 00 00 89 44 24 7c 8b 44 24 4c 35 74 0a 00 00 89 44 24 78 8b 44 24 4c 05 6f 05 00 00 89 44 24 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_RPX_2147910378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.RPX!MTB"
        threat_id = "2147910378"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 8c 24 c0 00 00 00 8b 89 dc 00 00 00 33 c8 8b c1 48 8b 8c 24 c0 00 00 00 89 81 dc 00 00 00 48 63 44 24 3c 48 8b 8c 24 c0 00 00 00 48 8b 89 b0 00 00 00 48 8b 94 24 c0 00 00 00 8b 52 5c 8b 04 81 33 c2 48 63 4c 24 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_RPY_2147910379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.RPY!MTB"
        threat_id = "2147910379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 30 8b 40 20 48 8b 4c 24 70 48 03 c8 48 8b c1 8b 4c 24 20 48 8d 04 88 48 89 44 24 38 48 8b 44 24 38 8b 00 48 8b 4c 24 70 48 03 c8 48 8b c1 48 89 44 24 28 48 8b 4c 24 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GA_2147927843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GA!MTB"
        threat_id = "2147927843"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 31 d2 49 f7 f0 45 8a 14 11 44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 a7 8c 0a 00 76 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GB_2147928730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GB!MTB"
        threat_id = "2147928730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 0c 20 42 32 04 16 41 88 02 4d 03 d5 44 3b cb 72 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVA_2147929883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVA!MTB"
        threat_id = "2147929883"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 0c 20 43 32 04 13 41 88 02 4d 03 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVB_2147929884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVB!MTB"
        threat_id = "2147929884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 2b c8 0f b6 44 0c 20 43 32 44 0c fb 41 88 41 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GNQ_2147929894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GNQ!MTB"
        threat_id = "2147929894"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c5 c5 fd cb c5 c5 73 dc ?? c5 e5 69 d7 44 30 14 0f c5 dd 60 e1 48 ff c1 c5 c5 68 f9 48 89 c8 c4 e3 fd 00 ff ?? 48 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GNQ_2147929894_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GNQ!MTB"
        threat_id = "2147929894"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {45 8a 14 10 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 44 30 14 0f c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GNQ_2147929894_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GNQ!MTB"
        threat_id = "2147929894"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 0f b6 44 0c ?? 43 32 44 08 ?? 41 88 41 ?? 49 ff cb 0f 85}  //weight: 10, accuracy: Low
        $x_10_2 = {48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 48 0f af cb 8a 44 0c ?? 43 32 04 13 41 88 02 4d 03 d4 45 3b cd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_BlackWidow_GVC_2147930060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVC!MTB"
        threat_id = "2147930060"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8a 14 11}  //weight: 1, accuracy: High
        $x_3_2 = {44 30 14 0f}  //weight: 3, accuracy: High
        $x_1_3 = {49 81 c1 12 ce 2b 00}  //weight: 1, accuracy: High
        $x_2_4 = {48 81 f9 d3 ?? ?? ?? 0f 86 07 f6 ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVD_2147931011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVD!MTB"
        threat_id = "2147931011"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 30 14 0f [0-16] 48 ff c1 [0-16] 48 89 c8 [0-16] 48 81 f9 [0-16] [0-16] 48 31 d2 [0-16] 49 f7 f0 [0-16] 45 8a 14 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_MKZ_2147932214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.MKZ!MTB"
        threat_id = "2147932214"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 f1 66 0f 62 c1 45 8a 14 10 45 0f 5f ca 45 0f 5d dc 45 0f 52 d6 44 0f c2 f8 ?? c5 f1 61 c2 c5 d9 6a dd c4 c1 41 f9 f0 c5 f5 61 c2 c5 dd 6a dd 44 30 14 0f 66 0f 6a f9 48 ff c1 66 0f 6a d5 48 89 c8 66 0f 6d ce 48 81 f9 d3 3b 01 00 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_MKK_2147932379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.MKK!MTB"
        threat_id = "2147932379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 f1 c5 e5 71 f3 07 c4 e3 fd 00 f6 ?? c4 e3 fd 00 ff ?? 45 8a 14 10 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 44 30 14 0f c5 f5 ef c9 c5 e5 75 db 48 ff c1 c5 fd 69 f4 c5 fd 61 c4 48 89 c8 c5 fd 62 c3 48 81 f9 d3 3b 01 00 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_MIP_2147932477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.MIP!MTB"
        threat_id = "2147932477"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 31 d2 c5 f5 ef c9 49 f7 f1 c5 e5 75 db c5 e5 71 f3 ?? 45 8a 14 10 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 c5 cd 75 f6 c5 cd 71 d6 ?? c5 cd db f7 44 30 14 0f c5 c5 fd cb 48 ff c1 c5 e5 67 db 48 89 c8 c5 fd 69 f4 48 81 f9 d3 3b 01 00 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_LMK_2147932721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.LMK!MTB"
        threat_id = "2147932721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c5 cd 68 f1 49 f7 f1 c5 d5 fd f5 c5 ed fd e2 c5 f5 fd f9 45 8a 14 10 66 0f 38 de f1 66 0f 38 de f9 66 44 0f 38 de c1 66 44 0f 38 de c9 44 30 14 0f c5 cd fd eb c5 dd fd d3 c5 c5 fd cb c5 fd fd db c5 d5 fd f5 48 ff c1 c5 fd 6f da c5 fd 6f ec c5 fd fd c6 48 89 c8 ?? 48 81 f9 d3 3d 01 00 0f 86}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_MMD_2147932722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.MMD!MTB"
        threat_id = "2147932722"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 f1 66 0f 38 40 d6 45 8a 14 10 66 0f 38 40 d6 0f 28 dc 0f 28 d5 0f 14 e7 0f 14 ee 0f 28 c3 66 0f 70 dc ?? 44 30 14 0f c4 e2 6d 40 d4 48 ff c1 66 0f 70 dc ?? 66 0f 70 e5 00 48 89 c8 66 0f 70 fa 00 48 81 f9 d3 3d 01 00 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_ZZP_2147932786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.ZZP!MTB"
        threat_id = "2147932786"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 f0 c4 43 2d 0f d2 08 45 8a 14 11 c4 43 1d 0f e4 ?? c4 43 1d 46 e0 13 c4 e3 5d 0f e4 04 c4 43 1d 0f e4 0c c4 43 2d 0f d2 08 c4 43 0d 0f f6 04 c5 cd 72 d6 19 48 83 c7 02 0f f5 c2 44 30 54 0f ?? c4 43 1d 0f e4 0c 48 83 ef 02 c4 e3 5d 0f e4 04 48 ff c1 c4 43 1d 46 e0 13 48 89 c8 0f 6a cc 48 81 f9 d3 35 01 00 0f 86}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_LLZ_2147934028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.LLZ!MTB"
        threat_id = "2147934028"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 44 30 14 0f c5 c5 73 d8 02 c5 fd 69 f4 c5 fd 61 c4 c5 dd 73 dc 02 c5 f5 73 db ?? c5 e5 69 d7 c5 e5 61 df c5 dd 69 e9 c5 dd 61 e1}  //weight: 5, accuracy: Low
        $x_4_2 = {48 ff c1 c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 07 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 48 89 c8 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd c5 c5 73 d8 ?? c5 fd 69 f4 c5 fd 61 c4 48 81 f9 94 fc 01 00 0f 86}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_MYZ_2147934286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.MYZ!MTB"
        threat_id = "2147934286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 03 cd 48 f7 e1 48 c1 ea 04 48 8d 04 d2 48 03 c0 48 2b c8 49 0f af cb 8a 44 0c ?? 42 32 04 16 41 88 02 4d 03 d5 44 3b cb 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_MHD_2147934505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.MHD!MTB"
        threat_id = "2147934505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 03 de 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 19 48 2b c8 8a 44 0c 20 42 32 04 13 41 88 02 4c 03 d6 45 3b dc 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_UTD_2147934829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.UTD!MTB"
        threat_id = "2147934829"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 f1 c5 fd 6f da c5 fd 6f ec c5 fd fd c6 c5 f5 fd cf c5 fd 67 c0 c5 f5 67 c9 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 c5 e5 67 db 45 8a 14 10 c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 44 30 14 0f c5 c5 73 d8 02}  //weight: 5, accuracy: High
        $x_4_2 = {48 ff c1 c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 07 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 48 89 c8 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd c5 c5 73 d8 ?? c5 fd 69 f4 c5 fd 61 c4 48 81 f9 d3 41 00 00 0f 86}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVF_2147934995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVF!MTB"
        threat_id = "2147934995"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 0c 02 41 33 48 78 49 8b 80 b0 00 00 00 41 89 0c 02 49 83 c2 04 8b 05 ?? ?? ?? ?? 41 8b 50 74 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVG_2147934996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVG!MTB"
        threat_id = "2147934996"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 8a 14 11}  //weight: 1, accuracy: High
        $x_3_2 = {44 30 14 0f}  //weight: 3, accuracy: High
        $x_1_3 = {48 81 f9 d3 35 01 00 0f 86}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVH_2147934999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVH!MTB"
        threat_id = "2147934999"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8a 14 10 [0-50] 44 30 14 0f [0-50] 48 ff c1 [0-50] 48 89 c8 [0-50] 48 81 f9 ?? ?? ?? ?? [0-50] 48 31 d2 [0-50] 49 f7 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_WTD_2147935028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.WTD!MTB"
        threat_id = "2147935028"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 f1 c5 cd fd eb c5 dd fd d3 c5 c5 fd cb c5 fd fd db c5 d5 fd f5 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 45 8a 14 10 c5 cd 75 f6 c5 cd 71 d6 ?? c5 cd db f7 c5 c5 71 d7 08 c5 fd 6f c8 c5 fd 6f da c5 fd 6f ec 44 30 14 0f c5 fd fd}  //weight: 5, accuracy: Low
        $x_4_2 = {48 ff c1 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd 48 89 c8 c5 fd 61 c4 c5 dd 73 dc 02 c5 f5 73 db ?? c5 e5 69 d7 c5 e5 61 df 48 81 f9 d3 41 00 00 0f 86}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVI_2147935567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVI!MTB"
        threat_id = "2147935567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 30 1c 0f [0-16] 48 ff c1 [0-16] 48 89 c8 [0-16] 48 81 f9 ?? ?? ?? ?? [0-32] 48 31 d2 [0-16] 49 f7 f4 [0-16] 45 8a 1c 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVJ_2147935768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVJ!MTB"
        threat_id = "2147935768"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8a 24 11 [0-50] 44 30 24 0f [0-50] 48 ff c1 [0-50] 48 89 c8 [0-50] 48 81 f9 ?? ?? ?? ?? [0-50] 48 31 d2 [0-50] 49 f7 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_PPN_2147936459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.PPN!MTB"
        threat_id = "2147936459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 f1 c5 dd fd d3 c5 c5 fd cb c5 fd fd db c5 d5 fd f5 c5 ed fd e2 45 8a 14 10 c5 c5 68 f9 c5 cd fd eb c5 dd fd d3 c5 c5 fd cb c5 fd fd db c5 d5 fd f5 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 c5 cd 75 f6 c5 cd 71 d6 ?? c5 cd db f7 c5 c5 71 d7 08 c5 fd 6f c8 c5 fd 6f da 44 30 14 0f c5 fd 67 c0 c5 f5 67 c9}  //weight: 5, accuracy: Low
        $x_4_2 = {48 ff c1 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd c5 c5 73 d8 02 c5 fd 69 f4 48 89 c8 c5 fd 61 c4 c5 dd 73 dc ?? c5 f5 73 db 02 c5 e5 69 d7 c5 e5 61 df c5 dd 69 e9 c5 dd 61 e1 48 81 f9 d3 3d 01 00 0f 86}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_MLU_2147936671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.MLU!MTB"
        threat_id = "2147936671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 f1 c5 fd 67 c0 c5 f5 67 c9 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd c5 c5 73 d8 ?? 45 8a 14 10 c5 e5 61 df c5 dd 69 e9 c5 dd 61 e1 c5 fd 70 f8 4e c5 fd 62 c3 c5 e5 6a dc c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 07 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 44 30 14 0f c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVK_2147936709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVK!MTB"
        threat_id = "2147936709"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b d1 8b ca 48 63 c9 48 0f af c1 0f b6 44 04 78 8b 4c 24 4c 33 c8 8b c1 48 63 4c 24 24 48 8b 54 24 60 88 04 0a eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_MPZ_2147936782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.MPZ!MTB"
        threat_id = "2147936782"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 f1 44 0f 14 c0 44 0f 14 c9 66 0f 70 e2 ?? 66 0f 70 eb 00 66 41 0f d9 c0 66 41 0f d9 c1 66 41 0f d9 c2 66 41 0f d9 c3 66 41 0f d9 c4 45 8a 14 10 66 41 0f d9 c4 66 41 0f d9 c2 66 41 0f d9 c6 66 41 0f d9 c7 66 0f f1 d3 66 0f f1 d0 66 0f f2 da 0f 28 d8 0f 14 d1 66 0f 70 ec 00 66 0f 38 de d1 44 30 14 0f 66 0f 38 de f1 66 0f 38 de f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVL_2147936792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVL!MTB"
        threat_id = "2147936792"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 89 44 24 68 48 63 4c 24 50 33 d2 48 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 84 04 ?? ?? ?? ?? 8b 4c 24 68 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 58 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVM_2147936793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVM!MTB"
        threat_id = "2147936793"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8a 14 10 [0-50] 44 30 14 0f [0-80] 48 ff c1 [0-80] 48 89 c8 [0-80] 48 81 f9 ?? ?? ?? ?? [0-80] 48 31 d2 [0-80] 49 f7 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVO_2147937125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVO!MTB"
        threat_id = "2147937125"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b c8 48 8b 45 ?? 0f b6 4c 0d ?? 43 32 4c 10 ff 41 88 4c 00 ff 3b 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVQ_2147937576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVQ!MTB"
        threat_id = "2147937576"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8a 14 10 [0-60] 44 30 14 0f [0-40] 48 ff c1 [0-120] 48 89 c8 [0-80] 48 81 f9 ?? ?? ?? ?? [0-100] 48 31 d2 [0-50] 49 f7 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_CCJW_2147938514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.CCJW!MTB"
        threat_id = "2147938514"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 89 84 24 ?? ?? ?? ?? 33 d2 48 8b 8c 24 ?? ?? ?? ?? 48 8b c1 48 8b 8c 24 ?? ?? ?? ?? 48 f7 f1 0f b6 84 04 ?? ?? ?? ?? 8b 4c 24 58 33 c8 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_MKA_2147939261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.MKA!MTB"
        threat_id = "2147939261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f af c8 8b c1 48 98 48 8b 8c 24 ?? ?? ?? ?? 48 2b c8 48 8b c1 0f b6 84 04 ?? ?? ?? ?? 8b 4c 24 68 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 58 88 04 0a e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_ERD_2147939357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.ERD!MTB"
        threat_id = "2147939357"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 8b d0 c1 ea 18 88 14 01 41 8b d0 ff 05 87 0b 01 00 8b 05 c1 0b 01 00 01 83 58 01 00 00 48 8b 05 cc 0b 01 00 48 63 8b ?? ?? ?? ?? c1 ea 10 88 14 01 41 8b d0 ff 83 ?? ?? ?? ?? 48 8b 0d b7 0a 01 00 c1 ea 08 8b 81 1c 01 00 00 33 05 28 0c 01 00 35 8a 56 0f 00 89 81 1c 01 00 00 48 63 0d 36 0b 01 00 48 8b 83 e8 00 00 00 88 14 01 ff 05 26 0b 01 00 48 63 8b ?? ?? ?? ?? 48 8b 83 e8 00 00 00 44 88 04 01 ff 83 ?? ?? ?? ?? 49 81 f9 c0 5d 00 00 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVR_2147939959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVR!MTB"
        threat_id = "2147939959"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 f7 f1 48 8b c2 0f b6 84 04 ?? ?? ?? ?? 8b 4c 24 5c 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 60 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_GVS_2147939960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.GVS!MTB"
        threat_id = "2147939960"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 81 c0 c6 cf 0e 00 c5 f5 fd f9}  //weight: 2, accuracy: High
        $x_1_2 = {45 8a 14 10}  //weight: 1, accuracy: High
        $x_1_3 = {44 30 14 0f}  //weight: 1, accuracy: High
        $x_1_4 = {48 ff c1 0f 28 f0}  //weight: 1, accuracy: High
        $x_1_5 = {48 89 c8 66 44 0f 38 de c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_BY_2147940161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.BY!MTB"
        threat_id = "2147940161"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 30 14 0f}  //weight: 2, accuracy: High
        $x_1_2 = {c4 e3 fd 00 ff d8 45 8a 14 10}  //weight: 1, accuracy: High
        $x_1_3 = {c5 cd 71 d6 08 c5 cd db f7}  //weight: 1, accuracy: High
        $x_1_4 = {c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_BG_2147940888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.BG!MTB"
        threat_id = "2147940888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 31 d2 49 f7 f6 45 8a 2c 11}  //weight: 1, accuracy: High
        $x_1_2 = {49 f7 e3 49 01 c7}  //weight: 1, accuracy: High
        $x_1_3 = {44 30 2c 0f}  //weight: 1, accuracy: High
        $x_2_4 = "yG7B^>SWx1523Y)2u+" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlackWidow_BH_2147941019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackWidow.BH!MTB"
        threat_id = "2147941019"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackWidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c8 c5 e5 71 f3 07 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8}  //weight: 1, accuracy: High
        $x_1_2 = {45 8a 14 10}  //weight: 1, accuracy: High
        $x_1_3 = {4c 8b 45 f8}  //weight: 1, accuracy: High
        $x_2_4 = "W2Bx5$K)UfwQuk+Dt^LB" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

