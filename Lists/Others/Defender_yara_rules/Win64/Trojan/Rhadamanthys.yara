rule Trojan_Win64_Rhadamanthys_FIA_2147852509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.FIA!MTB"
        threat_id = "2147852509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 89 44 24 50 48 8b 44 24 40 48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 0f b6 00 88 44 24 24 0f b6 44 24 24 33 44 24 50 48 8b 4c 24 40 48 8b 94 24 ?? ?? ?? ?? 48 03 d1 48 8b ca 88 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_RAZ_2147894727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.RAZ!MTB"
        threat_id = "2147894727"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8b f1 48 c1 ee 03 8d 7a 08 4c 2b f3 48 ff c6 48 8d 4c 24 60 4c 8b c7 48 8b d5 e8 ?? ?? ?? ?? 4c 8b cb 4c 8b c5 33 d2 49 8b cd e8 ?? ?? ?? ?? 48 8b cf 41 8a 04 1e 30 03 48 ff c3 48 ff c9 75}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 8b f1 48 c1 eb 03 bf ?? ?? ?? ?? 4c 2b f6 48 ff c3 48 8b d5 48 8b ce 4c 8b c7 48 2b d6 41 8a 04 0e 32 01 88 04 0a 48 ff c1 49 ff c8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_FIF_2147900901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.FIF!MTB"
        threat_id = "2147900901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 8d 28 01 00 00 48 8b 95 98 ?? ?? ?? 48 03 d1 48 8b ca 88 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_GXZ_2147904893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.GXZ!MTB"
        threat_id = "2147904893"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 6e c6 44 24 ?? 65 c6 44 24 ?? 6c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 56 c6 44 24 ?? 69 c6 44 24 ?? 72 c6 44 24 ?? 74 c6 44 24 ?? 75 c6 44 24 ?? 61 c6 44 24 ?? 6c c6 44 24 ?? 41 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 6f c6 44 24 ?? 63 41 b8 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_ZKA_2147905474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.ZKA!MTB"
        threat_id = "2147905474"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b cd 41 b8 ?? ?? ?? ?? 48 2b cb 49 8b d0 4c 8b db 42 8a 04 1e 41 32 03 42 88 04 19 49 83 c3 01 48 83 ea 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_CCHZ_2147905535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.CCHZ!MTB"
        threat_id = "2147905535"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 8a 04 1e 41 32 03 42 88 04 19 49 83 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_MKP_2147932420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.MKP!MTB"
        threat_id = "2147932420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff d0 48 83 c4 20 43 8a 04 3c 4c 8b 7d 70 48 8b 4d ?? 41 02 04 0c 0f b6 c0 41 8a 04 04 48 8b 4d 80 4c 8b 65 e0 42 32 04 21 42 88 04 21 48 b8 51 63 bb ed 3e b6 72 96 48 03 05 2f 0c 13 00 48 83 ec 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_IPK_2147933563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.IPK!MTB"
        threat_id = "2147933563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 41 0f 6e 54 05 fc 66 41 0f 6e 5c 05 00 66 0f 60 d6 66 0f 61 d6 66 0f 60 de 66 0f 61 de 66 0f ef ca 66 0f ef c3 48 83 c0 10 66 0f 6f d9 66 0f 6f d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_BS_2147935429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.BS!MTB"
        threat_id = "2147935429"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {a9 05 89 09 41 0d 11 11 d9 14 35 16 f5 19 b5 1d 6d 21 1d 25}  //weight: 3, accuracy: High
        $x_1_2 = {48 83 ec 38 48 8d 4c 24 28 e8}  //weight: 1, accuracy: High
        $x_1_3 = {6a 09 6b 31 6b 59 6b 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_A_2147935987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.A!MTB"
        threat_id = "2147935987"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 28 44 24 20 0f 28 4c 24 30 0f 29 4c 24 50 0f 29 44 24 40 48 8b 05 2b 46 11 00 48 8b 00 48 85 c0 ?? ?? 25 00 40 00 00 31 c9 48 09 c8 ?? ?? ?? ?? ?? ?? 4c 8d [0-16] 41 b9 08 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {48 c7 44 24 20 0c 00 00 00 41 b8 1b 00 00 00 48 8d 7c 24 50 48 89 f9 48 8d 15 71 8d 06 00 4c 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? 48 89 fa e8 ?? ?? ?? ?? 31 c0 48 3b 44 24 30 0f 81 ?? ?? ?? ?? 4c 8b 6c 24 38 48 8b 7c 24 40 31 c9 31 d2 4d 89 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NR_2147937186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NR!MTB"
        threat_id = "2147937186"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 45 bf c6 45 ef 01 48 89 44 24 28 45 33 c9 48 83 64 24 20 00 45 33 c0 33 d2 c7 45 eb 16 00 00 00 33 c9 e8 35 5b fe ff 83 cf ff}  //weight: 2, accuracy: High
        $x_1_2 = {74 0f 8b 5d eb 48 8d 4d bf e8 6d 5c fe ff 89 58 20 80 7d f7 00 74 0f 8b 5d f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NR_2147937186_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NR!MTB"
        threat_id = "2147937186"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 d1 e0 48 85 c0 0f 85 9b 00 00 00 31 c0 86 05 f5 3e 0a 00 3c 02 74 7e 83 bd ?? 00 00 00 01 0f 85 a6 fd ff ff 4c 8b b5 ?? 00 00 00 0f b6 95 00 01 00 00 f6 c2 01}  //weight: 3, accuracy: Low
        $x_1_2 = {f6 c2 01 0f 85 82 fd ff ff 48 8b 05 26 3f 0a 00 48 8b 00 48 d1 e0 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_KKL_2147942934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.KKL!MTB"
        threat_id = "2147942934"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 10 48 8d 54 24 40 48 8b 44 24 58 44 30 10 49 8b c6 83 e0 0f 48 03 c8 41 0f b6 04 24 32 01 32 85 ?? ?? ?? ?? 88 01 48 8d 4c 24 60 e8 ff f9 ff ff 4c 8b a5 ?? ?? ?? ?? 43 30 04 34 4d 8b f5 49 81 fd 00 fe 07 00 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_PKV_2147943243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.PKV!MTB"
        threat_id = "2147943243"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 44 04 40 30 41 02 49 8d 47 03 48 03 c1 83 e0 0f 0f b6 44 04 ?? 30 41 03 49 8d 47 04 48 03 c1 83 e0 0f 0f b6 44 04 40 30 41 04 48 83 c1 06 48 83 ea 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_GVC_2147952054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.GVC!MTB"
        threat_id = "2147952054"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 43 8d 14 26 3b d0 0f 83 83 05 00 00 44 0f b6 44 15 10 41 8b d4 45 0f b6 54 17 10 45 33 c2 41 8b d4 45 88 44 15 10 41 ff c4 44 3b e7 7c d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_GVD_2147953149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.GVD!MTB"
        threat_id = "2147953149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 08 41 89 c5 45 28 e5 44 32 6c 24 04 41 f6 dd 31 c0 49 39 d7 0f 92 c0 c1 e0 03 8d 04 40 4a 8b b4 08 ?? ?? ?? ?? 4c 01 d6 4c 89 f8 ff e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_GTV_2147954928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.GTV!MTB"
        threat_id = "2147954928"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 03 c6 41 8b c2 c1 c0 0a 45 8b f7 33 d0 45 8b fc 41 8b c2 45 8b e1 c1 c8 02 46 8d 0c 07 33 d0 8b fb 41 8b c5 49 83 c3 04 23 c3 41 8b dd 33 c8 45 8b ea 03 d1 46 8d 14 02}  //weight: 5, accuracy: High
        $x_5_2 = {89 5c 24 28 44 89 6c 24 ?? 44 89 7c 24 ?? f3 0f 6f 44 05 ?? f3 0f 6f 4c 04 ?? 66 0f fe c8 f3 0f 7f 4c 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_ARS_2147954941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.ARS!MTB"
        threat_id = "2147954941"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d1 48 8b 4c 24 18 48 01 c1 48 89 4c 24 18 48 8b 4c 24 28 48 8b 11 48 8b 0a 48 8b 44 24 20 48 8b 5c 24 10 ff d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_AMB_2147955947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.AMB!MTB"
        threat_id = "2147955947"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f ba f2 1f 33 d0 8b c2 24 01 f6 d8 1b c9 d1 ea 81 e1 ?? ?? ?? ?? 42 33 8c 84 ?? ?? ?? ?? 33 ca 42 89 4c 84 34 49 ff c0}  //weight: 5, accuracy: Low
        $x_5_2 = {68 00 74 74 70 00 3a 00 2f 00 2f 00 31 00 37 00 36 00 2e 00 34 00 36 00 2e 00 31 00 35 00 32 00 2e 00 36 00 32 00 3a 00 35 00 38 00 35 00 38 00 2f 00 [0-10] 2e 00 65 00 78 00 65 00}  //weight: 5, accuracy: Low
        $x_5_3 = {68 74 74 70 3a 2f 2f 31 37 36 2e 34 36 2e 31 35 32 2e 36 32 3a 35 38 35 38 2f [0-10] 2e 65 78 65}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Rhadamanthys_ARM_2147957084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.ARM!MTB"
        threat_id = "2147957084"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b6 54 1c 20 89 d1 44 01 d2 41 89 d0 41 c1 f8 1f 41 c1 e8 18 44 01 c2 0f b6 d2 44 29 c2 41 89 d2 48 63 d2 44 0f b6 44 14 20 46 88 44 1c 20 88 4c 14 20 42 02 4c 1c 20 0f b6 c9 0f b6 54 0c 20 30 13 48 83 c3 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_PGRM_2147957318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.PGRM!MTB"
        threat_id = "2147957318"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 44 24 48 f2 0f 10 84 24 ?? ?? ?? ?? f2 0f 58 05 ?? ?? ?? ?? f2 0f 59 05 ?? ?? ?? ?? f2 0f 2c c0 0f b6 c0 48 8b 4c 24 48 0f b6 09 33 c8 8b c1 48 8b 4c 24 48 88 01 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_DA_2147957461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.DA!MTB"
        threat_id = "2147957461"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c0 01 99 c1 ea ?? 01 d0 0f b6 c0 29 d0 4c 63 d8 42 0f b6 54 1c ?? 89 d1 44 01 d2 41 89 d0 41 c1 f8 ?? 41 c1 e8 18 44 01 c2 0f b6 d2 44 29 c2 41 89 d2 48 63 d2 44 0f b6 44 14 ?? 46 88 44 1c ?? 88 4c 14 20 42 02 4c 1c ?? 0f b6 c9 0f b6 54 0c ?? 30 13 48 83 c3 ?? 49 39 d9 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_ARAL_2147957547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.ARAL!MTB"
        threat_id = "2147957547"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c1 fa 07 48 89 de 48 c1 fb 3f 48 29 da 48 69 d2 68 01 00 00 48 89 f7 48 29 d6 48 89 31 48 c1 eb 3e 48 8d 14 3b 48 89 d3 48 c1 fa 02 48 b8 06 5b b0 05 5b b0 05 5b 48 89 d6 48 f7 ea 48 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NQA_2147957591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NQA!MTB"
        threat_id = "2147957591"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f 6e c0 49 8d 41 10 66 0f 70 c0 00 66 0f fc c1 41 0f 11 01}  //weight: 1, accuracy: High
        $x_2_2 = {48 89 c0 48 89 db 4c 89 c8 80 30 94 48 87 e4 48 83 c0 01 4c 39 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NQB_2147957619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NQB!MTB"
        threat_id = "2147957619"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f db c2 66 0f fc c1 66 0f ef c9 66 0f 6f d9 66 0f f8 d8}  //weight: 1, accuracy: High
        $x_2_2 = {66 0f db c2 66 0f fc c3 66 0f f8 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_GVB_2147957624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.GVB!MTB"
        threat_id = "2147957624"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 32 b1 4d 8d 24 24 48 83 c2 01 4c 39 c2 75 f0}  //weight: 2, accuracy: High
        $x_1_2 = {4d 8d 6d 00 88 08 48 83 c0 01 4c 39 c0 75 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_RR_2147957705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.RR!MTB"
        threat_id = "2147957705"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c0 90 52 48 8d 12 5a 4c 89 c0 66 90 80 30 72 48 89 c9 48 87 db 48 83 c0 01 48 39 c8 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_RR_2147957705_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.RR!MTB"
        threat_id = "2147957705"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 c2 48 8d 05 [0-5] 89 d9 31 c1 89 c8 31 d0 89 05 ?? ?? ?? ?? eb [0-5] 53 48 83 ec 20 48 89 cb b9 14 00 00 00 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NQF_2147957747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NQF!MTB"
        threat_id = "2147957747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_1_3 = {66 0f db c2 66 0f fc c1 66 0f ef c9 66 0f f8 c8}  //weight: 1, accuracy: High
        $x_2_4 = {f3 0f 6f 00 48 83 c0 10 66 0f ef c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_MK_2147957824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.MK!MTB"
        threat_id = "2147957824"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {f6 21 88 01 4d 8d 6d 00 90 4d 8d 36 48 83 c1 01 4c 39 c1 75}  //weight: 25, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NQH_2147958007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NQH!MTB"
        threat_id = "2147958007"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_1_3 = {48 89 f8 80 30 70 4d 8d 6d 00 48 83 c0 01 48 39 f0 75 f0}  //weight: 1, accuracy: High
        $x_2_4 = {80 30 7b 48 83 c0 01 4c 39 c0 75 f4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NQI_2147958008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NQI!MTB"
        threat_id = "2147958008"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_1_3 = {f3 0f 6f 00 48 83 c0 10 66 0f ef c1 0f 11 40 f0}  //weight: 1, accuracy: High
        $x_2_4 = {48 89 c2 66 0f 70 c0 00 66 0f ef c8 66 0f ef c2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NQO_2147958372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NQO!MTB"
        threat_id = "2147958372"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_3_3 = {66 0f 6e c2 41 81 ?? ?? ?? ?? ?? ?? 66 0f 70 c0 00 66 0f ef}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NQP_2147958386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NQP!MTB"
        threat_id = "2147958386"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_3_3 = {66 0f 6e c0 66 81 ?? ?? ?? ?? 66 0f 70 c0 00 66 0f ef}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NQQ_2147958444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NQQ!MTB"
        threat_id = "2147958444"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_3_3 = {66 0f 6e c1 81 ?? ?? ?? ?? ?? ?? 66 0f 70 c0 00 66 0f ef}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NRA_2147958594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NRA!MTB"
        threat_id = "2147958594"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_3_3 = {66 0f 6e c2 66 81 ?? ?? ?? ?? 66 0f 70 c0 00 66 0f ef}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NRD_2147958679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NRD!MTB"
        threat_id = "2147958679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_3_3 = {4c 89 d8 66 0f 70 c9 00 f3 0f 6f 01 48 83 c1 10 66 0f ef}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NRF_2147958827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NRF!MTB"
        threat_id = "2147958827"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_3_3 = {69 c0 6d 4e c6 41 31 d2 05 39 30 00 00 25 ff ff ff 7f 89 05 ?? ?? ?? ?? 48 83 c4 20 41 f7 f0}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NRE_2147958835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NRE!MTB"
        threat_id = "2147958835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_3_3 = {66 0f 71 f0 ?? 66 0f 71 d1 ?? 66 0f db c2 66 0f db cb 66 0f eb c1}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_AHD_2147958926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.AHD!MTB"
        threat_id = "2147958926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {44 0f b6 01 41 c0 c8 ?? 4d 89 db 44 88 01 4d 87 ff 90 4d 89 ff}  //weight: 30, accuracy: Low
        $x_20_2 = {4d 87 f6 4d 89 f6 4d 87 f6 4d 89 f6 48 89 c0 48 89 db 48 89 c9 48 89 d2}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NRG_2147959134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NRG!MTB"
        threat_id = "2147959134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_2_3 = {66 0f 6e ca 66 0f 70 c9 00 f3 41 0f 6f 02 49 83 c2 10 66 0f ef c1 41 0f 11 42}  //weight: 2, accuracy: High
        $x_3_4 = {48 0f af d1 48 c1 ea 24 8d 14 92 c1 e2 02 29 d0 83 f8 13}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rhadamanthys_NQJ_2147959185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NQJ!MTB"
        threat_id = "2147959185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_2_3 = {66 0f 6e c0 66 41 81 72 ?? ?? ?? 66 0f 70 c0 00 66 0f ef c8}  //weight: 2, accuracy: Low
        $x_2_4 = {66 0f 71 f2 ?? 66 0f db d1 66 0f f8 c2 f3 41 0f 6f 51}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Rhadamanthys_NRB_2147959186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rhadamanthys.NRB!MTB"
        threat_id = "2147959186"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChainingModeCBC" ascii //weight: 1
        $x_1_2 = "BCryptDecrypt" ascii //weight: 1
        $x_3_3 = {66 0f fc c1 66 0f 71 d1 ?? 66 0f fc c0 66 0f db ca 66 0f fc c0 66 0f eb c1}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

