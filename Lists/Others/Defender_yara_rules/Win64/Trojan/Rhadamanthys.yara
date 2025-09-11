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

