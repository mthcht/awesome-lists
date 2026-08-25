rule Trojan_Win64_Remus_C_2147967667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.C!MTB"
        threat_id = "2147967667"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {87 ff 0e 00 0f 10 05 ?? ?? ?? ?? 0f 29 44 24 ?? 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 ?? c7 44 24 ?? 00 00 00 00 8b 44 24 ?? 83 f8 14 77}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 4c d1 04 4c 89 6c 24 ?? 0f 11 74 24 ?? 48 c7 44 24 ?? 00 00 00 08 48 c7 44 24 ?? 02 00 00 00 41 b9 04 00 00 00 ba 07 00 00 00 4c 8d 44 24 ?? e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_DA_2147972599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.DA!MTB"
        threat_id = "2147972599"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b6 42 11 88 41 21 0f b6 42 12 88 41 22 0f b6 42 13 88 41 23 0f b6 42 14 88 41 24 0f b6 42 15 88 41 25 0f b6 42 16 88 41 26 0f b6 42 17 88 41 27 0f b6 42 18 88 41 28 0f b6 42 19 88 41 29 0f b6 42 1a 88 41 2a 0f b6 42 1b 88 41 2b 0f b6 42 1c 88 41 2c 0f b6 42 1d 88 41 2d 0f b6 42 1e 88 41 2e 0f b6 42 1f 88 41 2f 44 89 49 30 49 c1 e9 20 44 89 49 34 41 8b 00 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_AX_2147972704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.AX!MTB"
        threat_id = "2147972704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 85 c0 74 51 48 8b 48 18 48 85 c9 74 48 48 8b 51 20 48 83 c1 20 31 c0 48 39 ca 74 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_PL_2147973608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.PL!MTB"
        threat_id = "2147973608"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 2c 48 63 c9 ff 44 24 2c 8b 54 24 2c 69 d2 d2 40 00 00 66 33 54 4c 30 66 89 54 4c 30 8b 4c 24 2c 83 f9 0d 72 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_IDK_2147973615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.IDK!MTB"
        threat_id = "2147973615"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 85 c0 74 48 48 8b 48 18 48 85 c9 74 3f 4c 8d 51 20 45 33 c0 49 8b 0a 33 d2 49 3b ca 74 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_NYB_2147973647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.NYB!MTB"
        threat_id = "2147973647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetClipboardData" ascii //weight: 1
        $x_1_2 = "OpenClipboard" ascii //weight: 1
        $x_1_3 = {b1 79 37 9e 41 0f af d1 41 81 f1 b1 79 37 1e}  //weight: 1, accuracy: High
        $x_2_4 = {d1 e8 41 83 e0 01 41 f7 d8 41 21 d0 41 31 c0 44 89 c0 d1 e8 41 83 e0 01 41 f7 d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_NYD_2147973656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.NYD!MTB"
        threat_id = "2147973656"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GetClipboardData" ascii //weight: 1
        $x_1_2 = "OpenClipboard" ascii //weight: 1
        $x_1_3 = {69 c9 b8 7d 6d 5c 41 31 c8 8b 4c 24 ?? 85 c9 74 e3}  //weight: 1, accuracy: Low
        $x_2_4 = {81 e1 54 8a fe 9f 41 89 c0 0d 54 8a fe 1f 0f af c1 81 f1 54 8a fe 9f 41 81 e0 ab 75 01 60}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_MK_2147973798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.MK!MTB"
        threat_id = "2147973798"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 83 ec 58 b9 99 68 51 89 e8 ?? ?? 02 00 48 89 05 ?? ?? 03 00 b9 17 a3 aa e6 e8 ?? ?? 02 00 48 89 05 ?? ?? 03 00 c7 44 24}  //weight: 20, accuracy: Low
        $x_15_2 = "GetUserNameA" ascii //weight: 15
        $x_10_3 = "GetComputerNameExA" ascii //weight: 10
        $x_3_4 = "OpenClipboard" ascii //weight: 3
        $x_2_5 = "GetClipboardData" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_MKA_2147974737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.MKA!MTB"
        threat_id = "2147974737"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 83 ec 58 b9 51 80 41 a1 e8 ?? ?? 02 00 48 89 05 ?? ?? 03 00 b9 47 0d 06 f2 e8 ?? ?? 02 00 48 89 05 ?? ?? 03 00 48 89 c1}  //weight: 20, accuracy: Low
        $x_15_2 = "GetUserNameA" ascii //weight: 15
        $x_10_3 = "GetComputerNameExA" ascii //weight: 10
        $x_3_4 = "OpenClipboard" ascii //weight: 3
        $x_2_5 = "GetClipboardData" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_NZD_2147975281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.NZD!MTB"
        threat_id = "2147975281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetClipboardData" ascii //weight: 1
        $x_1_2 = "OpenClipboard" ascii //weight: 1
        $x_1_3 = {69 c9 67 f7 a4 7a 41 31 c8 8b 4c 24 30 85 c9}  //weight: 1, accuracy: High
        $x_2_4 = {41 81 e1 e4 bc f4 ef 41 89 c2 41 81 e2 1b 43 0b 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Remus_DB_2147975369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.DB!MTB"
        threat_id = "2147975369"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e f9 f0 5c 9b bf 43 23 62 86 30 e9 d9 4c 9b af bf 12 77 76 11 d9 e4 3c dd 9f 9d 02 4f 66 22 c9 ed 2c d5 8f 90 f2 49 56 11 b9 1e 1c c6 7f bd e2 65 46 4c a9 1f 0c c1 6f 8d d2 8a 35 42 99 13 fc f7 5f ad c2 80 25 73 89 33 ec f5 4f cb b2 80 15 75 79 25 dc 20 3f f8 a2 b0 05 66 69 2e cc 02 2f d6 92 b2 f5 68 59 59 bc 66 1f d0 85 41 0b cf 90 20 16 88 9b 19 21 75 a7 ee 2c 55 b2 a5 37 39 bd f0 42 0e d5 71}  //weight: 1, accuracy: High
        $x_1_2 = {c0 b6 e5 de 8c 57 81 a4 67 9f 01 93 65 2d a3 78 04 10 a2 c5 bf 99 df 1d 82 70 c6 c0 f3 00 d3 3a 53 32 71 92 02 33 80 55 9d 39 27 22 d1 f4 2a c2 c3 67 c3 09 12 d8 45 56 e2 e3 c9 07 8d f4 99 d5 8f 9e 05 5e be 13 58 fb a6 37 d3 c3 c5 5e 9b 74 d8 f8 3d f6 29 79 7c cc b0 52 80 da 16 be ba 2e 3c 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Remus_NZ_2147976949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.NZ!MTB"
        threat_id = "2147976949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 33 54 4c 30 66 89 54 4c 30 8b 4c 24 2c 83 f9 0e}  //weight: 3, accuracy: High
        $x_1_2 = {8b 4c 24 30 ff 44 24 30 8b 4c 24 30 69 c9 ?? ?? ?? ?? 41 31 c8 8b 4c 24 30 85 c9 74 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

