rule Ransom_Win64_Magniber_ZZ_2147787867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.ZZ"
        threat_id = "2147787867"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 ff 69 00 65 00 c7 45 03 78 00 70 00 c7 45 07 6c 00 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 0f 2e 00 65 00 c7 45 13 78 00 65 00 66 44 89 65 17 c7 45 c7 6e 00 74 00 c7 45 cb 64 00 6c 00 c7 45 cf 6c 00 2e 00 c7 45 d3 64 00 6c 00 c7 45 d7 6c 00 00 00 c7 45 df 6b 00 65 00 c7 45 e3 72 00 6e 00 c7 45 e7 65 00 6c 00 c7 45 eb 33 00 32 00 c7 45 ef 2e 00 64 00 c7 45 f3 6c 00 6c 00 66 44 89 65 f7}  //weight: 1, accuracy: High
        $x_1_3 = {40 30 39 41 03 ff 81 ff ff 00 00 00 41 0f 44 ff 49 03 cf 49 2b d7 75 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_DA_2147788025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.DA!MTB"
        threat_id = "2147788025"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d6 45 8d 7c 24 01 48 8b d8 49 8b ce 40 30 39 41 03 ff 81 ff ff 00 00 00 41 0f 44 ff 49 03 cf 49 2b d7 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_AD_2147809472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.AD!MTB"
        threat_id = "2147809472"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c1 eb 05 00 48 33 c1 48 23 e0 48 8b ec 48 83 ec 10 48 33 db 48 c7 c7 ?? ?? ?? ?? 48 89 7d f0 48 89 5d f8 6a 40 68 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8d 4d f0 4d 33 c0 48 8d 55 f8 48 33 c0 48 c7 c0 ?? ?? ?? ?? 48 c7 c1 ?? ?? ?? ?? 48 33 c8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 83 ec 10 48 33 db 48 c7 c7 ?? ?? ?? ?? 48 89 7d f0 48 89 5d f8 6a 40 68 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 8d 4d f0 4d 33 c0 48 8d 55 f8 48 b9 ff ff ff ff ff ff ff ff e8}  //weight: 1, accuracy: Low
        $x_2_5 = {48 ff c6 eb 05 00 48 ff c6 48 ff c7 48 ff c1 48 81 f9 ?? ?? ?? ?? 8a a6 ?? ?? ?? ?? 32 a6 ?? ?? ?? ?? 32 ?? 8a ?? 88 27 48 ff c6}  //weight: 2, accuracy: Low
        $x_2_6 = {48 ff c6 e9 05 00 48 ff c6 48 ff c7 48 ff c1 48 81 f9 ?? ?? ?? ?? 8a a6 ?? ?? ?? ?? 32 a6 ?? ?? ?? ?? 32 ?? 8a ?? 88 27 48 ff c6}  //weight: 2, accuracy: Low
        $x_2_7 = {48 ff c6 e9 05 00 48 ff c6 48 ff c7 48 ff c1 48 81 f9 ?? ?? ?? ?? 8a a6 ?? ?? ?? ?? 32 e0 80 f4 43 88 27 8a c4 48 ff c6}  //weight: 2, accuracy: Low
        $x_2_8 = {48 ff c6 e9 05 00 48 ff c6 48 ff c7 48 ff c1 48 81 f9 ?? ?? ?? ?? 8a a6 ?? ?? ?? ?? 32 a6 ?? ?? ?? ?? 32 e0 8a c4 88 27 48 ff c6}  //weight: 2, accuracy: Low
        $x_2_9 = {49 ff c6 e9 05 00 49 ff c6 49 ff c5 48 ff c1 48 81 f9 ?? ?? ?? ?? 41 8a 86 ?? ?? ?? ?? 41 32 86 ?? ?? ?? ?? 32 c2 8a d0 41 88 45 00 49 ff c6}  //weight: 2, accuracy: Low
        $x_2_10 = {49 ff c6 eb 05 00 49 ff c6 49 ff c5 48 ff c1 48 81 f9 ?? ?? ?? ?? 41 8a 86 ?? ?? ?? ?? 41 32 86 ?? ?? ?? ?? 32 c2 8a d0 41 88 45 00 49 ff c6}  //weight: 2, accuracy: Low
        $x_2_11 = {48 ff c6 eb 05 00 48 ff c6 48 ff c7 48 ff c1 48 81 f9 ?? ?? ?? ?? 8a 86 ?? ?? ?? ?? 32 86 ?? ?? ?? ?? 32 c2 8a d0 88 07 48 ff c6}  //weight: 2, accuracy: Low
        $x_2_12 = {48 ff c6 e9 05 00 48 ff c6 48 ff c7 48 ff c1 48 81 f9 ?? ?? ?? ?? 8a 86 ?? ?? ?? ?? 32 86 ?? ?? ?? ?? 32 c2 8a d0 88 07 48 ff c6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_Magniber_2147816453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber!MTB"
        threat_id = "2147816453"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c6 e9 05 00 48 ff c6 48 ff c7 48 ff c2 48 81 fa ?? ?? 00 00 8a be ?? ?? 00 00 32 fb 80 f7 ?? 88 3f 8a df 48 ff c6}  //weight: 1, accuracy: Low
        $x_1_2 = {48 ff c6 eb 05 00 48 ff c6 48 ff c7 48 ff c2 48 81 fa ?? ?? 00 00 8a be ?? ?? 00 00 32 fb 80 f7 ?? 88 3f 8a df 48 ff c6}  //weight: 1, accuracy: Low
        $x_1_3 = {48 ff c6 e9 05 00 48 ff c6 48 ff c7 48 ff c2 48 81 fa ?? ?? 00 00 8a ae ?? ?? 00 00 32 e9 80 f5 ?? 88 2f 8a cd 48 ff c6}  //weight: 1, accuracy: Low
        $x_1_4 = {48 ff c6 eb 05 00 48 ff c6 48 ff c7 48 ff c2 48 81 fa ?? ?? 00 00 8a ae ?? ?? 00 00 32 e9 80 f5 ?? 88 2f 8a cd 48 ff c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win64_Magniber_ADA_2147818567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.ADA!MTB"
        threat_id = "2147818567"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c6 eb 05 00 48 ff c6 48 ff c7 48 ff c2 48 81 fa ?? ?? ?? ?? 8a ae ?? ?? ?? ?? 32 e8 80 f5 ?? 88 2f 8a c5 48 ff c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_A_2147836454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.A"
        threat_id = "2147836454"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3 [0-6] b8 ?? ?? 00 00 0f 05 c3 [0-6] b8 ?? ?? 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 69 00 6e 00 6e 00 74 00 00 00 2e 00 00 00 2e 00 2e 00 00 00 5c 00 00 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 68 00 74 00 6d 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "= new Array(" ascii //weight: 1
        $x_1_4 = "fromCharCode" ascii //weight: 1
        $x_1_5 = {72 65 67 69 73 74 72 61 74 69 6f 6e 3e 3c 2f 73 63 72 69 70 74 6c 65 74 3e 00}  //weight: 1, accuracy: High
        $x_1_6 = " /i:../../../" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_A_2147836454_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.A"
        threat_id = "2147836454"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3 [0-6] b8 ?? ?? 00 00 0f 05 c3 [0-6] b8 ?? ?? 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 69 00 6e 00 6e 00 74 00 00 00 2e 00 00 00 2e 00 2e 00 00 00 5c 00 00 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 68 00 74 00 6d 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "= new Array(" ascii //weight: 1
        $x_1_4 = "fromCharCode" ascii //weight: 1
        $x_1_5 = {23 40 7e 5e [0-4] 41 41 41 3d 3d}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 00 45 00 3a 00 56 00 42 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 65 00 20 00 [0-4] 2e 00 2e 00 2f 00 2e 00 2e 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_A_2147836454_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.A"
        threat_id = "2147836454"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3 [0-6] b8 ?? ?? 00 00 0f 05 c3 [0-6] b8 ?? ?? 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 69 00 6e 00 6e 00 74 00 00 00 2e 00 00 00 2e 00 2e 00 00 00 5c 00 00 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 68 00 74 00 6d 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "= new Array(" ascii //weight: 1
        $x_1_4 = "fromCharCode" ascii //weight: 1
        $x_1_5 = "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide //weight: 1
        $x_1_6 = {3c 2f 68 74 6d 6c 3e 00 e8 00 00 00 00 58 48 83 e8 05 48 2d ?? ?? 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_PC_2147841939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.PC!MTB"
        threat_id = "2147841939"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 86 37 03 00 00 e9 79 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {32 86 0b 03 00 00 e9 87 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {32 c2 eb 86}  //weight: 1, accuracy: High
        $x_1_4 = {8a d0 eb 4c}  //weight: 1, accuracy: High
        $x_1_5 = {88 07 eb eb}  //weight: 1, accuracy: High
        $x_1_6 = {48 ff c6 eb 70}  //weight: 1, accuracy: High
        $x_1_7 = {48 ff c7 e9 f6 fe ff ff}  //weight: 1, accuracy: High
        $x_1_8 = {48 ff c1 e9 cf 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_CR_2147841940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.CR!MTB"
        threat_id = "2147841940"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c1 e9 50 ff ff ff 7a 5e 6f 0d 9b 8e 3e b7 2e 13 99 a2 c8 a2 da 45 86 5e eb 94 43 1a 5b 18 c8 1e 65 b3 5d df f7 db 56 8a d0 e9 40 ff ff ff 2f 36 90 06 e6 eb 05 bf 73 af 37 04 48 ff c6 e9 f8 fe ff ff d5 56 2c 56 a2 5e 21 ca 65 ed c6 d2 8a 86 ed 02 00 00 eb 15 ca d6 27 60 91 b5 0c 69 2a c7 dc 92 2c c4 f3 59 e9 49 fd ff ff 32 86 c0 02 00 00 e9 1f ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_PAA_2147842062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.PAA!MTB"
        threat_id = "2147842062"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c9 eb 05 00 48 33 c9 32 c0 8a a6 ?? ?? ?? ?? 32 e0 80 f4 ?? 88 27 8a c4 48 ff c6 48 ff c7 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b fc eb 05 00 4c 8b fc 48 83 e4 ?? 48 8b ec 48 83 ec ?? 48 33 db 48 c7 c7 ?? ?? ?? ?? 48 89 7d ?? 48 89 5d ?? 49 c7 c6 ?? ?? ?? ?? 49 81 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_PAB_2147842913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.PAB!MTB"
        threat_id = "2147842913"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 33 d2 eb 05 00 48 33 d2 32 c0 8a a6 ?? ?? ?? ?? 32 a6 ?? ?? ?? ?? 32 e0 8a c4 88 27 48 ff c6 48 ff c7 48 ff c2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_A_2147848494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.gen!A"
        threat_id = "2147848494"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3 [0-6] b8 ?? ?? 00 00 0f 05 c3 [0-6] b8 ?? ?? 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 69 00 6e 00 6e 00 74 00 00 00 2e 00 00 00 2e 00 2e 00 00 00 5c 00 00 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 68 00 74 00 6d 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "= new Array(" ascii //weight: 1
        $x_1_4 = "fromCharCode" ascii //weight: 1
        $x_1_5 = {e8 00 00 00 00 58 48 83 e8 05 48 2d ?? ?? ?? 00 c3}  //weight: 1, accuracy: Low
        $x_1_6 = {b9 4c 77 d6 07 e8 ?? ?? ?? ?? 48 8d [0-8] ff d0 b9 49 f7 02 78 4c 8b e0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win64_Magniber_PAC_2147848875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.PAC!MTB"
        threat_id = "2147848875"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 ff c6 eb 05 00 48 ff c6 ff 05 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8a a2 ?? ?? ?? ?? 32 a2 ?? ?? ?? ?? 32 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 26 48 ff c2}  //weight: 2, accuracy: Low
        $x_2_2 = {48 ff c6 eb 05 00 48 ff c6 ff 05 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8a aa ?? ?? ?? ?? 32 aa ?? ?? ?? ?? 32 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 2e 48 ff c2}  //weight: 2, accuracy: Low
        $x_2_3 = {48 ff c6 e9 05 00 48 ff c6 ff 05 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8a aa ?? ?? ?? ?? 32 aa ?? ?? ?? ?? 32 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 2e 48 ff c2}  //weight: 2, accuracy: Low
        $x_2_4 = {48 ff c6 e9 05 00 48 ff c6 ff 05 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8a a2 ?? ?? ?? ?? 32 a2 ?? ?? ?? ?? 32 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 26 48 ff c2}  //weight: 2, accuracy: Low
        $x_2_5 = {48 ff c6 eb 05 00 48 ff c6 ff 05 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8a 8a ?? ?? ?? ?? 32 8a ?? ?? ?? ?? 32 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 88 0e 48 ff c2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win64_Magniber_B_2147849407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.gen!B"
        threat_id = "2147849407"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c0 4c 8b d1 b8 ?? 00 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 eb [0-128] 48 83 e8 05 eb [0-128] 48 2d ?? ?? ?? 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 4c 77 d6 07 e8 ?? ?? ?? ?? 48 8d [0-8] ff d0 b9 49 f7 02 78 4c 8b e0 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {ff d0 b9 3a 56 29 a8 e8 ?? ?? ?? ?? b9 77 87 2a f1 48 89 ?? ?? e8 ?? ?? ?? ?? b9 d3 6b 6e d4}  //weight: 1, accuracy: Low
        $x_1_5 = {74 6d dd 6e c7 45 ?? 07 c0 75 4e 48 c7 ?? ?? 00 02 00 00 48 89 ?? ?? c7 44 ?? ?? 00 10 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_B_2147849407_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.gen!B"
        threat_id = "2147849407"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3 [0-48] b8 ?? ?? 00 00 0f 05 c3 [0-48] b8 ?? ?? 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 48 83 e8 05 48 2d ?? ?? ?? 00 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 4c 77 d6 07 e8 ?? ?? ?? ?? 48 8d [0-8] ff d0 b9 49 f7 02 78 4c 8b e0 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {ff d0 b9 3a 56 29 a8 e8 ?? ?? ?? ?? b9 77 87 2a f1 48 89 ?? ?? e8 ?? ?? ?? ?? b9 d3 6b 6e d4}  //weight: 1, accuracy: Low
        $x_1_5 = {74 6d dd 6e c7 45 ?? 07 c0 75 4e 48 c7 ?? ?? 00 02 00 00 48 89 ?? ?? c7 44 ?? ?? 00 10 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_B_2147849407_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.gen!B"
        threat_id = "2147849407"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3 [0-48] b8 ?? ?? 00 00 0f 05 c3 [0-48] b8 ?? ?? 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 eb [0-128] 48 83 e8 05 eb [0-128] 48 2d ?? ?? ?? 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 4c 77 d6 07 e8 ?? ?? ?? ?? 48 8d [0-8] ff d0 b9 49 f7 02 78 4c 8b e0 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {ff d0 b9 3a 56 29 a8 e8 ?? ?? ?? ?? b9 77 87 2a f1 48 89 ?? ?? e8 ?? ?? ?? ?? b9 d3 6b 6e d4}  //weight: 1, accuracy: Low
        $x_1_5 = {74 6d dd 6e c7 45 ?? 07 c0 75 4e 48 c7 ?? ?? 00 02 00 00 48 89 ?? ?? c7 44 ?? ?? 00 10 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_PAI_2147851012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.PAI!MTB"
        threat_id = "2147851012"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 82 72 0c 00 00 32 05 ?? ?? ?? ?? 88 05 9e 3d 01 00 88 06 48 ff c2 48 ff c6 ff 05 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8a 82 8f 0c 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_GA_2147932059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.GA!MTB"
        threat_id = "2147932059"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a a6 e1 09 00 00 32 e0 80 f4 fe 88 27 8a c4 48 ff c6 48 ff c7 48 ff c1 48 81 f9 8b 9c 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Magniber_YBI_2147953002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.YBI!MTB"
        threat_id = "2147953002"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a ae ae 06 00 00 32 e8 80 f5 ?? 88 2f 8a c5 48 ff c6}  //weight: 1, accuracy: Low
        $x_1_2 = {8a a6 62 ba 01 00 32 e0 80 f4 ?? 88 27 8a c4 48 ff c6 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win64_Magniber_YBJ_2147953003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Magniber.YBJ!MTB"
        threat_id = "2147953003"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 7d f0 48 89 5d f8 49 c7 c6 ?? ?? ?? ?? 49 81 f6 ?? ?? ?? ?? 41 56 49 c7 c6 ?? ?? ?? ?? 49 81 f6 ?? ?? ?? ?? 41 56 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

