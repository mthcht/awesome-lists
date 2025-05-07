rule Virus_Win64_Expiro_EN_2147724808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.EN!bit"
        threat_id = "2147724808"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 52 47 55 4a b9 60 00 00 00 00 00 00 00 65 4a 8b 11 56 4a 8b 72 10 4a 83 c2 18 4e 8b 2a 49 8b 55 10 41 57 4b 89 d5 4f 83 c5 30 49 8b 4d 00 4e 83 f9 00 74 2e 4e 8b 6a 60 4d 8b 7d 00 41 81 e7 df 00 df 00 4d 8b 6d 0c 45 c1 e5 08 45 01 fd 45 c1 e5 02 41 81 ed 2c cd 14 c9 4d 85 ed 0f 84 05 00 00 00 4a 8b 12 eb bc 8b 51 3c 48 83 c2 10 48 03 d1 46 8b 6a 78 4b 01 cd 43 56 45 8b 7d 20 4b 01 cf 45 8b 37}  //weight: 1, accuracy: High
        $x_1_2 = {e8 04 00 00 00 45 5f eb 29 46 8b 39 43 81 f7 ?? ?? ?? ?? 44 89 3a 49 ff cd 4f ff cd 4f ff cd 4d ff cd 48 83 c2 04 4a 83 c1 04 45 85 ed 74 02 eb d8}  //weight: 1, accuracy: Low
        $x_1_3 = {55 48 89 e5 41 55 41 56 41 57 48 83 ec 18 49 89 cf 49 c7 c6 02 00 00 00 48 c7 45 ?? 0c 00 00 00 48 c7 c0 0a 00 00 00 48 99 49 f7 fe 49 89 c3 48 c7 c0 1e 00 00 00 48 99 49 f7 fb 48 89 45 ?? 4d 89 dd 49 83 c5 03 4d 89 da 49 83 ea 03 49 c1 e2 02 4c 8b 4d ?? 49 b8 ?? ?? ?? ?? ?? ?? ?? ?? 4d 01 c1 47 89 0c 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_MF_2147725356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.MF!bit"
        threat_id = "2147725356"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8b 4f 60 4d 8b 19 43 81 e3 df 00 df 00 4f 8b 49 0b 47 01 d9 43 c1 e9 02 41 [0-6] 4d 85 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {45 8b 5d 00 41 [0-6] 47 89 1f 4b ff c9 4d ff c5}  //weight: 1, accuracy: Low
        $x_1_3 = {55 48 89 e5 41 57 48 83 ec 48 48 c7 45 e8 0c 00 00 00 48 c7 c0 30 00 00 00 4c 8b 55 e8 48 99 49 f7 fa 49 89 c7 48 c7 c0 04 00 00 00 48 99 49 f7 ff 48 89 45 e0 4d 89 fb 49 83 eb 03 4c 89 5d d8 48 c7 45 d0 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_MG_2147728553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.MG!bit"
        threat_id = "2147728553"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8b 73 60 4b 8b 36 81 e6 df 00 df 00 4d 8b 76 0b 43 01 f6 47 c1 e6 02}  //weight: 1, accuracy: High
        $x_1_2 = {8b 30 81 f6 ?? ?? ?? ?? 43 89 33 4f 83 c3 04 48 ff c0 45 83 ee 04 4a ff c0 4e ff c0 4c ff c0 47 85 f6 75 dc}  //weight: 1, accuracy: Low
        $x_1_3 = {55 48 89 e5 48 83 ec 30 4c 89 45 20 48 89 55 18 48 89 4d 10 49 c7 c3 06 00 00 00 48 c7 c0 48 00 00 00 48 99 49 f7 fb 48 89 45 e0 4d 89 da 49 83 ea 03 4c 89 55 f8 4c 8b 5d f8 49 83 c3 0a 4c 89 5d f0 49 83 eb 08 4c 89 5d e8 48 c7 c0 28 00 00 00 4c 8b 55 e8 48 99 49 f7 fa 48 89 45 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_MM_2147730109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.MM!bit"
        threat_id = "2147730109"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8b 61 60 4d 8b 1c 24 43 81 e3 df 00 df 00 4d 8b 64 24 0b 45 01 dc 45 c1 e4 02}  //weight: 1, accuracy: High
        $x_1_2 = {46 8b 1f 43 81 f3 ?? ?? ?? ?? 47 89 19 4e ff c7 4c ff c7 4e ff c7 41 83 ec 04 4d 81 c1 04 00 00 00 4e ff c7 47 85 e4 75 d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_MN_2147730151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.MN!bit"
        threat_id = "2147730151"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 78 60 4d 8b 1f 43 81 e3 df 00 df 00 4d 8b 7f 0c 43 c1 e7 08 47 01}  //weight: 1, accuracy: High
        $x_1_2 = {44 8b 19 43 81 f3 ?? ?? ?? ?? 46 89 18 4f ff cf 4f ff cf 4a ff c1 4e ff c1 4c ff c1 4b ff cf 4d ff cf 48 ff c1 4e 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_MO_2147730173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.MO!bit"
        threat_id = "2147730173"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4b 60 4c 8b 29 43 81 e5 df 00 df 00 4a 8b 49 0c c1 e1 08 43 03 cd c1 e1 02}  //weight: 1, accuracy: High
        $x_1_2 = {45 8b 2b 43 81 f5 ?? ?? ?? ?? 44 89 2b 49 ff c3 83 e9 04 4b ff c3 4f ff c3 4e 81 c3 04 00 00 00 4d ff c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_AA_2147850504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.AA!MTB"
        threat_id = "2147850504"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 51 52 53 55 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 55 48 8b ec 48 83 ec 20 48 83 e4 f0 48 8d 1d d6 39 f7 ff 48 ba 00 00 00 00 00 00 00 00 53 f7 93 90 02 00 00 81 b3 a0 02 00 00 e9 6d b2 28 f7 93 a4 03 00 00 f7 93 6c 03 00 00 81 83 d8 01 00 00 2a 39 44 7c f7 93 f8 00 00 00 81 43 14 6e 1b e8 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_DA_2147850511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.DA!MTB"
        threat_id = "2147850511"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 53 55 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 55 48 8b ec 48 83 ec 20 48 83 e4 f0 48 8d 1d ?? ?? ?? ?? 48 ?? 00 00 00 00 00 00 00 00 53 81 83 bc 03 00 00 43 00 3c 27 81 83 a8 01 00 00 d2 2d cb 3b 81 83 70 03 00 00 b9 79 04 09 81 b3 2c 02 00 00 5e 6f 7d 62 81 ab 1c 03 00 00 a4 29 6f 54 81 b3 f8 02 00 00 d7 6e e6 30}  //weight: 1, accuracy: Low
        $x_1_2 = {50 51 52 53 55 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 55 48 8b ec 48 83 ec 20 48 83 e4 f0 48 8d 1d ?? ?? ?? ?? 6a 00 5f 53 81 83 bc 03 00 00 43 00 3c 27 81 83 a8 01 00 00 d2 2d cb 3b 81 83 70 03 00 00 b9 79 04 09 81 b3 2c 02 00 00 5e 6f 7d 62 81 ab 1c 03 00 00 a4 29 6f 54 81 b3 f8 02 00 00 d7 6e e6 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Virus_Win64_Expiro_DD_2147852499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.DD!MTB"
        threat_id = "2147852499"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 53 55 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 55 48 8b ec 48 83 ec 20 48 83 e4 f0 48 8d ?? d6 ?? f7 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {04 00 00 48 81 ?? ?? 04 00 00 48 81 ?? ?? c0 08 00 04 00 48 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_EM_2147852531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.EM!MTB"
        threat_id = "2147852531"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 51 52 53 55 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 55 48 8b ec 48 83 ec 20 48 83 e4 f0}  //weight: 2, accuracy: High
        $x_3_2 = {48 81 c2 00 04 00 00 48 81 c3 00 04 00 00 48 81 fa 00 c0 08 00 74 05 e9}  //weight: 3, accuracy: High
        $x_3_3 = {48 81 c7 00 04 00 00 48 81 c0 00 04 00 00 48 81 ff 00 c0 08 00 74 05 e9}  //weight: 3, accuracy: High
        $x_3_4 = {c0 08 00 74 05 e9 12 00 48 81 ?? 00 04 00 00 48 81 ?? 00 04 00 00 48 81}  //weight: 3, accuracy: Low
        $x_3_5 = {c0 08 00 0f 85 12 00 48 81 ?? 00 04 00 00 48 81 ?? 00 04 00 00 48 81}  //weight: 3, accuracy: Low
        $x_3_6 = {c0 08 00 0f 84 12 00 48 81 ?? 00 04 00 00 48 81 ?? 00 04 00 00 48 81}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Virus_Win64_Expiro_DE_2147891320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.DE!MTB"
        threat_id = "2147891320"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 08 48 c7 04 24 00 00 00 00 48 83 c4 08 48 8b 4c 24 f8 48 c7 c2 a1 5a 00 00 49 c7 c0 00 30 00 00 49 c7 c1 40 00 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {54 d2 48 c7 c1 26 3e 00 00 41 b9 68 8d 00 00 41 ba 00 92 81 92 48 ff c9 44 30 0c 08 45 01 d1 41 d1 c1 48 85 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_PABG_2147892714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.PABG!MTB"
        threat_id = "2147892714"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 8b 50 60 4d 8b 2a 45 81 e5 df 00 df 00 4f 8b 52 0c 41 c1 e2 08 45 01 ea 45 c1 ea 01 41 81 ea a5 99 22 19 4f 85 d2 0f 84 08}  //weight: 1, accuracy: High
        $x_1_2 = {45 8b 45 00 4f 03 c1 41 8b 40 0b 81 e8 65 63 74 00 83 f8 00 75 05 e9 06 00 00 00 49 83 c5 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_DF_2147896165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.DF!MTB"
        threat_id = "2147896165"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 8b 48 60 48 8b 31 81 e6 df 00 df 00 48 8b 49 0b 03 ce c1 e9 02 81 e9 d2 4c 91 0c 4e 83 f9 00 74}  //weight: 1, accuracy: High
        $x_1_2 = {49 8b 5c 24 60 4c 8b 1b 45 81 e3 df 00 df 00 48 8b 5b 0b 46 01 db c1 eb 02 81 eb d2 4c 91 0c 4c 83 fb 00 74 09 49 8b 1c 24}  //weight: 1, accuracy: High
        $x_1_3 = {4f 8b 75 60 4b 8b 06 81 e0 df 00 df 00 4d 8b 76 0c 43 c1 e6 08 41 01 c6 41 c1 e6 01 43 81 ee 96 66 8a 64 49 83 fe 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Virus_Win64_Expiro_EK_2147900439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.EK!MTB"
        threat_id = "2147900439"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 57 41 56 41 55 0f 84 eb 01 00 00 0f 85 e5 01 00 00 48 8d 44 24 38 48 89 44 24 28 48 89 7c 24 20 b9 02 01 00 00 48 89 f2 0f 84 ab 00 00 00 0f 85 a5 00 00 00 4c 89 f1 ff d0 48 81 c4 98 00 00 00 5b 5d 0f 84 c6 01 00 00 0f 85 c0 01 00 00 00 00 00 00 31 f6 4c 8d 64 24 36 66 0f 1f 44 00 00 41 8b 54 b5 00 48 01 fa 4c 89 e1 ff d5 74 47 75 45}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_RPY_2147907702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.RPY!MTB"
        threat_id = "2147907702"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 90 a8 00 00 00 f7 90 e4 00 00 00 f7 90 54 02 00 00 f7 50 50 f7 90 88 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 81 c7 00 04 00 00 48 81 c0 00 04 00 00 48 81 ff 00 c0 08 00 74 05 e9 ?? ?? ff ff 59 e8 ?? ?? ff ff 48 8b e5 5d 41 5f 41 5e 41 5d 41 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_AEX_2147916241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.AEX!MTB"
        threat_id = "2147916241"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 5c 24 58 48 89 44 24 50 48 89 5c 24 48 48 89 5c 24 40 89 5c 24 38 89 5c 24 30 41 b9 00 00 cf 00 4c 8b c7 48 8b d7 33 c9 89 5c 24 28 89 5c 24 20 ff 15 7d 10 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_HNF_2147928180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.HNF!MTB"
        threat_id = "2147928180"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 8b 48 20 49 29 fa 4d 2b d1 41 c1 ea 01 44 8b 48 24 4f 01 d1 4b 01 f9 47 8b 11 43 c1 e2 10 41 c1 ea 0e 44 8b 48 1c 4f 01 d1 4c 03 cf 47 8b 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_HNG_2147928933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.HNG!MTB"
        threat_id = "2147928933"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 e9}  //weight: 10, accuracy: Low
        $x_1_2 = {2e 74 65 78 74 00 00 00 [0-232] 2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 e2}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 74 65 78 74 00 00 00 [0-232] 2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 60}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win64_Expiro_HNN_2147929545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.HNN!MTB"
        threat_id = "2147929545"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 66 0f 1f 84 00 00 00 00 00 ff e0}  //weight: 10, accuracy: High
        $x_1_2 = {2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 e2}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 60}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win64_Expiro_HNV_2147931541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.HNV!MTB"
        threat_id = "2147931541"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 40 00 00 00 ba 00 ff 00 [0-240] [0-48] 65 ?? 8b [0-2] 43 [0-3] 4d 8b ?? 10 49 ?? ?? 18 [0-9] 83 ?? 10 ?? 8b ?? ?? ?? ?? 8b ?? 30 ?? 83 ?? 00 74 ?? ?? 8b ?? 60 ?? 8b [0-2] 81 ?? df 00 df 00 ?? 8b ?? 0b [0-6] c1 [0-3] 81 [0-6] 83 ?? 00 74 ?? ?? 8b [0-8] 8b [0-5] 3c [0-5] 83 ?? 10 [0-5] 8b ?? 78 [0-6] 8b ?? 20 ?? 01 ?? ?? 8b ?? ?? ?? ?? 45 8b ?? 0b}  //weight: 1, accuracy: Low
        $x_3_2 = {b8 40 00 00 00 ba 00 ff 00 [0-240] 81 [0-8] 83 ?? 00 75 [0-16] eb ?? ?? 8b ?? 20 ?? 2b [0-6] c1 ?? 01 ?? 8b ?? 24 ?? 01 [0-8] 8b [0-8] 8b ?? 1c [0-9] c1 [0-21] 8b [0-64] [0-3] 40 00 00 00 ba 00 ?? 0b 00 [0-32] 5e 45 [0-32] 0f af ?? ?? ?? ?? ?? 00 [0-80] e8 ?? 00 00 00 [0-9] 8b [0-3] [0-24] [0-5] ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_HNU_2147931548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.HNU!MTB"
        threat_id = "2147931548"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 72 73 72 63 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 40 2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 e2}  //weight: 1, accuracy: Low
        $x_2_2 = {50 45 00 00 64 86 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_A_2147936276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.A!MTB"
        threat_id = "2147936276"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b ec 48 83 ec 20 48 83 e4 f0 48 8d ?? ?? ?? ?? ?? 48 be 00 00 00 00 00 00 00 00 52 81 aa f0 03 00 00 ?? ?? ?? ?? 81 b2 a8 00 00 00 ?? ?? ?? ?? 81 6a 2c ?? ?? ?? ?? f7 92 9c 01 00 00 81 aa fc 00 00 00 ?? ?? ?? ?? 81 b2 38 03 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_PAGJ_2147937390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.PAGJ!MTB"
        threat_id = "2147937390"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {45 89 fa 47 8a 14 16 44 88 55 cf 44 0f b6 55 cf 44 8b 4d bc 41 01 f9 45 0f b6 c9 45 31 ca 44 88 55 cf 45 89 fa 44 8a 4d cf 47 88 0c 16 4d 8d 7f 01 eb}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Expiro_HNW_2147940877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Expiro.HNW!MTB"
        threat_id = "2147940877"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "700"
        strings_accuracy = "Low"
    strings:
        $x_700_1 = {00 00 40 00 00 40 2e 72 65 6c 6f 63 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e2 00 00 00}  //weight: 700, accuracy: Low
        $x_699_2 = {00 00 00 00 40 00 00 40 2e 72 73 72 63 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 (e0|e2) 00 00 00 00}  //weight: 699, accuracy: Low
        $x_1_3 = {24 00 04 00 00 00 54 00 72 00 61 ?? 6e 00 73 00 6c 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3c 61 73 73 65 6d 62 6c 79 ?? 78 6d 6c 6e 73 3d}  //weight: 1, accuracy: Low
        $x_1_5 = {3c 2f 73 65 63 75 72 69 74 79 3e 3c 2f 74 72 ?? 73 74 49 6e 66 6f 3e 3c 2f 61 73 73 65 6d 62 6c 79 3e}  //weight: 1, accuracy: Low
        $x_1_6 = {3c 2f 64 65 70 65 6e 64 65 6e 63 79 3e ?? 0a 3c 2f 61 73 73 65 6d 62 6c 79 3e}  //weight: 1, accuracy: Low
        $x_1_7 = {3c 2f 61 73 73 65 6d 62 6c 79 [0-16] 50 41 44 44 49 4e 47 58 58}  //weight: 1, accuracy: Low
        $x_1_8 = {3e 50 41 50 41 44 44 49 4e 47 58 58 ?? 41 44 44 49 4e 47}  //weight: 1, accuracy: Low
        $x_1_9 = {7d 50 41 50 41 44 44 49 4e 47 58 58 ?? 41 44 44 49 4e 47 50 41 44 44 49 4e 47}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_699_*) and 1 of ($x_1_*))) or
            ((1 of ($x_700_*))) or
            (all of ($x*))
        )
}

