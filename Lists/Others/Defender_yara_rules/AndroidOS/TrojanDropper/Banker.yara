rule TrojanDropper_AndroidOS_Banker_G_2147779943_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.G!MTB"
        threat_id = "2147779943"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {14 03 59 ee 1c 2d 14 04 dc 5a f3 0c 12 05 35 a5 2b 00 14 03 f0 ba 01 00 91 03 04 03 48 06 00 05 13 07 3c 00 b3 37 d8 07 07 5f b1 47 dc 04 05 02 48 04 02 04 14 08 cf 81 0b 00 92 03 03 08 d0 33 d6 89 b0 73 b7 64 8d 44 4f 04 01 05 14 04 66 2d 0d 00 92 04 04 03 b0 74 d8 05 05 01 01 49 01 34 01 93 28 d6 14 0a d4 8e 08 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_E_2147780893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.E!MTB"
        threat_id = "2147780893"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 00 75 17 12 01 13 02 0a 1a 12 02 13 03 0a 1a 13 04 09 00 35 42 07 00 d8 02 02 01 13 03 75 17 28 f8 13 02 0a 00 23 24 ?? ?? 26 04 8b 00 00 00 13 05 19 00 b0 35 b1 05 23 26 ?? ?? 13 07 64 00 36 75 06 00 14 03 b0 76 01 00 b0 53 12 17 23 77 ?? ?? 26 07 81 00 00 00 01 58 12 05 13 09 0b 00 35 95 08 00 13 08 8b e8 b0 38 d8 05 05 01 28 f7 37 03 08 00 14 00 17 e3 05 00 92 05 03 08 b0 50 33 08 0d 00 14 03 d9 49 7b 00 14 05 98 7c 4e 00 92 09 08 00 b1 39 90 03 09 05 01 05 12 00 12 79 35}  //weight: 2, accuracy: Low
        $x_2_2 = {10 00 14 05 fc d0 0e 00 14 09 67 6e 07 00 92 0a 03 08 b0 5a 91 05 0a 09 d8 00 00 01 28 f0 12 00 35 20 2d 00 14 08 12 2f 06 00 b1 58 48 05 04 00 14 09 61 c5 0b 00 b0 93 dc 09 00 01 48 09 07 09 14 0a 9f 55 02 00 b1 3a b1 8a 93 0b 0a 0a d8 0b 0b ff b0 5b 91 05 03 08 da 05 05 00 b0 5b b3 88 dc 08 08 01 b0 8b 97 05 0b 09 8d 55 4f 05 06 00 d8 00 00 01 01 35 01 a3 28 d4 13 00 1a 00 35 01 0a 00 14 00 c7 07 0b 00 93 00 03 00 d8 01 01 01 28 f5 22 00 ?? ?? 70 20 ?? ?? 60 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_F_2147781503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.F!MTB"
        threat_id = "2147781503"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 00 00 00 02 00 00 00 00 00 00 00 37 00 00 00 13 00 ?? ?? 23 01 ?? ?? 26 01 22 00 00 00 23 02 ?? ?? 12 13 23 33 ?? ?? 26 03 26 00 00 00 12 04 35 04 0f 00 48 05 01 04 dc 06 04 01 48 06 03 06 b7 65 8d 55 4f 05 02 04 d8 04 04 01 28 f2 22 00 ?? ?? 70 20 ?? ?? 20 00 11 00}  //weight: 2, accuracy: Low
        $x_2_2 = {07 00 00 00 02 00 00 00 00 00 00 00 ?? ?? 00 00 13 00 ?? ?? 23 01 ?? ?? 26 01 ?? ?? ?? ?? 23 02 ?? ?? 12 33 23 33 ?? ?? 26 03 ?? ?? ?? ?? 12 04 35 04 0f 00 48 05 01 04 dc 06 04 03 48 06 03 06 b7 65 8d 55 4f 05 02 04 d8 04 04 01 28 f2 22 00 ?? ?? 70 20 ?? ?? 20 00 11 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_D_2147782702_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.D!MTB"
        threat_id = "2147782702"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 02 35 12 2a 00 14 04 aa e8 0d 00 b1 48 48 04 03 02 14 05 f2 2d 06 00 b0 85 dc 09 02 ?? 48 09 07 09 91 0a 05 08 d8 0a 0a 3d b3 55 d8 05 05 ff b0 45 91 04 0a 08 da 04 04 00 b0 45 b3 88 dc 08 08 01 b0 85 97 04 05 09 8d 44 4f 04 06 02 d8 02 02 01 01 a8 28 d7 13 01 1d 00 35 10 05 00 d8 00 00 01 28 fa 22 00 ?? ?? 70 20 ?? ?? 60 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_I_2147785346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.I!MTB"
        threat_id = "2147785346"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 02 35 12 30 00 d8 08 08 5d 48 05 03 02 14 09 40 be 00 00 91 04 09 04 dc 09 02 02 48 09 07 09 14 0a 6e 83 03 00 b3 8a b0 4a b3 88 d8 08 08 ff b0 58 91 05 0a 04 da 05 05 00 b0 58 93 05 04 04 dc 05 05 01 b0 58 97 05 08 09 8d 55 4f 05 06 02 14 05 4c 4d 93 00 b3 45 d8 02 02 01 01 48 01 a4 28 d1 13 01 22 00 35 10 05 00 d8 00 00 01 28 fa 22 00 ?? ?? 70 20 ?? ?? 60 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_H_2147786798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.H!MTB"
        threat_id = "2147786798"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 00 35 20 2d 00 14 08 12 2f 06 00 b1 58 48 05 04 00 14 09 61 c5 0b 00 b0 93 dc 09 00 03 48 09 07 09 14 0a 9f 55 02 00 b1 3a b1 8a 93 0b 0a 0a d8 0b 0b ff b0 5b 91 05 03 08 da 05 05 00 b0 5b b3 88 dc 08 08 01 b0 8b 97 05 0b 09 8d 55 4f 05 06 00 d8 00 00 01 01 35 01 a3 28 d4 13 00 1a 00 35 01 0a 00 14 00 c7 07 0b 00 93 00 03 00 d8 01 01 01 28 f5 22 00 ?? ?? 70 20 ?? ?? 60 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_L_2147787185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.L!MTB"
        threat_id = "2147787185"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {35 10 21 00 14 06 dc ac 0e 00 b1 68 48 06 02 00 d0 55 77 f5 dc 09 00 02 48 09 07 09 14 0a 03 ac 02 00 91 08 05 08 b0 a8 b7 96 8d 66 4f 06 04 00 13 06 1f 29 b3 56 d8 00 00 01 01 8b 01 58 01 b5 28 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_J_2147787559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.J!MTB"
        threat_id = "2147787559"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 02 35 12 29 00 48 06 03 02 d8 08 04 f8 dc 09 02 02 48 09 07 09 91 0a 04 08 d8 0a 0a 3d b3 44 d8 04 04 ff b0 64 91 06 0a 08 da 06 06 00 b0 64 93 06 08 08 dc 06 06 01 b0 64 b7 94 8d 44 4f 04 05 02 13 04 29 00 b3 84 d8 04 04 46 b1 a4 d8 02 02 01 28 d8 13 01 2e 00 35 10 05 00 d8 00 00 01 28 fa 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_K_2147787561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.K!MTB"
        threat_id = "2147787561"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 00 00 20 23 05 ?? ?? 01 10 6e 20 ?? ?? 5b 00 0a 06 3a 06 27 00 ?? ?? ?? ?? 01 12 34 70 06 00 6e 40 ?? ?? 5c 61 28 f2 dc 08 00 08 db 09 08 04 dc 0a 00 04 39 08 05 00 71 20 ?? ?? 34 00 44 08 03 09 da 09 0a 08 b9 98 8d 88 48 09 05 02 b7 98 8d 88 4f 08 05 02 d8 00 00 01 d8 02 02 01 28 df 0e 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_O_2147793735_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.O!MTB"
        threat_id = "2147793735"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 02 12 03 ?? ?? ?? ?? ?? ?? 0a 02 12 f4 32 42 16 00 39 02 03 00 28 12 b1 29 12 04 35 24 0b 00 48 05 01 04 b7 a5 8d 55 4f 05 01 04 d8 04 04 01 28 f6 ?? ?? ?? ?? ?? ?? 28 e1}  //weight: 5, accuracy: Low
        $x_1_2 = {76 69 63 65 3b 06 00 2f ?? ?? 53 65 72}  //weight: 1, accuracy: Low
        $x_1_3 = {63 61 74 69 6f 6e 3b 08 00 2f ?? ?? 41 70 70 6c 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_P_2147794330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.P!MTB"
        threat_id = "2147794330"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 ec 38 48 89 d5 48 89 fb 48 8b 07 48 8d 35 ?? ?? ff ff ff 90 ?? ?? 00 00 49 89 c6 48 8d 35 ?? ?? ff ff 48 89 df 31 d2 48 89 e9 e8 ?? ?? 00 00 49 89 c4 48 89 df 31 f6 48 89 ea e8 ?? ?? 00 00 48 89 44 24 28 48 8b 03 48 89 df 48 89 ee ff 90 ?? ?? 00 00 4c 8b 03 48 8d 15 ?? ?? ff ff 48 8d 0d ?? ?? ff ff 48 89 df 48 89 c6 41 ff}  //weight: 2, accuracy: Low
        $x_1_2 = {41 89 c6 48 89 df 48 89 ee e8 ?? ?? 00 00 48 8d 15 ?? ?? ff ff 48 89 c7 44 89 f6 e8 ?? ?? 00 00 48 89 df 4c 89 64 24 30 4c 89 e6 48 89 c2 44 89 f1 e8 ?? ?? 00 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = "openRawResource" ascii //weight: 1
        $x_1_4 = "dalvik/system/DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_N_2147794879_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.N!MTB"
        threat_id = "2147794879"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 02 35 02 1e 00 d8 08 08 5f 48 06 01 02 d8 05 05 dd dc 09 02 03 48 09 07 09 14 0a 0b a5 38 00 b1 58 b1 a8 b7 96 8d 66 4f 06 04 02 13 06 36 47 b3 86 d8 02 02 01 01 8b 01 58 01 b5 28 e3 13 00 21 00 35 03 05 00 d8 03 03 01 28 fa 22 00 ?? ?? 70 20 ?? ?? 40 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_U_2147794986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.U!MTB"
        threat_id = "2147794986"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {35 04 0f 00 48 05 01 04 dc 06 04 01 48 06 03 06 b7 65 8d 55 4f 05 02 04 d8 04 04 01 28 f2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_V_2147795072_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.V!MTB"
        threat_id = "2147795072"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {35 10 23 00 48 06 02 00 d0 58 d4 6c dc 09 00 03 48 09 07 09 14 0a d2 ed 0c 00 93 0a 08 0a b1 5a 97 05 06 09 8d 55 4f 05 04 00 14 05 21 3c 4d 00 14 06 23 8c 27 00 92 0a 0a 05 b1 8a 90 05 0a 06 d8 00 00 01 28 de}  //weight: 5, accuracy: High
        $x_5_2 = {35 02 26 00 d8 05 05 18 48 03 01 02 d0 58 24 fa dc 09 02 02 48 09 06 09 14 0a f3 ec 05 00 b0 8a b0 a5 b7 93 8d 33 4f 03 04 02 14 03 31 1f 04 00 14 09 9b 4e 08 00 90 0a 05 08 b1 3a 90 03 0a 09 d8 02 02 01 01 8b 01 38 01 b3 28 db}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_W_2147795226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.W!MTB"
        threat_id = "2147795226"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {35 04 21 00 14 05 9c 52 0d 00 b1 59 48 05 01 04 14 06 fb c4 21 00 b0 96 dc 07 04 02 48 07 08 07 14 0a f8 d1 01 00 92 09 09 0a b0 69 b7 75 8d 55 4f 05 03 04 14 05 43 6b 01 00 b3 65 d8 04 04 01 28 e0}  //weight: 5, accuracy: High
        $x_5_2 = {35 14 2b 00 d8 08 08 57 48 05 03 04 14 06 d8 51 0b 00 91 06 08 06 dc 09 04 03 48 09 07 09 14 0a b6 95 09 00 92 0a 0a 06 b1 8a b3 66 d8 06 06 ff b0 56 b1 a8 da 08 08 00 b0 86 93 05 0a 0a dc 05 05 01 b0 56 97 05 06 09 8d 55 4f 05 02 04 d8 04 04 01 01 a8 28 d6}  //weight: 5, accuracy: High
        $x_5_3 = {35 02 30 00 14 05 e8 e3 04 00 b1 75 48 06 01 02 14 07 45 98 0e 00 b1 57 dc 08 02 01 48 08 04 08 14 09 00 b5 0c 00 14 0a f5 d3 09 00 92 09 09 07 92 05 05 0a b0 95 b7 86 8d 66 4f 06 03 02 14 06 7a b3 04 00 14 08 7d 84 0e 00 91 06 05 06 b3 78 b1 86 d8 02 02 01 01 7b 01 57 01 65 01 b6 28 d1}  //weight: 5, accuracy: High
        $x_5_4 = {35 05 21 00 14 06 a3 0e 02 00 b0 64 48 06 01 05 d8 07 04 23 dc 08 05 01 48 08 03 08 14 09 dc 43 05 00 14 0a d8 03 02 00 b3 97 b1 47 b1 a7 b7 86 8d 66 4f 06 02 05 93 04 07 04 d8 05 05 01 01 74 28 e0}  //weight: 5, accuracy: High
        $x_5_5 = {35 a4 2c 00 14 05 7a e3 07 00 92 03 03 05 48 05 00 04 14 06 82 5d 07 00 b0 36 dc 07 04 03 48 07 02 07 14 08 4b 6f 03 00 14 09 8d 90 0c 00 92 06 06 08 b0 36 91 03 06 09 b7 75 8d 55 4f 05 01 04 14 05 82 9b 09 00 14 06 f5 8f 0e 00 92 05 05 03 b3 65 d8 04 04 01 28 d5}  //weight: 5, accuracy: High
        $x_5_6 = {35 02 27 00 14 03 3e a1 04 00 b1 53 48 05 01 02 d8 08 08 04 dc 09 02 03 48 09 06 09 91 03 08 03 d8 03 03 e5 b7 95 8d 55 4f 05 04 02 14 05 6a 20 06 00 14 09 94 a6 02 00 b3 39 b0 59 91 05 09 08 d8 02 02 01 01 8a 01 38 01 53 01 a5 28 da}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_X_2147795301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.X!MTB"
        threat_id = "2147795301"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {35 12 0f 00 48 05 03 02 dc 06 02 02 48 06 08 06 b7 65 8d 55 4f 05 04 02 d8 02 02 01 28 f2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 00}  //weight: 5, accuracy: Low
        $x_5_2 = {35 95 1e 00 d9 03 04 44 48 04 00 05 14 06 fd 6d 0d 00 b0 36 dc 07 05 02 48 07 02 07 d8 08 06 e5 d8 08 08 26 91 03 08 03 b7 74 8d 44 4f 04 01 05 93 04 03 06 d8 05 05 01 01 64 28 e3}  //weight: 5, accuracy: High
        $x_5_3 = {35 95 24 00 14 06 9e c7 02 00 b0 36 48 03 00 05 b3 64 dc 07 05 01 48 07 02 07 14 08 ce cc 05 00 92 08 08 06 b0 84 b7 73 8d 33 4f 03 01 05 14 03 e3 a0 05 00 14 07 b6 ed 06 00 b0 63 93 07 04 07 b1 73 d8 05 05 01 28 dd}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_TA_2147795716_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.TA!MTB"
        threat_id = "2147795716"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {12 09 12 7a 35 a9 0a 00 da 06 01 2c d9 06 06 11 b0 56 d8 09 09 01 28 f6 12 09 35 29 34 00 14 05 ?? ?? 1f 00 b0 56 48 05 04 09 d1 11 93 26 dc 0a 09 03 48 0a 08 0a ?? 0b 01 06 d8 0b 0b ec 93 0c 0b 0b d8 0c 0c ff b0 5c b1 16 da 06 06 00 b0 6c 93 05 01 01 dc 05 05 01 b0 5c 97 05 0c 0a 8d 55 4f 05 07 09 14 05 c6 b1 00 00 14 06 2d e1 0b 00 b0 b5 93 06 01 06 b1 65 d8 09 09 01 01 16 01 b1 ?? ?? 13 00 12 00 35 03 0c 00 13 00 16 00 91 02 01 05 b3 60 91 06 02 00 d8 03 03 01 ?? ?? 22 00 c6 14 70 20 ?? ?? 70 00 11 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_M_2147795813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.M!MTB"
        threat_id = "2147795813"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 02 35 12 2f 00 d0 95 ee 42 48 09 03 02 14 0a 7e 11 05 00 b1 a4 dc 0a 02 02 48 0a 08 0a 14 0b cf 35 1d 00 92 0b 0b 04 b1 5b 93 0c 0b 0b d8 0c 0c ff b0 9c 92 09 05 04 da 09 09 00 b0 9c b3 44 dc 04 04 01 b0 4c 97 04 0c 0a 8d 44 4f 04 06 02 12 44 92 09 0b 05 b0 49 d8 02 02 01 01 b4 28 d2 13 00 1d 00 35 07 0a 00 da 00 09 59 b3 45 91 05 00 05 d8 07 07 01 28 f5 22 00 ?? ?? 70 20 ?? ?? 60 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_Y_2147796511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.Y!MTB"
        threat_id = "2147796511"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {35 12 2a 00 14 04 01 2d 0c 00 b0 49 d1 94 16 07 da 05 09 4d b1 45 da 09 09 00 b3 59 b0 09 48 07 03 02 b0 79 93 07 04 04 d8 07 07 ff b0 79 94 07 04 04 b0 79 dc 07 02 02 48 07 08 07 b7 97 8d 77 4f 07 06 02 14 07 0f ad 83 00 b3 74 d8 02 02 01 01 59 28 d7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AA_2147798343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AA!MTB"
        threat_id = "2147798343"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {35 12 31 00 d8 08 08 52 14 07 50 2e 97 00 91 04 07 04 da 07 08 50 91 07 04 07 da 08 08 00 b3 78 b0 08 48 09 03 02 b0 98 93 09 04 04 d8 09 09 ff b0 98 94 09 04 04 b0 98 dc 09 02 03 48 09 06 09 b7 98 8d 88 4f 08 05 02 13 08 24 00 b3 78 b0 48 d8 08 08 a8 d8 02 02 01 01 8a 01 48 01 74 01 a7 28 d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_Z_2147807681_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.Z!MTB"
        threat_id = "2147807681"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 08 35 28 ?? ?? d8 04 04 52 48 07 03 08 14 09 50 2e 97 00 91 01 09 01 dc 09 08 03 48 09 06 09 da 0b 04 50 91 0b 01 0b da 04 04 00 b3 b4 b0 04 b0 74 93 07 01 01 b1 a7 b0 74 94 07 01 01 b0 74 b7 94 8d 44 4f 04 05 08 13 04 24 00 b3 b4 b0 14 d8 07 04 a8 d8 08 08 01 01 14 01 b1 28 d3 13 00 0a 00 13 02 11 00 35 20 ?? ?? 93 02 01 07 d8 00 00 01 28 f8 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AB_2147809492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AB!MTB"
        threat_id = "2147809492"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {35 05 1b 00 92 06 04 07 48 08 01 05 b0 64 b0 74 dc 07 05 02 48 07 03 07 d0 69 16 14 d0 99 2c f8 b0 49 b7 87 8d 77 4f 07 02 05 b0 96 b1 46 d8 05 05 01 01 97 28 e6}  //weight: 5, accuracy: High
        $x_5_2 = {35 15 1d 00 b0 a9 48 0b 02 05 90 0c 09 0a dc 0d 05 02 48 0d 07 0d b0 c9 d2 aa 35 1b b0 a9 97 0a 0b 0d 8d aa 4f 0a 03 05 14 0a 53 c9 03 00 b1 9a b0 ca d8 05 05 01 01 c9 28 e4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AD_2147809589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AD!MTB"
        threat_id = "2147809589"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pmwiauehjljcMGVlOTdjODUyMTQ2MDZlMDI1" ascii //weight: 1
        $x_1_2 = "olcbligejjazOTg5MDYzYTg3ZTU0ODA5YmRiMjk5ZGU2Y2I0MTliODExMjAzN2I5N2JmZmUwOGYz" ascii //weight: 1
        $x_1_3 = "czhpdychbbznNDc1YjRjNjZhNmFlZWNkMTU0MDgyMjBiMWI5YTkyMmZmMDE1OWEzNGZmYzJkMzg4MWU4OQ==" ascii //weight: 1
        $x_1_4 = "erzgduplbrktZDIzZGM5ZWIwMjM5NjFkYWExYWQ=" ascii //weight: 1
        $x_1_5 = "vgreqfrvqpcoYWRlZTMwNzVmMDc1YTIxM2Jh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AF_2147809959_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AF!MTB"
        threat_id = "2147809959"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {35 97 55 00 d8 01 01 01 d5 11 ff 00 48 03 08 01 b0 30 d5 00 ff 00 [0-7] 48 03 08 01 48 04 08 00 b0 43 d5 33 ff 00 48 04 0b 07 48 03 08 03 b7 43 8d 33 4f 03 02 07 d8 07 07 01 28 e1}  //weight: 5, accuracy: Low
        $x_5_2 = {35 a1 49 00 d8 02 02 01 d5 23 ff 00 48 02 09 03 b0 20 d5 02 ff 00 [0-10] 48 00 09 03 48 05 09 02 b0 50 d5 00 ff 00 [0-4] 48 05 0e 01 48 00 09 00 b7 50 8d 00 4f 00 04 01}  //weight: 5, accuracy: Low
        $x_5_3 = {35 95 28 00 14 07 cf a4 0e 00 92 02 02 06 b0 72 b1 42 48 04 00 05 92 02 02 06 dc 07 05 02 48 07 03 07 14 08 5e 36 01 00 92 08 08 06 91 08 02 08 b7 74 8d 44 4f 04 01 05 14 04 e6 95 0d 00 92 06 06 08 b0 46 b1 26 d8 05 05 01 01 24 01 82 28 d9}  //weight: 5, accuracy: High
        $x_5_4 = {35 96 23 00 48 03 00 06 14 04 a2 61 0d 00 14 07 54 b2 0b 00 b3 54 b0 74 dc 05 06 01 48 05 02 05 14 07 a9 83 0a 00 92 07 07 04 14 08 5b 62 d9 01 b1 87 b7 53 8d 33 4f 03 01 06 13 03 38 01 d8 06 06 01 01 75 28 de}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AG_2147812152_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AG!MTB"
        threat_id = "2147812152"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {35 21 2e 00 14 06 3b a7 00 00 b0 64 48 06 03 01 d9 09 04 1f dc 0a 01 03 48 0a 08 0a da 0b 09 4e 91 0b 04 0b b1 94 b0 b4 da 04 04 00 b0 64 93 06 0b 0b db 06 06 01 df 06 06 01 b0 64 94 06 0b 0b b0 64 b7 a4 8d 44 4f 04 07 01 14 04 59 8a 7b 00 93 04 0b 04 d8 01 01 01 01 b4 28 d3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AE_2147813187_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AE!MTB"
        threat_id = "2147813187"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {35 a5 6f 00 00 00 00 00 14 03 f0 ba 01 00 00 00 00 00 91 03 04 03 00 00 00 00 48 06 00 05 00 00 13 07 3c 00 00 00 00 00 00 00 00 00 b3 37 00 00 d8 07 07 5f 00 00 b1 47 00 00 00 00 00 00 00 00 00 00 dc 04 05 02 00 00 00 00 00 00 48 04 02 04 00 00 00 00 00 00 00 00 14 08 cf 81 0b 00 00 00 00 00 92 03 03 08 00 00 00 00 d0 33 d6 89 00 00 00 00 b0 73 00 00 00 00 b7 64 00 00 8d 44 00 00 00 00 00 00 00 00 4f 04 01 05 00 00 14 04 66 2d 0d 00 00 00 00 00 00 00 92 04 04 03 00 00 00 00 00 00 b0 74 00 00 00 00 00 00 d8 05 05 01 00 00 00 00 00 00 01 49 00 00 00 00 00 00 00 00 01 34 00 00 00 00 00 00 01 93 00 00 00 00 00 00 00 00 00 00 28 97}  //weight: 5, accuracy: High
        $x_5_2 = {35 15 56 00 00 00 00 00 b0 a9 00 00 00 00 00 00 00 00 48 0b 02 05 00 00 00 00 00 00 00 00 00 00 90 0c 09 0a 00 00 dc 0d 05 02 00 00 00 00 00 00 00 00 00 00 48 0d 07 0d 00 00 b0 c9 00 00 00 00 00 00 00 00 d2 aa 35 1b 00 00 00 00 00 00 b0 a9 00 00 00 00 00 00 97 0a 0b 0d 00 00 00 00 00 00 00 00 00 00 8d aa 00 00 00 00 00 00 4f 0a 03 05 00 00 00 00 00 00 00 00 14 0a 53 c9 03 00 00 00 00 00 00 00 b1 9a 00 00 00 00 b0 ca 00 00 00 00 00 00 d8 05 05 01 00 00 00 00 00 00 01 c9 00 00 00 00 28 af}  //weight: 5, accuracy: High
        $x_5_3 = {35 a5 26 00 92 04 04 03 48 06 00 05 14 07 32 86 0d 00 92 03 03 04 b0 73 dc 07 05 02 48 07 02 07 14 08 d0 95 0e 00 b0 48 b7 76 8d 66 4f 06 01 05 14 06 8d d0 04 00 92 04 04 06 b1 48 90 04 08 03 d8 05 05 01 01 49 01 34 01 93 28 db}  //weight: 5, accuracy: High
        $x_5_4 = {35 06 20 00 14 07 e5 fd 0d 00 b0 75 48 07 01 06 14 08 6d 18 05 00 91 04 08 04 dc 08 06 03 48 08 03 08 d8 09 04 b2 b0 95 b7 87 8d 77 4f 07 02 06 93 07 05 04 d8 06 06 01 01 5a 01 45 01 a4 28 e1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AJ_2147814966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AJ!MTB"
        threat_id = "2147814966"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 21 2f 00 14 04 3b a7 00 00 b0 46 48 04 03 01 d9 08 06 1f dc 09 01 03 48 09 07 09 da 0a 08 4e 91 0a 06 0a b1 86 b0 a6 da 06 06 00 b0 46 93 04 0a 0a db 04 04 01 df 04 04 01 b0 46 94 04 0a 0a b0 46 97 04 06 09 8d 44 4f 04 05 01 14 04 59 8a 7b 00 93 04 0a 04 d8 01 01 01 01 a6 28 d2}  //weight: 1, accuracy: High
        $x_1_2 = "dalvik/system/DexClassLoader;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AI_2147815315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AI!MTB"
        threat_id = "2147815315"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 20 2c 00 14 09 3b a7 00 00 b0 94 48 09 03 00 d9 0a 04 1f dc 0b 00 03 48 0b 08 0b da 0c 0a 4e 91 0c 04 0c b1 a4 b0 c4 da 04 04 00 b0 94 93 09 0c 0c b3 69 b7 69 b0 94 94 09 0c 0c b0 94 b7 b4 8d 44 4f 04 05 00 14 04 59 8a 7b 00 93 04 0c 04 d8 00 00 01 01 c4 28 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AK_2147815669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AK!MTB"
        threat_id = "2147815669"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 02 2f 00 14 04 3b a7 00 00 b0 47 48 04 03 02 d9 06 07 1f dc 09 02 03 48 09 08 09 da 0a 06 4e 91 0a 07 0a b1 67 b0 a7 da 07 07 00 b0 47 93 04 0a 0a db 04 04 01 df 04 04 01 b0 47 94 04 0a 0a b0 47 97 04 07 09 8d 44 4f 04 05 02 14 04 59 8a 7b 00 93 04 0a 04 d8 02 02 01 01 a7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_C_2147817542_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.C!MTB"
        threat_id = "2147817542"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {35 01 2e 00 14 06 3b a7 00 00 b0 64 48 06 02 01 d9 08 04 1f dc 09 01 03 48 09 07 09 da 0a 08 4e 91 0a 04 0a b1 84 b0 a4 da 04 04 00 b0 64 93 06 0a 0a db 06 06 01 df 06 06 01 b0 64 94 06 0a 0a b0 64 b7 94 8d 44 4f 04 05 01 14 04 59 8a 7b 00 93 04 0a 04 d8 01 01 01 01 a4 28 d3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AL_2147819333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AL!MTB"
        threat_id = "2147819333"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 00 35 20 2f 00 14 01 3b a7 00 00 b0 15 48 01 03 00 d9 08 05 1f dc 09 00 03 48 09 07 09 da 0a 08 4e 91 0a 05 0a b1 85 b0 a5 da 05 05 00 b0 15 93 01 0a 0a db 01 01 01 df 01 01 01 b0 15 94 01 0a 0a b0 15 97 01 05 09 8d 11 4f 01 06 00 14 01 59 8a 7b 00 93 01 0a 01 d8 00 00 01 01 a5 ?? ?? 13 00 13 00 13 01 2f 00 35 10 05 00 d8 00 00 01 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 60 00 11 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AM_2147822293_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AM!MTB"
        threat_id = "2147822293"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 24 2e 00 14 05 3b a7 00 00 b0 51 48 05 03 04 d9 08 01 1f dc 09 04 03 48 09 07 09 da 0a 08 4e 91 0a 01 0a b1 81 b0 a1 da 01 01 00 b0 51 93 05 0a 0a db 05 05 01 df 05 05 01 b0 51 94 05 0a 0a b0 51 b7 91 8d 11 4f 01 06 04 14 01 59 8a 7b 00 93 01 0a 01 d8 04 04 01 01 a1 28 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AN_2147832928_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AN!MTB"
        threat_id = "2147832928"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 08 36 00 d1 42 11 24 48 04 03 08 d0 66 d0 1a dc 09 08 03 48 09 01 09 14 0a 99 90 00 00 93 0b 02 06 b0 ba 91 0b 06 0a b0 2b da 0b 0b 00 b0 4b 93 04 02 02 db 04 04 01 df 04 04 01 b0 4b b4 22 b0 2b 97 02 0b 09 8d 22 4f 02 05 08 14 02 38 02 01 00 14 04 ec 64 01 00 92 09 06 0a b0 29 90 02 09 04 d8 08 08 01 01 64 01 a6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AP_2147833751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AP!MTB"
        threat_id = "2147833751"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 12 2f 00 14 09 bb 4a 96 00 b0 94 48 09 03 02 14 0a 39 ea 6d 00 91 0a 04 0a dc 0b 02 03 48 0b 08 0b 14 0c d0 e6 06 00 92 0c 0c 0a b1 4c da 0a 0a 00 b3 4a b0 0a b0 9a 93 09 0c 0c d8 09 09 ff b0 9a 94 09 0c 0c b0 9a 97 09 0a 0b 8d 99 4f 09 06 02 93 04 07 04 d8 02 02 01 01 c4 28 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AO_2147834159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AO!MTB"
        threat_id = "2147834159"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 39 33 00 d1 11 11 24 48 07 02 09 d0 44 d0 1a dc 0b 09 03 48 0b 08 0b 14 0c 99 90 00 00 93 0d 01 04 b0 dc 91 0d 04 0c b0 1d da 0d 0d 00 b0 7d 93 07 01 01 b3 07 b7 07 b0 7d b4 11 b0 1d 97 01 0d 0b 8d 11 4f 01 06 09 14 01 38 02 01 00 14 07 ec 64 01 00 92 0b 04 0c b0 1b b0 b7 d8 09 09 01 01 41 01 c4 28 ce}  //weight: 1, accuracy: High
        $x_1_2 = "Ldalvik/system/DexClassLoader;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AQ_2147834872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AQ!MTB"
        threat_id = "2147834872"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 08 35 00 d1 11 11 24 48 04 02 08 d0 55 d0 1a dc 09 08 03 48 09 06 09 14 0a 99 90 00 00 93 0b 01 05 b0 ba 91 0b 05 0a b0 1b da 0b 0b 00 b0 4b 93 04 01 01 db 04 04 01 df 04 04 01 b0 4b b4 11 b0 1b 97 01 0b 09 8d 11 4f 01 03 08 14 01 38 02 01 00 14 04 ec 64 01 00 92 09 05 0a b0 19 b0 94 d8 08 08 01 01 51 01 a5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Banker_AR_2147838434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Banker.AR!MTB"
        threat_id = "2147838434"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 08 35 00 d1 33 11 24 48 04 01 08 d0 66 d0 1a dc 09 08 03 48 09 02 09 14 0a 99 90 00 00 93 0b 03 06 b0 ba 91 0b 06 0a b0 3b da 0b 0b 00 b0 4b 93 04 03 03 db 04 04 01 df 04 04 01 b0 4b b4 33 b0 3b 97 03 0b 09 8d 33 4f 03 05 08 14 03 38 02 01 00 14 04 ec 64 01 00 92 09 06 0a b0 39 b0 94 d8 08 08 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

