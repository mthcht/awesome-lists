rule TrojanDropper_AndroidOS_Wroba_A_2147783683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Wroba.A"
        threat_id = "2147783683"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 00 22 01 16 00 70 10 14 00 01 00 70 20 58 00 14 00 70 20 56 00 14 00 0c 01 6e 10 1b 00 00 00 0c 02 71 20 53 00 12 00 22 01 17 00 22 02 22 00 70 10 33 00 02 00 6e 10 5c 00 04 00 0c 03 6e 10 1a 00 03 00 0c 03 6e 20 34 00 32 00 1a 03 0a 00 6e 20 34 00 32 00 6e 10 35 00 02 00 0c 02 70 20 17 00 21 00 6e 10 1c 00 01 00 6e 10 1a 00 00 00 0c 00 22 01 22 00 70 10 33 00 01 00 6e 10 5c 00 04 00 0c 02 6e 10 1a 00 02 00 0c 02 6e 20 34 00 21 00 1a 02 0a 00 6e 20 34 00 21 00 6e 10 35 00 01 00 0c 01 12 02 70 40 4f 00 04 21 0c 02 71 40 55 00 04 21}  //weight: 1, accuracy: High
        $x_1_2 = {13 04 00 04 23 44 30 00 6e 20 20 00 40 00 0a 05 12 f6 33 65 06 00 70 40 52 00 98 42 0e 00 12 06 35 56 0b 00 48 07 04 06 b7 17 8d 77 4f 07 04 06 d8 06 06 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Wroba_C_2147795894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Wroba.C!MTB"
        threat_id = "2147795894"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 6d 79 63 6f 64 65 2e 64 65 78 00 65 78 69 73 74 73 00 64 65 6c 65 74 65}  //weight: 1, accuracy: High
        $x_1_2 = {00 61 6d 00 00 73 74 61 72 74 73 65 72 76 69 63 65 00 00 00 00 2d 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 4c 6f 61 64 65 64 41 70 6b 00 6d 43 6c 61 73 73 4c 6f 61 64 65 72}  //weight: 1, accuracy: High
        $x_1_4 = "getAssets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Wroba_D_2147822254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Wroba.D!MTB"
        threat_id = "2147822254"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 23 78 44 a4 f8 48 30 7a 44 08 30 84 f8 4a 30 c4 e9 00 02 04 f1 08 00 40 22 fe f7 f0 ee 04 f1 50 00 4f f4 99 71 fe f7 e4 ee 20 46 00 21}  //weight: 10, accuracy: High
        $x_10_2 = {00 23 78 44 a4 f8 48 30 7a 44 08 30 84 f8 4a 30 c4 e9 00 02 04 f1 08 00 40 22 fe f7 82 ef 04 f1 50 00 4f f4 99 71 fe f7 76 ef 20 46 00 21}  //weight: 10, accuracy: High
        $x_10_3 = {00 23 78 44 a4 f8 48 30 7a 44 08 30 84 f8 4a 30 c4 e9 00 02 04 f1 08 00 40 22 fe f7 1a ef 04 f1 50 00 4f f4 99 71 fe f7 0e ef 20 46 00 21}  //weight: 10, accuracy: High
        $x_1_4 = "com.Loader" ascii //weight: 1
        $x_1_5 = "/Volumes/Android/buildbot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_AndroidOS_Wroba_E_2147824744_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Wroba.E!MTB"
        threat_id = "2147824744"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shinhan_send_pwd" ascii //weight: 1
        $x_1_2 = "hidde_id" ascii //weight: 1
        $x_1_3 = "shinhan_card_number" ascii //weight: 1
        $x_1_4 = "woori_main_activity" ascii //weight: 1
        $x_1_5 = "hana_main_activity " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_AndroidOS_Wroba_A_2147828581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Wroba.A!xp"
        threat_id = "2147828581"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 44 20 1c 7a 44 04 93 b0 47 23 68 02 1c 29 1c 88}  //weight: 1, accuracy: High
        $x_1_2 = {44 7b 44 b0 47 22 68 49 49 03 90 a7 20 80 00 13 58 79 44 20 1c 98 47 23 68 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 23 68 3e 4a 01 1c 08 33 db 6f 20 1c 7a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Wroba_F_2147828898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Wroba.F!MTB"
        threat_id = "2147828898"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 2a 08 d0 01 2a 0c d0 8a b9 02 68 09 49 d2 f8 9c 22 79 44 10 47 02 68 08 49 d2 f8 9c 22 79 44 10 47 02 68 04 49 d2 f8 9c 22 79 44 10 47}  //weight: 1, accuracy: High
        $x_1_2 = {c2 6f 30 46 90 47 01 46 30 68 08 4a 09 4b d0 f8 84 50 7a 44 7b 44 30 46 a8 47 02 46 30 46 21 46 43 46 5d f8 04 8b}  //weight: 1, accuracy: High
        $x_1_3 = {19 f8 0b 10 dd e9 09 02 61 40 90 42 07 f8 b9 1c 04 d2 01 70 09 98 01 30 09 90 03 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Wroba_H_2147830750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Wroba.H!MTB"
        threat_id = "2147830750"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 02 40 f9 e2 00 00 b0 e3 00 00 b0 e1 03 00 aa 08 85 40 f9 42 bc 16 91 63 e4 16 91 e0 03 14 aa 00 01 3f d6 e2 03 00 aa e0 03 14 aa e1 03 13 aa fd 7b 42 a9 f4 4f 41 a9 e3 03 15 aa}  //weight: 1, accuracy: High
        $x_1_2 = {08 00 40 f9 e1 00 00 f0 21 c4 01 91 02 9d 42 f9 40 00 1f d6 08 00 40 f9 e1 00 00 b0 21 ec 10 91 02 9d 42 f9 40 00 1f d6 08 00 40 f9 e1 00 00 b0 21 c0 10 91 02 9d 42 f9 40 00 1f d6}  //weight: 1, accuracy: High
        $x_1_3 = {e9 23 44 a9 0a 6b 77 38 3f 01 08 eb 53 01 15 4a c2 00 00 54 33 01 00 39 e8 23 40 f9 08 05 00 91 e8 23 00 f9 21 00 00 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_AndroidOS_Wroba_G_2147830922_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Wroba.G!MTB"
        threat_id = "2147830922"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 46 20 68 59 46 32 46 4b 46 cd f8 3c 90 d0 f8 88 50 20 46 a8 47 20 68 df f8 c4 15 d0 f8 9c 22 79 44 20 46 90 47 03 46 20 68 59 46 32 46}  //weight: 1, accuracy: High
        $x_1_2 = {4c 89 f6 ff 90 08 01 00 00 48 89 c3 49 8b 2f 31 c0 4c 89 ff 4c 89 ee 48 89 da 4c 89 64 24 68 4c 89 e1 ff 95 10 01 00 00 49 8b 07 48 8d 35 75 0a 00 00 4c 89 ff ff 90 38 05 00 00 48 89 c1 49 8b 2f 31 c0 4c 89 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_AndroidOS_Wroba_FA_2147836809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Wroba.FA!MTB"
        threat_id = "2147836809"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 00 0c 00 00 00 0b 00 16 02 f0 55 bb 20 10 00}  //weight: 1, accuracy: High
        $x_1_2 = "getRuntime" ascii //weight: 1
        $x_1_3 = "getClassLoader" ascii //weight: 1
        $x_1_4 = "PathClassLoader" ascii //weight: 1
        $x_1_5 = "findLibrary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

