rule TrojanDropper_AndroidOS_Bian_B_2147809971_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Bian.B!MTB"
        threat_id = "2147809971"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Bian"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {12 03 35 23 2d 00 48 05 00 03 14 09 90 12 05 00 b0 69 dc 0a 03 01 48 0a 07 0a d3 6b e5 7d b0 9b da 0c 0b 00 b3 9c b0 1c b0 5c 93 05 06 06 d8 05 05 ff b0 5c b4 66 b0 6c 97 05 0c 0a 8d 55 4f 05 04 03 14 05 0a d1 00 00 14 06 2c 9f 09 00 b3 95 b1 5b b0 b6 d8 03 03 01 01 95 28 d4 13 00 1c 00 35 08 07 00 93 00 05 06 d8 08 08 01 28 f8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Bian_A_2147811484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Bian.A!MTB"
        threat_id = "2147811484"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Bian"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 01 13 02 20 00 12 33 35 21 6d 00 44 02 09 00 12 14 44 05 09 04 12 26 44 07 09 06 b7 75 44 07 09 03 b7 75 44 07 0b 01 b7 75 70 20 ?? ?? 58 00 0a 05 70 20 ?? ?? 58 00 0a 05 b7 52 4b 02 09 00 44 02 09 04 44 05 09 06 44 07 09 03 b7 75 44 07 09 00 b7 75 d8 07 01 01 44 07 0b 07 b7 75 70 20 ?? ?? 58 00 0a 05 70 20 ?? ?? 58 00 0a 05 b7 52 4b 02 09 04 44 02 09 06 44 05 09 03 44 07 09 00 b7 75 44 07 09 04 b7 75 d8 07 01 02 44 07 0b 07 b7 75 70 20 ?? ?? 58 00 0a 05 70 20 ?? ?? 58 00 0a 05 b7 52 4b 02 09 06 44 02 09 03 44 05 09 00 44 04 09 04 b7 54 44 05 09 06 b7 54 d8 05 01 03 44 05 0b 05 b7 54 70 20 ?? ?? 48 00 0a 04 70 20 ?? ?? 48 00 0a 04 b7 42 4b 02 09 03 d8 01 01 04 28 91}  //weight: 2, accuracy: Low
        $x_1_2 = {dc 05 02 03 44 06 04 05 e2 06 06 08 44 07 04 05 e0 07 07 18 b6 76 b0 16 b7 26 4b 06 04 05 e2 06 01 1d e0 01 01 03 b6 61 44 05 04 05 b7 51 d8 02 02 01 4b 01 03 02 28 e1}  //weight: 1, accuracy: High
        $x_1_3 = {12 08 e0 09 0b 10 b6 a9 4b 09 07 08 12 18 e0 09 0d 10 b6 c9 4b 09 07 08 44 [0-4] 07 [0-4] dc 07 02 04 e0 07 07 03 b9 [0-4] 8d [0-4] 48 07 [0-4] 03 b7 [0-4] 8d [0-4] 8d [0-4] 4f [0-4] 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Bian_C_2147812785_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Bian.C!MTB"
        threat_id = "2147812785"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Bian"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 01 35 21 2c 00 14 06 3b a7 00 00 b0 64 48 06 03 01 d9 09 04 1f dc 0a 01 02 48 0a 08 0a da 0b 09 4e 91 0b 04 0b da 04 04 00 b3 94 b0 04 b0 64 93 06 0b 0b d8 06 06 ff b0 64 94 06 0b 0b b0 64 b7 a4 8d 44 4f 04 07 01 14 04 59 8a 7b 00 93 04 0b 04 d8 01 01 01 01 b4 28 d5 13 00 2f 00 35 05 05 00 d8 05 05 01 28 fa 22 00 ?? ?? 70 20 ?? ?? 70 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

