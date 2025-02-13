rule Trojan_AndroidOS_Cerberus_B_2147797095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Cerberus.B!MTB"
        threat_id = "2147797095"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 04 35 24 2d 00 14 08 6d 42 06 00 b1 81 48 08 03 04 14 09 87 6a 0d 00 b0 97 dc 09 04 01 48 09 06 09 14 0a b1 65 0c 00 93 0b 01 07 b0 ba da 0b 07 00 b3 1b b0 0b b0 8b 93 01 0a 0a d8 01 01 ff b0 1b 94 01 0a 0a b0 1b 97 01 0b 09 8d 11 4f 01 05 04 d8 04 04 01 01 71 01 a7 28 d4 12 70 13 01 0e 00 35 10 07 00 d3 71 83 13 d8 00 00 01 28 f8 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Cerberus_C_2147808786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Cerberus.C!MTB"
        threat_id = "2147808786"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 02 35 12 ?? ?? 48 05 03 02 14 08 ?? ?? 05 00 ?? ?? 04 08 dc 08 02 01 48 08 09 08 d3 4b e5 7d b0 ab da 0c 0b 00 b3 ac b0 0c b0 5c 93 05 04 04 d8 05 05 ff b0 5c b4 44 b0 4c 97 04 0c 08 8d 44 4f 04 06 02 14 04 0a d1 00 00 14 05 ?? ?? 09 00 b3 a4 b1 4b ?? ?? 0b 05 d8 02 02 01 28 d3 13 00 1c 00 35 07 ?? ?? 93 00 0a 04 d8 07 07 01 28 f8 22 00 ?? ?? 70 20 ?? ?? 60 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Cerberus_D_2147809015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Cerberus.D!MTB"
        threat_id = "2147809015"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 08 35 28 ?? ?? d8 01 01 b2 48 04 03 08 14 05 ed 97 05 00 b0 15 dc 09 08 01 48 09 07 09 db 0a 01 3d b0 5a da 0b 0a 00 b3 5b b0 0b b0 4b 93 04 01 01 d8 04 04 ff b0 4b b4 11 b0 1b 97 01 0b 09 8d 11 4f 01 06 08 14 01 f3 9a 0e 00 14 04 fa 48 0b 00 92 09 05 0a b1 19 b0 94 d8 08 08 01 01 a1 28 d1 13 00 0e 00 13 02 33 00 35 20 0b 00 93 02 04 05 91 02 01 02 d8 05 02 3b d8 00 00 01 28 f4 22 00 ?? ?? 70 20 ?? ?? 60 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Cerberus_E_2147813350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Cerberus.E!MTB"
        threat_id = "2147813350"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 01 35 21 2f 00 14 05 3b a7 00 00 b0 56 48 05 04 01 d9 09 06 1f dc 0a 01 03 48 0a 08 0a da 0b 09 4e 91 0b 06 0b b1 96 b0 b6 da 06 06 00 b0 56 93 05 0b 0b db 05 05 01 df 05 05 01 b0 56 94 05 0b 0b b0 56 97 05 06 0a 8d 55 4f 05 07 01 14 05 59 8a 7b 00 93 05 0b 05 d8 01 01 01 01 b6 ?? ?? 13 00 2f 00 35 03 05 00 d8 03 03 01 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Cerberus_F_2147817432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Cerberus.F!MTB"
        threat_id = "2147817432"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 0b 00 35 61 09 00 14 06 de ab 01 00 b3 46 d8 01 01 01 ?? ?? 12 01 35 01 2e 00 14 06 3b a7 00 00 b0 64 48 06 02 01 d9 08 04 1f dc 09 01 01 48 09 07 09 da 0a 08 4e 91 0a 04 0a b1 84 b0 a4 da 04 04 00 b0 64 93 06 0a 0a db 06 06 01 df 06 06 01 b0 64 94 06 0a 0a b0 64 b7 94 8d 44 4f 04 05 01 14 04 59 8a 7b 00 93 04 0a 04 d8 01 01 01 01 a4 ?? ?? 13 00 13 00 13 01 2f 00 35 10 05 00 d8 00 00 01 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

