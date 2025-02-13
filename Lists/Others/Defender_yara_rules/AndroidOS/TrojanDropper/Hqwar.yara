rule TrojanDropper_AndroidOS_Hqwar_B_2147819339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Hqwar.B!MTB"
        threat_id = "2147819339"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 21 2f 00 14 04 3b a7 00 00 b0 47 48 04 03 01 d9 08 07 1f dc 09 01 02 48 09 06 09 da 0a 08 4e 91 0a 07 0a b1 87 b0 a7 da 07 07 00 b0 47 93 04 0a 0a db 04 04 01 df 04 04 01 b0 47 94 04 0a 0a b0 47 97 04 07 09 8d 44 4f 04 05 01 14 04 59 8a 7b 00 93 04 0a 04 d8 01 01 01 01 a7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Hqwar_A_2147820482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Hqwar.A!MTB"
        threat_id = "2147820482"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 51 6e 10 ?? ?? 06 00 0a 02 12 00 34 10 08 00 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00 48 03 05 00 94 04 00 02 6e 20 ?? ?? 46 00 0a 04 b7 43 8d 33 4f 03 05 00 d8 00 00 01 28 ea}  //weight: 1, accuracy: Low
        $x_1_2 = "lockNow" ascii //weight: 1
        $x_1_3 = "isAdminActive" ascii //weight: 1
        $x_1_4 = "getDisplayMessageBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Hqwar_D_2147824866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Hqwar.D!MTB"
        threat_id = "2147824866"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d2 00 99 0b [0-4] b0 30 [0-4] 54 d3 [0-7] 21 33 [0-4] 54 d4 [0-7] 21 44 [0-4] b1 43 [0-4] b0 30 [0-4] 52 d3 [0-7] d0 33 5d 09 [0-4] d0 33 12 05 [0-4] d8 03 03 48 [0-4] 52 d4 [0-7] b0 43 [0-4] b0 30 [0-4] 59 d0 [0-7] 54 d0 [0-7] 21 00 [0-4] d1 00 0f 3f}  //weight: 1, accuracy: Low
        $x_1_2 = "seC/duexry/sulPiym" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Hqwar_C_2147824867_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Hqwar.C!MTB"
        threat_id = "2147824867"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d2 00 99 0b [0-4] b0 30 [0-4] 54 d3 0c 00 [0-4] 21 33 [0-4] 54 d4 0f 00 [0-4] 21 44 [0-4] b1 43 [0-4] b0 30 [0-4] 52 d3 14 00 [0-4] d0 33 5d 09 [0-4] d0 33 12 05 [0-4] d8 03 03 48 [0-4] 52 d4 07 00 [0-4] b0 43 [0-4] b0 30 [0-4] 59 d0 08 00 [0-4] 54 d0 09 00 [0-4] 21 00 [0-4] d1 00 0f 3f [0-4] 52 d3 0b 00 [0-4] b1 30 [0-4] 52 d3 14 00 [0-4] b0 30 [0-4] d8 03 00 e6 [0-4] 55 d0 11 00 [0-4] 38 00 [0-7] 01 10}  //weight: 1, accuracy: Low
        $x_1_2 = "com/neohbi/cevzsiw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Hqwar_E_2147827070_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Hqwar.E!MTB"
        threat_id = "2147827070"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d2 00 99 0b [0-4] b0 30 [0-4] 54 d3 c0 19 [0-4] 21 33 [0-4] 54 d4 c3 19 [0-4] 21 44 [0-4] b1 43 [0-4] b0 30 [0-4] 52 d3 c8 19 [0-4] d0 33 5d 09 [0-4] d0 33 12 05 [0-4] d8 03 03 48 [0-4] 52 d4 bb 19 [0-4] b0 43 [0-4] b0 30 [0-4] 59 d0 bc 19 [0-4] 54 d0 bd 19 [0-4] 21 00 [0-4] d1 00 0f 3f}  //weight: 1, accuracy: Low
        $x_1_2 = "com/neohbi/cevzsiw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Hqwar_G_2147830924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Hqwar.G!MTB"
        threat_id = "2147830924"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 08 00 35 40 05 00 d8 00 00 01 28 fa 12 00 ?? ?? 35 ?? ?? 00 14 ?? 3b a7 00 00 b0 ?? d9 ?? 01 1f da ?? ?? 4e 91 ?? 01 ?? b1 ?? b0 ?? da 01 01 00 48 ?? 03 ?? b0 ?? 93}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 11 4f 01 06 ?? 14 01 59 8a 7b 00 93 01 ?? 01 d8 ?? ?? 01 01 ?? 28 ?? 13 00 13 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Hqwar_H_2147833331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Hqwar.H!MTB"
        threat_id = "2147833331"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 08 36 00 d1 42 11 24 48 04 03 08 d0 66 d0 1a dc 09 08 01 48 09 01 09 14 0a 99 90 00 00 93 0b 02 06 b0 ba 91 0b 06 0a b0 2b da 0b 0b 00 b0 4b 93 04 02 02 db 04 04 01 df 04 04 01 b0 4b b4 22 b0 2b 97 02 0b 09 8d 22 4f 02 05 08 14 02 38 02 01 00 14 04 ec 64 01 00 92 09 06 0a b0 29 90 02 09 04 d8 08 08 01 01 64 01 a6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Hqwar_I_2147834044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Hqwar.I!MTB"
        threat_id = "2147834044"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Hqwar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 25 12 02 35 12 2c 00 14 05 54 03 05 00 90 0a 08 05 13 05 26 00 b3 a5 b0 85 93 09 0a 0a d8 09 09 ff 48 0b 03 02 b0 b9 92 08 08 05 da 08 08 00 b0 89 93 08 05 05 dc 08 08 01 b0 89 dc 08 02 02 48 08 07 08 b7 98 8d 88 4f 08 04 02 da 08 05 35 db 09 0a 44 b1 98 d8 02 02 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

