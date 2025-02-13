rule TrojanDropper_AndroidOS_SAgent_B_2147831277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.B!MTB"
        threat_id = "2147831277"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 0c 00 6e 10 ?? 00 ?? 00 0c ?? 71 20 ?? 00 ?? 00 54 ?? ?? 00 72 20 ?? 00 ?? 00}  //weight: 2, accuracy: Low
        $x_1_2 = {35 32 12 00 34 40 03 00 01 10 48 05 07 02 48 06 08 00 b7 65 8d 55 4f 05 07 02 d8 02 02 01 d8 00 00 01 28 ef}  //weight: 1, accuracy: High
        $x_1_3 = {35 20 12 00 34 31 03 00 12 01 48 04 06 00 48 05 07 01 b7 54 8d 44 4f 04 06 00 d8 00 00 01 d8 01 01 01 28 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_AndroidOS_SAgent_C_2147832795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.C!MTB"
        threat_id = "2147832795"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 30 23 00 ?? ?? 12 01 21 32 35 21 0c 00 48 02 03 01 df 02 02 ?? 8d 22 4f 02 00 01 d8 01 01 01 28 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {13 00 0b 00 23 01 ?? ?? 26 01 16 00 00 00 12 02 35 02 0c 00 48 03 01 02 60 04 ?? ?? b0 34 67 04 ?? ?? d8 02 02 01 28 f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgent_CA_2147833332_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.CA!MTB"
        threat_id = "2147833332"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {21 30 23 00 ?? ?? 12 01 21 32 35 21 0c 00 48 02 03 01 df 02 02 ?? 8d 22 4f 02 00 01 d8 01 01 01 28 f4}  //weight: 5, accuracy: Low
        $x_1_2 = "asset_name" ascii //weight: 1
        $x_1_3 = "dex_name" ascii //weight: 1
        $x_1_4 = "startDelayedOpenAdTimer" ascii //weight: 1
        $x_1_5 = "getDexClassloader" ascii //weight: 1
        $x_1_6 = "getAssets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_AndroidOS_SAgent_D_2147834049_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.D!MTB"
        threat_id = "2147834049"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "loadDex" ascii //weight: 1
        $x_1_2 = "getClassLoader" ascii //weight: 1
        $x_1_3 = {0c 11 08 00 11 00 6e 20 ?? ?? 0d 00 0c 0c 71 10 ?? ?? 0c 00 0c 11 74 01 ?? ?? 11 00 0c 11 1a 12 ?? ?? 74 02 ?? ?? 11 00 0c 06 6e 10 ?? ?? 06 00 0a 11 39 11 09 00 13 11 01 00 02 00 11 00 6e 20 ?? ?? 06 00}  //weight: 1, accuracy: Low
        $x_1_4 = {0b 0e 74 01 ?? ?? 17 00 0c 11 74 01 ?? ?? 11 00 0c 11 74 01 ?? ?? 11 00 0c 11 77 01 ?? ?? 11 00 0c 11 1f 11 ?? ?? 1a 12 ?? ?? 74 02 ?? ?? 11 00 0c 0d 6e 10 ?? ?? 0d 00 0a 11 39 11 09 00 13 11 01 00 02 00 11 00 6e 20 ?? ?? 0d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgent_F_2147838013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.F!MTB"
        threat_id = "2147838013"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "qtfreet" ascii //weight: 1
        $x_1_2 = "stringersakalam" ascii //weight: 1
        $x_1_3 = {48 04 00 01 62 05 ?? ?? 94 06 01 03 6e 20 ?? ?? 65 00 0a 05 b7 54 8d 44 4f 04 00 01 d8 01 01 01 28 c9}  //weight: 1, accuracy: Low
        $x_1_4 = {34 21 27 00 22 01 ?? ?? 70 20 ?? ?? 01 00 11 01 62 03 ?? ?? 6e 20 ?? ?? 07 00 0a 04 6e 20 ?? ?? 43 00 0a 03 e0 03 03 04 62 04 ?? ?? d8 05 00 01 6e 20 ?? ?? 57 00 0a 05 6e 20 ?? ?? 54 00 0a 04 b6 43 6e 20 ?? ?? 32 00 d8 00 00 02 28 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_AndroidOS_SAgent_G_2147838014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.G!MTB"
        threat_id = "2147838014"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 70 23 02 ?? ?? 62 00 ?? ?? 21 03 01 10 21 74 35 40 11 00 48 04 07 00 62 05 ?? ?? 94 06 00 03 48 05 05 06 b7 54 8d 44 4f 04 02 00 d8 00 00 01 28 ef 62 00 ?? ?? 21 00 21 73 35 31 11 00 48 03 02 01 62 04 ?? ?? 94 05 01 00 48 04 04 05 b7 43 8d 33 4f 03 02 01 d8 01 01 01 28 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgent_H_2147838520_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.H!MTB"
        threat_id = "2147838520"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 1a 00 35 41 1e 00 dc 04 01 03 44 05 03 04 e2 05 05 08 44 06 03 04 e0 06 06 18 b6 65 b0 05 b7 15 4b 05 03 04 [0-16] b6 50 44 04 03 04 b7 40 d8 01 01 01 4b 00 02 01 28 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgent_I_2147838522_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.I!MTB"
        threat_id = "2147838522"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/example/assetexam" ascii //weight: 1
        $x_1_2 = "com.vqs.iphoneassess" ascii //weight: 1
        $x_1_3 = "/mnt/sdcard/VqsPhone.apk" ascii //weight: 1
        $x_1_4 = "isAppInstall" ascii //weight: 1
        $x_1_5 = "copyApkFromAssets" ascii //weight: 1
        $x_1_6 = "Runstart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgent_J_2147838523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.J!MTB"
        threat_id = "2147838523"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 12 34 20 08 00 22 00 [0-4] 70 20 [0-4] 10 00 11 00 49 02 01 00 df 03 02 ff d5 33 ed 6c d5 22 12 93 b6 32 8e 22 8e 22 50 02 01 00 [0-22] 21 13 35 32 15 00 d8 00 [0-4] d8 00 00 01 d8 00 [0-4] 49 02 01 00 df 03 02 ff b5 03 df 04 00 ff b5 42 b6 32 8e 22 8e 22 50 02 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {21 12 34 20 08 00 22 [0-4] 00 70 20 [0-4] 10 00 11 00 49 02 01 00 d5 23 12 93 df 02 02 ff d5 22 ed 6c b6 32 8e 22 8e 22 8e 22 50 02 01 00 [0-22] 21 13 35 32 16 00 d8 00 [0-4] d8 00 00 01 d8 00 [0-4] 49 02 01 00 df 03 00 ff b5 23 df 02 02 ff b5 02 b6 32 8e 22 8e 22 8e 22 50 02 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_AndroidOS_SAgent_KA_2147838524_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.KA!MTB"
        threat_id = "2147838524"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b ac 20 1c 00 21 0c 22 02 f0 ?? ?? 01 9b 08 22 99 19 20 1c 02 f0 ?? ?? 20 1c 02 f0 ?? ?? 58 af 05 1c 00 21 31 22 38 1c 02 f0 ?? ?? 31 1c 01 9b 0a ac 08 31 59 18 20 1c 3a 1c 30 23 ff f7 ?? ?? 38 36 28 1c 07 96 02 f0 ?? ?? 06 1c 01 9b 07 9a 20 1c 99 18 2b 1c 32 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {80 22 e5 ac 52 00 20 1c 00 21 02 f0 ?? ?? 20 1c 09 99 02 f0 ?? ?? 20 1c a5 a9 02 f0 ?? ?? ?? ?? 20 1c 79 44 02 f0 ?? ?? 20 1c ff f7 ?? ?? ?? ?? 20 1c 79 44 02 f0 ?? ?? 20 1c ff f7 ?? ?? ?? ?? 21 1c 78 44 2c 30 02 f0 ?? ?? 20 1c 39 1c 02 f0 ?? ?? ?? ?? 20 1c 79 44 02 f0 ?? ?? 04 1c 01 22 23 1c 29 1c 30 1c 02 f0 ?? ?? 20 1c 02 f0 ?? ?? 20 1c 02 f0 ?? ?? 30 1c 02 f0 ?? ?? 07 9b 06 9a 5e 19 05 9b 01 33 05 93}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgent_KB_2147838525_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgent.KB!MTB"
        threat_id = "2147838525"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 03 19 00 92 04 01 03 d8 05 04 02 6e 30 ?? ?? 46 05 0c 04 13 05 10 00 71 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0a 04 4f 04 02 03 d8 03 03 01 28 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

