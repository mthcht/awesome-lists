rule TrojanDropper_AndroidOS_SpyBnk_A_2147777644_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SpyBnk.A!MTB"
        threat_id = "2147777644"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SpyBnk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 0c 00 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 10 ?? ?? 07 00 0c 03 22 04 ?? ?? 70 10 ?? ?? 04 00 22 05 ?? ?? 70 10 ?? ?? 05 00 6e 10 ?? ?? 02 00 0c 06 6e 20 ?? ?? 65 00 1a 06 03 00 6e 20 ?? ?? 65 00 6e 10 ?? ?? 05 00 0c 05 6e 10 ?? ?? 05 00 0c 05 6e 20 ?? ?? 54 00 6e 10}  //weight: 1, accuracy: Low
        $x_1_2 = {07 00 0c 05 6e 20 0d 00 25 00 0c 02 12 05 46 02 02 05 6e 20 ?? ?? 24 00 6e 10 ?? ?? 04 00 0c 02 6e 20 0e 00 23 00 0c 02 13 03 0b 00 23 33 34 00 6e 20 ?? ?? 32 00 13 04 08 00 48 05 03 04 d5 55 ff 00 e0 05 05 10 13 06 09 00 48 06 03 06 d5 66 ff 00 e0 04 06 08 b6 54 13 05 0a 00 48 03 03 05 d5 33 ff 00 b6 43 6e 10 ?? ?? 02 00 0a 04 70 54}  //weight: 1, accuracy: Low
        $x_1_3 = "getAssets" ascii //weight: 1
        $x_1_4 = "/JxApplication;" ascii //weight: 1
        $x_1_5 = "/K9Receiver;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SpyBnk_E_2147797853_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SpyBnk.E!MTB"
        threat_id = "2147797853"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SpyBnk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 01 00 10 23 12 2d 00 71 20 ?? ?? 1a 00 0a 03 12 04 6e 40 ?? ?? 29 34 0a 03 12 f5 32 53 16 00 39 03 03 00 28 12 b1 3a 12 05 35 35 0b 00 48 06 02 05 b7 b6 8d 66 4f 06 02 05 d8 05 05 01 28 f6 6e 40 ?? ?? 20 34 28 e1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SpyBnk_D_2147799093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SpyBnk.D!MTB"
        threat_id = "2147799093"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SpyBnk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 06 00 08 23 66 ?? ?? 6e 20 ?? ?? 62 00 0a 07 12 f8 33 87 35 00 70 40 ?? ?? 1a 64 6e 10 ?? ?? 01 00 0c 01 6e 10 ?? ?? 00 00 0c 02 71 20 ?? ?? 12 00 22 01 ?? ?? 22 02 ?? ?? 70 10 ?? ?? 02 00 6e 10 ?? ?? 0a 00 0c 03 6e 10 ?? ?? 03 00 0c 03 6e 20 ?? ?? 32 00 1a 03 06 00 6e 20 ?? ?? 32 00 6e 10 ?? ?? 02 00 0c 02 70 20 ?? ?? 21 00 6e 10 ?? ?? 01 00 70 20 ?? ?? 0a 00 0e 00 12 08 35 78 0b 00 48 09 06 08 b7 39 8d 99 4f 09 06 08 d8 08 08 01 28 f6 6e 40 ?? ?? 64 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SpyBnk_C_2147799094_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SpyBnk.C!MTB"
        threat_id = "2147799094"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SpyBnk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 01 00 10 23 11 ?? ?? 21 12 71 20 ?? ?? 29 00 0a 02 12 03 6e 40 ?? ?? 18 23 0a 02 12 f4 32 42 16 00 39 02 03 00 28 12 b1 29 12 04 35 24 0b 00 48 05 01 04 b7 a5 8d 55 4f 05 01 04 d8 04 04 01 28 f6 6e 40 ?? ?? 10 23 28 e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SpyBnk_B_2147799095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SpyBnk.B!MTB"
        threat_id = "2147799095"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SpyBnk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 00 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 10 ?? ?? 07 00 0c 03 22 04 ?? ?? 70 10 ?? ?? 04 00 22 05 ?? ?? 70 10 ?? ?? 05 00 6e 10 ?? ?? 02 00 0c 06 6e 20 ?? ?? 65 00 1a 06 01 00 6e 20 ?? ?? 65 00 6e 10 ?? ?? 05 00 0c 05 6e 10 ?? ?? 05 00 0c 05 6e 20 ?? ?? 54 00 6e 10}  //weight: 2, accuracy: Low
        $x_2_2 = {07 00 0c 05 6e 20 0d 00 25 00 0c 02 12 05 46 02 02 05 6e 20 ?? ?? 24 00 6e 10 ?? ?? 04 00 0c 02 6e 20 0e 00 23 00 0c 02 13 03 0b 00 23 33 31 00 6e 20 ?? ?? 32 00 13 04 08 00 48 05 03 04 d5 55 ff 00 e0 05 05 10 13 06 09 00 48 06 03 06 d5 66 ff 00 e0 04 06 08 b6 54 13 05 0a 00 48 03 03 05 d5 33 ff 00 b6 43}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_AndroidOS_SpyBnk_F_2147799096_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SpyBnk.F!MTB"
        threat_id = "2147799096"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SpyBnk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 06 00 08 23 66 ?? ?? 6e 20 ?? ?? 62 00 0a 07 12 f8 33 87 35 00 70 40 ?? ?? 1a 64 6e 10 ?? ?? 01 00 0c 01 6e 10 ?? ?? 00 00 0c 02 71 20 ?? ?? 12 00 22 01 ?? ?? 22 02 ?? ?? 70 10 ?? ?? 02 00 6e 10 ?? ?? 0a 00 0c 03 6e 10 ?? ?? 03 00 0c 03 6e 20 ?? ?? 32 00 1a 03 07 00 6e 20 ?? ?? 32 00 6e 10 ?? ?? 02 00 0c 02 70 20 ?? ?? 21 00 6e 10 ?? ?? 01 00 70 20 ?? ?? 0a 00 0e 00 12 08 35 78 0b 00 48 09 06 08 b7 39 8d 99 4f 09 06 08 d8 08 08 01 28 f6 6e 40 ?? ?? 64 75 28 b7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SpyBnk_G_2147799097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SpyBnk.G!MTB"
        threat_id = "2147799097"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SpyBnk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 06 00 08 23 66 ?? ?? 6e 20 ?? ?? 62 00 0a 07 12 f8 33 87 ?? ?? 70 40 ?? ?? 1a 64 6e 10 ?? ?? 01 00 0c 01 6e 10 ?? ?? 00 00 0c 02 71 20 ?? ?? 12 00 22 01 ?? ?? 22 02 ?? ?? 70 10 ?? ?? 02 00 6e 10 ?? ?? 0a 00 0c 03 6e 10 ?? ?? 03 00 0c 03 6e 20 ?? ?? 32 00 1a 03 04 00 6e 20 ?? ?? 32 00 6e 10 ?? ?? 02 00 0c 02 70 20 ?? ?? 21 00 6e 10 ?? ?? 01 00 6e 10 ?? ?? 00 00 0c 00 22 01 ?? ?? 70 10 ?? ?? 01 00 6e 10 ?? ?? 0a 00 0c 02 6e 10 ?? ?? 02 00 0c 02 6e 20 ?? ?? 21 00 1a 02 04 00 6e 20 ?? ?? 21 00 6e 10 ?? ?? 01 00 0c 01 70 30 ?? ?? 0a 01 0e 00 12 08 35 78 0b 00 48 09 06 08 b7 39 8d 99 4f 09 06 08 d8 08 08 01 28 f6 6e 40 ?? ?? 64 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SpyBnk_H_2147799098_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SpyBnk.H!MTB"
        threat_id = "2147799098"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SpyBnk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 07 00 08 23 77 ?? ?? 21 78 71 20 ?? ?? 83 00 0a 08 6e 40 ?? ?? 72 85 0a 08 12 f9 32 98 16 00 39 08 03 00 28 12 b1 83 12 09 35 89 0b 00 48 0a 07 09 b7 4a 8d aa 4f 0a 07 09 d8 09 09 01 28 f6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

