rule Adware_AndroidOS_Adlo_A_348570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Adlo.A!MTB"
        threat_id = "348570"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Adlo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1c 00 00 00 6e 10 ?? 01 01 00 0a 00 23 00 ?? 00 6e 20 ?? 01 01 00 6e 10 ?? 01 01 00 71 10 ?? 01 00 00 0c 01 6e 20 ?? 01 12 00 6e 10 ?? 01 02 00}  //weight: 10, accuracy: Low
        $x_10_2 = {12 00 00 00 21 ?? 23 00 ?? 00 12 01 [0-5] 35 [0-3] 00 48 [0-8] 8d ?? 4f ?? 00 ?? d8 [0-3] 01}  //weight: 10, accuracy: Low
        $x_1_3 = "createNewFile" ascii //weight: 1
        $x_1_4 = "BaseDexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Adware_AndroidOS_Adlo_B_435417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Adlo.B!MTB"
        threat_id = "435417"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Adlo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 03 00 08 48 04 02 08 dd 04 04 1f b7 43 8e 33 50 03 00 08 d8 08 08 01}  //weight: 1, accuracy: High
        $x_1_2 = {12 40 23 00 ?? 00 12 01 4d 02 00 01 62 02 05 00 12 11 4d 02 00 01 12 02 12 21 4d 02 00 01 12 32 4d 03 00 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Adlo_C_451259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Adlo.C!MTB"
        threat_id = "451259"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Adlo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 02 6f 20 01 00 21 00 12 02 69 02 05 00 0e 00 03 00 01 00 02}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 00 00 00 00 00 11 00 00 00 12 00 69 00 05 00 6f 10 02 00 02 00 0c 00 22 01 1a 00 70 10 19 00 01 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 0b 02 00 4d 0b 0c 02 6e 30 13 00 a9 0c 0c 09 71 10 16 00 08 00 0c 08 23 00 34 00 4d 06 00 01 4d 08 00 02 12 08 6e 30 27 00 89 00 0c 00 35 71 0d 00 71 20 21 00 14 00 0c 09 71 30 23 00 10 09 b0 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

