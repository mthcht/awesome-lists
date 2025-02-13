rule Ransom_AndroidOS_Rkor_A_2147829435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Rkor.A!MTB"
        threat_id = "2147829435"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Rkor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 00 21 41 35 10 18 00 48 01 04 00 71 00 ?? ?? 00 00 0c 02 71 00 ?? ?? 00 00 0c 03 21 33 94 03 00 03 48 02 02 03 b7 21 8d 11 4f 01 04 00 d8 00 00 01 28 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_AndroidOS_Rkor_B_2147831910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Rkor.B!MTB"
        threat_id = "2147831910"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Rkor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1a 00 00 00 71 00 ?? ?? 00 00 0c 00 21 01 3d 01 14 00 12 01 21 42 35 21 10 00 48 02 04 01 21 03 94 03 01 03 48 03 00 03 b7 32 8d 22 4f 02 04 01 d8 01 01 01 28 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_AndroidOS_Rkor_C_2147832692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Rkor.C!MTB"
        threat_id = "2147832692"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Rkor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 00 09 00 54 21 ?? 0c 33 13 05 00 72 20 ?? ?? 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 39 00 23 00 1c 00 ?? 02 1d 00 62 00 ?? 00 39 00 13 00 22 00 ?? 02 62 01 ?? 00 38 01 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

