rule Trojan_MSIL_Gozi_MA_2147851302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gozi.MA!MTB"
        threat_id = "2147851302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 9f a2 2b 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 da 00 00 00 01 01 00 00 e2 04}  //weight: 2, accuracy: High
        $x_2_2 = "3a2c787f-67cb-40c2-89f4-aa5ee0d3c3cc" ascii //weight: 2
        $x_2_3 = "Yttsm.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Gozi_NG_2147899460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gozi.NG!MTB"
        threat_id = "2147899460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {19 8d 6d 00 00 01 0a 06 16 02 a2 06 17 03 8c ?? ?? 00 01 a2 06 18 04 a2 28 ?? ?? 00 06 28 ?? ?? 00 06 72 ?? ?? 00 70 06 28 ?? ?? 00 06 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "Xoladoniv.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Gozi_SK_2147905070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gozi.SK!MTB"
        threat_id = "2147905070"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 08 02 8e 69 5d 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 35 00 00 0a 02 08 17 58 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 b9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

