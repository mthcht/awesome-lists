rule Trojan_MSIL_Nekark_MBDA_2147844514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.MBDA!MTB"
        threat_id = "2147844514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 cf 17 00 70 6f ?? 00 00 0a 74 ?? 00 00 01 72 db 17 00 70 72 df 17 00 70 6f ?? 00 00 0a 72 e5 17 00 70 72 e9 17 00 70 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 1f 24 9d 6f ce 00 00 0a 0b 07 8e 69 8d ?? 00 00 01 0c 16 13 04 2b 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_2147847152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark!MTB"
        threat_id = "2147847152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Microsoft.exe" ascii //weight: 3
        $x_1_2 = "TWljcm9zb2Z0JQ==" ascii //weight: 1
        $x_1_3 = "TWljcm9zb2Z0JA==" ascii //weight: 1
        $x_1_4 = "TWljcm9zb2Z0Kg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Nekark_MBFQ_2147899006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.MBFQ!MTB"
        threat_id = "2147899006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sddfhefddffjfsfkfgsacsafp" ascii //weight: 10
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_KAA_2147900307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.KAA!MTB"
        threat_id = "2147900307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 07 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 61 28 ?? 00 00 0a 03 08 20 ?? ?? 00 00 58 20 ?? ?? 00 00 59 03 8e 69 5d 91 59 20 ?? 00 00 00 58 17 58 20 00 ?? 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_HDAA_2147904771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.HDAA!MTB"
        threat_id = "2147904771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 91 61 02 08 20 ?? ?? 00 00 58 20 ?? ?? 00 00 59 02 8e 69 5d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_IIAA_2147905610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.IIAA!MTB"
        threat_id = "2147905610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 61 04 08 20 ?? 02 00 00 58 20 ?? 02 00 00 59 1b 59 1b 58 04 8e 69 5d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_NK_2147911680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.NK!MTB"
        threat_id = "2147911680"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 17 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 72 ?? 00 00 70 6f 1a 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "ExclusionPath.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_ZKAA_2147923420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.ZKAA!MTB"
        threat_id = "2147923420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 06 07 20 cf 00 00 00 20 b8 00 00 00 28 ?? 00 00 2b 0c 04 03 6f ?? 00 00 0a 59 0d}  //weight: 2, accuracy: Low
        $x_3_2 = {03 19 8d 01 00 00 01 25 16 12 02 20 99 03 00 00 20 b5 03 00 00 28 ?? 00 00 06 9c 25 17 12 02 20 82 00 00 00 20 af 00 00 00 28 ?? 00 00 06 9c 25 18 12 02 20 1f 02 00 00 20 69 02 00 00 28 ?? 01 00 06 9c 6f ?? 00 00 0a 11 0f}  //weight: 3, accuracy: Low
        $x_2_3 = {03 11 06 75 03 00 00 1b 11 07 74 04 00 00 1b 11 08 94 91 6f ?? 00 00 0a 1e 13 0e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_NM_2147927269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.NM!MTB"
        threat_id = "2147927269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "she lazy universe she understand" ascii //weight: 1
        $x_1_2 = "quick them white them object teach me old them design" ascii //weight: 1
        $x_2_3 = "PatrickRichPlayer322Patrick.dnpyG" ascii //weight: 2
        $x_1_4 = "design it blue" ascii //weight: 1
        $x_1_5 = "old innovate computer" ascii //weight: 1
        $x_1_6 = "black solution solve" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_AYA_2147929764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.AYA!MTB"
        threat_id = "2147929764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Horror_virus.Properties.Resources" wide //weight: 2
        $x_1_2 = "You Computer Hacked :)" wide //weight: 1
        $x_1_3 = "your computer won't start because MBR deleted" wide //weight: 1
        $x_1_4 = "DisableRegistryTools" wide //weight: 1
        $x_1_5 = "Trojan.redskull" wide //weight: 1
        $x_1_6 = "DisableTaskMgr" wide //weight: 1
        $x_1_7 = "if you break at least one rule, you computer death" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_PKM_2147936652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.PKM!MTB"
        threat_id = "2147936652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 00 0a 07 06 28 ?? 00 00 06 72 00 14 00 70 7e 3a 00 00 04 6f ?? 00 00 0a 72 0c 14 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 72 16 14 00 70 02 6f ?? 00 00 0a 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 07 72 22 14 00 70 6f ?? 00 00 0a 07 28 ?? 00 00 0a 26 de 03}  //weight: 3, accuracy: Low
        $x_2_2 = {06 08 91 18 5b 1f 0f 58 0d 07 09 d1 13 04 12 04 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 08 18 58 0c 08 06 8e 69 32 db}  //weight: 2, accuracy: Low
        $x_2_3 = "browser|opera|msedge|chrome|firefox|brave|vivaldi" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nekark_AYB_2147942954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nekark.AYB!MTB"
        threat_id = "2147942954"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\ICantThinkOfANameLmao\\obj\\Debug\\ICantThinkOfANameLmao.pdb" ascii //weight: 2
        $x_1_2 = "aaa_TouchMeNot_.txt" wide //weight: 1
        $x_1_3 = "Hello by running this file your agree to some files may be deleted or lost" wide //weight: 1
        $x_1_4 = "Moving and hiding files from Documents..." wide //weight: 1
        $x_1_5 = "MoveAndHideFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

