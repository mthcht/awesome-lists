rule Trojan_MSIL_Shelma_SPQ_2147838120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelma.SPQ!MTB"
        threat_id = "2147838120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 08 11 09 07 11 09 9a 1f 10 28 10 00 00 0a 9c 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d dc}  //weight: 5, accuracy: High
        $x_1_2 = "20221213.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelma_ASH_2147846138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelma.ASH!MTB"
        threat_id = "2147846138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 11 2b 37 11 0e 11 11 91 18 59 2d 15 11 0e 11 11 11 0e 11 11 91 1b 59 20 ff 00 00 00 5f d2 9c 2b 13 11 0e 11 11 11 0e 11 11 91 1b 59 20 ff 00 00 00 5f d2 9c 11 11 17 58 13 11 11 11 11 0e 8e 69 32 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelma_ASH_2147846138_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelma.ASH!MTB"
        threat_id = "2147846138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 0a 2b 4b 11 04 11 0a 11 04 11 0a 91 11 07 11 0a 1f 20 5d 91 61 d2 9c 11 04 11 0a 11 04 11 0a 91 6e 11 06 11 0a 1f 20 5d 94 6a 59 ?? ?? ?? ?? ?? 6a 5f d2 9c 11 04 11 0a 11 04 11 0a 91 11 05 11 0a 1f 10 5d 91 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 04 8e 69 32 ad}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelma_AAMZ_2147888947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelma.AAMZ!MTB"
        threat_id = "2147888947"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 00 07 18 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 0c 08 06 16 06 8e 69 6f ?? 00 00 0a 0d}  //weight: 3, accuracy: Low
        $x_1_2 = "4qPxf87juOWHJvnn+vSesXjPCbJpJZTIJl" wide //weight: 1
        $x_1_3 = "abcd123544534kkkddf1111324325kkd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelma_SXP_2147900081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelma.SXP!MTB"
        threat_id = "2147900081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 06 02 06 91 18 59 20 ?? ?? ?? 00 5f d2 9c 06 17 58 0a 06 02 8e 69 32 e7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelma_GP_2147901080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelma.GP!MTB"
        threat_id = "2147901080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {72 c8 19 00 70 0b 72 ca 19 00 70 28 0c 00 00 06 0c 72 ca 19 00 70 28 0c 00 00 06 0d 73 1b 00 00 0a 13 04 06 28 1c 00 00 0a 73 1d 00 00 0a 13 05 11 05 11 04 08 09}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

