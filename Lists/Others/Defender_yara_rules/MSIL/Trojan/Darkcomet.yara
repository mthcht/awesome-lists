rule Trojan_MSIL_Darkcomet_AVY_2147833491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.AVY!MTB"
        threat_id = "2147833491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 08 11 05 20 00 01 00 00 5d b4 9c 07 11 08 17 d6 11 07 20 00 01 00 00 5d b4 9c 00 11 08 18 d6 13 08 11 08 11 0c 13 0e 11 0e 31 81}  //weight: 2, accuracy: High
        $x_1_2 = "jacques" wide //weight: 1
        $x_1_3 = "unoro" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_ACI_2147833818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.ACI!MTB"
        threat_id = "2147833818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 07 8e 69 5d 91 08 06 58 07 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 0c 00 00 01 08 17 58 0c 08 02 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_ARP_2147833952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.ARP!MTB"
        threat_id = "2147833952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 09 02 09 91 06 09 06 8e 69 5d 91 08 58 20 ff 00 00 00 5f 61 d2 9c 09 17 58 0d 09 07 8e 69 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_ADPP_2147833953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.ADPP!MTB"
        threat_id = "2147833953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0a 06 11 0a 06 91 11 04 06 91 61 28 ?? ?? ?? 0a 9c 06 17 d6 0a 28 ?? ?? ?? 0a 06 11 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_AMH_2147833954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.AMH!MTB"
        threat_id = "2147833954"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0d 17 02 28 ?? ?? ?? 0a b5 13 04 0b 2b 26 06 09 02 07 17 28}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_ADLQ_2147833955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.ADLQ!MTB"
        threat_id = "2147833955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 08 15 d6 0c 08 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_ACZA_2147833956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.ACZA!MTB"
        threat_id = "2147833956"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 07 11 05 11 07 91 06 11 06 25 17 58 13 06 91 61 d2 9c 11 06 06 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_ABIU_2147834054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.ABIU!MTB"
        threat_id = "2147834054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 06 08 11 06 91 09 11 06 09 8e 69 5d 91 11 05 58 20 00 02 00 00 5f 61 d2 9c 11 06 17 58}  //weight: 2, accuracy: High
        $x_1_2 = "Sheeit" ascii //weight: 1
        $x_1_3 = "img" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_AKH_2147834286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.AKH!MTB"
        threat_id = "2147834286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 1a 5a 0a 06 8d ?? ?? ?? 01 0c 02 25 13 07 2c 06 11 07 8e 69 2d 05 16 e0 0d 2b 09 11 07 16 8f ?? ?? ?? 01 0d 08 25 13 07 2c 06 11 07 8e 69 2d 06 16 e0 13 04 2b 0a 11 07 16 8f ?? ?? ?? 01 13 04 09 d3 11 04 d3 02 8e 69 08 8e 69 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_AXM_2147834287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.AXM!MTB"
        threat_id = "2147834287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 02 8e b7 17 59 0c 0b 2b 0f 02 07 02 07 91 1f 0d 61 d2 9c 07 1f 0d 58 0b 07 08 31 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_ADET_2147835045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.ADET!MTB"
        threat_id = "2147835045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 0a 13 08 2b 13 06 11 08 06 11 08 91 07 11 08 91 61 9c 11 08 17 d6 13 08 11 08 11 0a 31 e7 06 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darkcomet_ATJ_2147839132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkcomet.ATJ!MTB"
        threat_id = "2147839132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkcomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 0a 2b 46 02 50 17 8d 2d 00 00 01 13 04 11 04 16 06 8c 1f 00 00 01 a2 11 04 14 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

