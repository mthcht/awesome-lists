rule Trojan_MSIL_Racoon_CC_2147837602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racoon.CC!MTB"
        threat_id = "2147837602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 04 17 58 13 04 11 04 20 00 01 00 00 5d 13 04 11 06 11 0a 11 04 94 58 13 06 11 06 20 00 01 00 00 5d 13 06 11 0a 11 04 94 13 08 11 0a 11 04 11 0a 11 06 94 9e 11 0a 11 06 11 08 9e 11 0a 11 0a 11 04 94 11 0a 11 06 94 58 20 00 01 00 00 5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Racoon_RDA_2147888100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racoon.RDA!MTB"
        threat_id = "2147888100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 19 00 00 0a 02 16 03 8e 69 6f 1a 00 00 0a 0a 06 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Racoon_BR_2147907484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racoon.BR!MTB"
        threat_id = "2147907484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 20 b8 00 00 00 28 17 00 00 0a 0b 02 50 06 8f 17 00 00 01 25 47 07 58 d2 52 1f 30 28 17 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Racoon_RDC_2147909190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Racoon.RDC!MTB"
        threat_id = "2147909190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Racoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0c 08 02 16 02 8e 69 6f 07 00 00 0a 08 6f 08 00 00 0a 07 6f 09 00 00 0a 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

