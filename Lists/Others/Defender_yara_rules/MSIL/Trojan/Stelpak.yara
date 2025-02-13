rule Trojan_MSIL_Stelpak_SK_2147918594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelpak.SK!MTB"
        threat_id = "2147918594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 08 28 17 00 00 0a 9c 73 18 00 00 0a 13 04 08 13 05 11 04 11 05 03 8e 69 5d 6f 19 00 00 0a 07 08 03 08 03 8e 69 5d 91 9c 08 17 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelpak_SL_2147919068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelpak.SL!MTB"
        threat_id = "2147919068"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 04 08 13 05 11 04 11 05 03 8e 69 5d}  //weight: 2, accuracy: High
        $x_2_2 = {07 08 03 08 03 8e 69 5d 91 9c 08 17 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelpak_EADV_2147931203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelpak.EADV!MTB"
        threat_id = "2147931203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 08 08 28 1f 00 00 0a 9c 07 08 04 08 05 5d 91 9c 08 17 58 0c 08 20 00 01 00 00 3f e0 ff ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelpak_EADV_2147931203_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelpak.EADV!MTB"
        threat_id = "2147931203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 11 07 1f 28 5a 58 13 08 28 2f 00 00 0a 07 11 08 1e 6f 30 00 00 0a 17 8d 30 00 00 01 6f 31 00 00 0a 28 08 00 00 06 72 00 01 00 70 28 32 00 00 0a 39 41 00 00 00 07 11 08 1f 14 58 28 2e 00 00 0a 13 09 07 11 08 1f 10 58 28 2e 00 00 0a 13 0a 11 0a 8d 1d 00 00 01 80 05 00 00 04 07 11}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

