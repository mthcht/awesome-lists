rule Trojan_MSIL_InjectorX_RDA_2147848266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorX.RDA!MTB"
        threat_id = "2147848266"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 04 11 0a 75 0e 00 00 1b 11 0c 93 13 05 11 0a 75 0e 00 00 1b 11 0c 17 58 93 11 05 61 13 06 1f 0e 13 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InjectorX_RDC_2147894064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorX.RDC!MTB"
        threat_id = "2147894064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 03 16 03 8e 69 6f 47 00 00 0a 00 11 05 6f 48 00 00 0a 00 11 04 6f 49 00 00 0a 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

