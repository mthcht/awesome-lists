rule Trojan_MSIL_LummaCStealer_CXFW_2147850269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaCStealer.CXFW!MTB"
        threat_id = "2147850269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaCStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "T4bWCOfEtS0MY" ascii //weight: 1
        $x_1_2 = "wRmWCOfDvKcco" ascii //weight: 1
        $x_1_3 = "KZvxddCnih4sbWx6hao" ascii //weight: 1
        $x_1_4 = "HCY62RCgepis74pcNX4" ascii //weight: 1
        $x_1_5 = "QNEYZkC5JxDGjlrAYwS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_LummaCStealer_AAKA_2147852867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaCStealer.AAKA!MTB"
        threat_id = "2147852867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaCStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 05 07 28 ?? 00 00 06 00 11 05 17 28 ?? 00 00 06 00 11 05 09 28 ?? 00 00 06 00 00 11 05 6f ?? 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 07 11 07 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

