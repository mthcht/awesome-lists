rule Trojan_MSIL_Purelogstealer_SRT_2147936584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogstealer.SRT!MTB"
        threat_id = "2147936584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 10 00 00 0a 07 6f 11 00 00 0a 6f 12 00 00 0a 06 fe 06 ?? ?? ?? 06 73 13 00 00 0a 28 01 00 00 2b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Purelogstealer_SOLD_2147938427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogstealer.SOLD!MTB"
        threat_id = "2147938427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 61 00 00 70 28 0c 00 00 0a 0a 72 bb 00 00 70 28 0c 00 00 0a 0b 28 0d 00 00 0a 0c 08 06 6f 0e 00 00 0a 08 07 6f 0f 00 00 0a 73 10 00 00 0a 0d 09 08 6f 11 00 00 0a 17 73 12 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Purelogstealer_SEAW_2147940709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogstealer.SEAW!MTB"
        threat_id = "2147940709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 0a 00 00 06 0a 73 0b 00 00 0a 25 06 28 09 00 00 06 6f 0c 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

