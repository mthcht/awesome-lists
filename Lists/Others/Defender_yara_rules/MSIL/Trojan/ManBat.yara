rule Trojan_MSIL_ManBat_KAA_2147905521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ManBat.KAA!MTB"
        threat_id = "2147905521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ManBat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 08 11 04 11 08 91 07 11 08 91 61 9c 11 08 17 d6 13 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

