rule Trojan_MSIL_ZgRat_RPX_2147906235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRat.RPX!MTB"
        threat_id = "2147906235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 14 11 15 11 15 07 58 9e 11 15 17 58 13 15 11 15 11 14 8e 69 32 e9 11 11 17 58 13 11 11 11 03 8e 69 3f 52 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ZgRat_SGB_2147912597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZgRat.SGB!MTB"
        threat_id = "2147912597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZgRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 72 01 00 00 70 28 0f 00 00 06 80 01 00 00 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

