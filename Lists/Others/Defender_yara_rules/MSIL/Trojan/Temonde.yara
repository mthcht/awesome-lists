rule Trojan_MSIL_Temonde_MCF_2147946230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Temonde.MCF!MTB"
        threat_id = "2147946230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Temonde"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 00 21 67 00 45 00 6c 00 30 00 59 00 4d 00 52 00 53 00 52 00 48 00 31 00 6f 00 30 00 4c 00 78 00 56 00 00 2f 50 00 6f 00 6b 00 65 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

