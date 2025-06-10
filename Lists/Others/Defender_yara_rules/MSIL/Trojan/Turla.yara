rule Trojan_MSIL_Turla_PGT_2147943227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Turla.PGT!MTB"
        threat_id = "2147943227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Turla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {43 00 67 00 39 00 55 00 63 00 6d 00 46 00 75 00 63 00 33 00 42 00 76 00 63 00 6e 00 51 00 75 00 63 00 48 00 4a 00 76 00 64 00 47 00 38 00 53 00 44 00 30 00 31 00 76 00 5a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

