rule Trojan_MSIL_Snojan_AS_2147838185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snojan.AS!MTB"
        threat_id = "2147838185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snojan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 05 09 11 05 09 6f 33 00 00 0a 1e 5b 6f 34 00 00 0a 6f 35 00 00 0a 00 09 11 05 09 6f 36 00 00 0a 1e 5b 6f 34 00 00 0a 6f 37 00 00 0a 00 09 17 6f 38 00 00 0a 00 08 09 6f 39 00 00 0a}  //weight: 2, accuracy: High
        $x_1_2 = "fuax" wide //weight: 1
        $x_1_3 = "FSAFSAFASFASFSAFSAFAS" wide //weight: 1
        $x_1_4 = "afaw.afaw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

