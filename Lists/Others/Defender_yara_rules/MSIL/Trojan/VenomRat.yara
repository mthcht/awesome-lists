rule Trojan_MSIL_VenomRat_AVN_2147929611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomRat.AVN!MTB"
        threat_id = "2147929611"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 07 2b 29 11 06 11 07 e0 58 11 04 11 07 91 52 11 06 11 07 e0 58 47 11 04 11 07 91 fe 01 16 fe 01 13 08 11 08 2d dd 11 07 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

