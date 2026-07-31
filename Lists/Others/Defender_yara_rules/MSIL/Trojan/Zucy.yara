rule Trojan_MSIL_Zucy_SSN_2147975029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zucy.SSN!MTB"
        threat_id = "2147975029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zucy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 0a 00 00 06 13 05 02 7b 0c 00 00 04 11 05 28 0b 00 00 06 13 06 11 05 1f 29 94 13 07 02 7b 0b 00 00 04 11 07 1e 58 73 1b 00 00 0a 28 0c 00 00 06 13 08 11 08 07 fe 01 13 0a 11 0a 39 13 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

