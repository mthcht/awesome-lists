rule Trojan_MSIL_Rezlt_RDA_2147888236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rezlt.RDA!MTB"
        threat_id = "2147888236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rezlt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 93 0d 06 09 04 59 d1 6f 04 00 00 0a 26 08 00 15 17 58 17 58 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

