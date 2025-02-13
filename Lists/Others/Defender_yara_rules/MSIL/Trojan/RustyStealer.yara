rule Trojan_MSIL_RustyStealer_BH_2147914569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RustyStealer.BH!MTB"
        threat_id = "2147914569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 07 02 07 6f 76 00 00 0a 03 07 03 6f 74 00 00 0a 5d 6f 76 00 00 0a 61 d1 9d 00 07 17 58 0b 07 02 6f 74 00 00 0a fe 04 0c 08 2d d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

