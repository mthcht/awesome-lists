rule Trojan_MSIL_AnonymousRAT_RDA_2147920030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AnonymousRAT.RDA!MTB"
        threat_id = "2147920030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AnonymousRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 02 6f 2d 00 00 0a 18 8d 2f 00 00 01 25 16 1f 0a 9d 25 17 1f 0d 9d 17 6f 2e 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

