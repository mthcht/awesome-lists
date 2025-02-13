rule Trojan_MSIL_RatX_RDA_2147888938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RatX.RDA!MTB"
        threat_id = "2147888938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RatX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 75 4c 00 00 01 6f b1 00 00 0a 1e 9a 0b 07 0a 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

