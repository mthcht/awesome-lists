rule Trojan_MSIL_DarkVNC_GVN_2147978591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkVNC.GVN!MTB"
        threat_id = "2147978591"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkVNC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 32 11 0b 1d 5f 91 13 1a 11 1a 19 62 11 1a 1b 63 60 d2 13 1a 11 05 11 0b 11 05 11 0b 91 11 1a 61 d2 9c 11 0b 17 58 13 0b 11 0b 11 08 32 d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

