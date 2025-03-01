rule Trojan_MSIL_SpyKeyLogger_RDA_2147903920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyKeyLogger.RDA!MTB"
        threat_id = "2147903920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 43 00 00 0a 80 1a 00 00 04 7e 1a 00 00 04 07 16 07 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

