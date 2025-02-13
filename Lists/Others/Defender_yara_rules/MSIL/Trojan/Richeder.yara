rule Trojan_MSIL_Richeder_IJ_2147916555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Richeder.IJ!MTB"
        threat_id = "2147916555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Richeder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0e 17 58 1f 10 5d 08 58 13 0f 11 09 11 0e 8f 18 00 00 01 13 10 11 10 11 10 47 11 0f d2 61 d2 52 11 0e 13 07 11 07 17 58 13 0e 11 0e 11 09 8e 69 32 cd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

