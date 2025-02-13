rule Ransom_MSIL_Maoloa_UH_2147843239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Maoloa.UH!MTB"
        threat_id = "2147843239"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Maoloa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 00 6f 15 00 00 0a 11 03 16 11 03 8e 69 6f 16 00 00 0a 13 04 38 0c 00 00 00 28 09 00 00 06 13 03 38 da ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

