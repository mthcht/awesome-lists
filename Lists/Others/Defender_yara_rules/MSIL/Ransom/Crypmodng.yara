rule Ransom_MSIL_Crypmodng_GBP_2147837199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypmodng.GBP!MTB"
        threat_id = "2147837199"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypmodng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 04 11 05 09 11 05 09 8e 69 5d 91 07 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 07 8e 69 32 e0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

