rule Ransom_MSIL_Stupid_G_2147745148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Stupid.G!MTB"
        threat_id = "2147745148"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stupid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C choice /C Y /N /D Y /T 3 & Del" ascii //weight: 1
        $x_1_2 = "imha_zamani" ascii //weight: 1
        $x_1_3 = "Encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

