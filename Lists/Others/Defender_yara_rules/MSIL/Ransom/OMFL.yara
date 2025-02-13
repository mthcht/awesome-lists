rule Ransom_MSIL_OMFL_DA_2147774381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/OMFL.DA!MTB"
        threat_id = "2147774381"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OMFL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".omfl" ascii //weight: 1
        $x_1_2 = "SHA384" ascii //weight: 1
        $x_1_3 = "desktop.ini" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "chomuranso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

