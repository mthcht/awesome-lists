rule Ransom_MSIL_WannaCry_AYA_2147922981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaCry.AYA!MTB"
        threat_id = "2147922981"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WannaCry.Properties.Resources" wide //weight: 2
        $x_1_2 = "Ooops, your files have been encrypted!" wide //weight: 1
        $x_1_3 = "Nobody can recover your files without our decryption service" wide //weight: 1
        $x_1_4 = ".WNCRY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WannaCry_MBZ_2147942166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaCry.MBZ!MTB"
        threat_id = "2147942166"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ooops, your files has been encrypted" wide //weight: 2
        $x_1_2 = "Send $600 worth of bitcoin to this adress" wide //weight: 1
        $x_1_3 = "Wanna Decrypt0r 2.0" wide //weight: 1
        $x_1_4 = "Please pay first! one file deleted." wide //weight: 1
        $x_1_5 = "FAKE WANNA CRY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

