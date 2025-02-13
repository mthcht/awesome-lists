rule Ransom_MSIL_Ramsil_SK_2147754390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ramsil.SK!MTB"
        threat_id = "2147754390"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ramsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\README.txt" wide //weight: 1
        $x_1_2 = "This is a punishment on you !!!" wide //weight: 1
        $x_1_3 = "Files encrypted are as follows:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

