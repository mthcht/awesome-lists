rule Ransom_MSIL_CornCrypt_B_2147719882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CornCrypt.B"
        threat_id = "2147719882"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CornCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Restoring your files - The nasty way" ascii //weight: 1
        $x_1_2 = "below to other people, if two or more people will install this file and pay, we will decrypt your files for free." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CornCrypt_PA_2147775468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CornCrypt.PA!MTB"
        threat_id = "2147775468"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CornCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\READ_IT.txt.fuckunicornhtrhrtjrjy" wide //weight: 1
        $x_1_2 = ".fuckunicornhtrhrtjrjy" wide //weight: 1
        $x_1_3 = "\\ransom.jpg" wide //weight: 1
        $x_1_4 = "fuckunicorn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

