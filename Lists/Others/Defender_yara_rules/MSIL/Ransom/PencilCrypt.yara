rule Ransom_MSIL_PencilCrypt_PA_2147798179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/PencilCrypt.PA!MTB"
        threat_id = "2147798179"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PencilCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\res\\bg.jpg" wide //weight: 1
        $x_1_2 = "SOFTWARE\\PencilCry" wide //weight: 1
        $x_1_3 = ".pencilcry" wide //weight: 1
        $x_1_4 = "your files have been encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

