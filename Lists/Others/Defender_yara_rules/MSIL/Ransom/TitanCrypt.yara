rule Ransom_MSIL_TitanCrypt_PA_2147818493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/TitanCrypt.PA!MTB"
        threat_id = "2147818493"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TitanCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All of your files have been encrypted" wide //weight: 1
        $x_1_2 = "\\___RECOVER__FILES__.titancrypt.txt" wide //weight: 1
        $x_1_3 = ".titancrypt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

