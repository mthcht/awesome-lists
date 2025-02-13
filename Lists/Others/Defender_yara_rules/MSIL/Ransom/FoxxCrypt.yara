rule Ransom_MSIL_FoxxCrypt_PA_2147796812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FoxxCrypt.PA!MTB"
        threat_id = "2147796812"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FoxxCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All of your files have been encrypted" wide //weight: 1
        $x_1_2 = "\\___RECOVER__FILES__.foxxy.txt" wide //weight: 1
        $x_1_3 = ".foxxy" wide //weight: 1
        $x_1_4 = "Encrypting:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

