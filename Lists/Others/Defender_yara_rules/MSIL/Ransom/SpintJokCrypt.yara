rule Ransom_MSIL_SpintJokCrypt_PA_2147782349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SpintJokCrypt.PA!MTB"
        threat_id = "2147782349"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpintJokCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".SplinterJoke" wide //weight: 1
        $x_1_2 = "ransom_note.txt" wide //weight: 1
        $x_1_3 = "DeleteShadowCopies" ascii //weight: 1
        $x_1_4 = "YOUR FILES ARE ENCRYPTED" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

