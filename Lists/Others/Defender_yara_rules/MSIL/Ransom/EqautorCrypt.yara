rule Ransom_MSIL_EqautorCrypt_PA_2147793712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/EqautorCrypt.PA!MTB"
        threat_id = "2147793712"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EqautorCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypter.exe" ascii //weight: 1
        $x_1_2 = "UNLOCKED" wide //weight: 1
        $x_1_3 = "encrypted by EQAUTOR RANSOMEWARE" wide //weight: 1
        $x_1_4 = "MYPERSONAL@PROTONMAIL.COM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

