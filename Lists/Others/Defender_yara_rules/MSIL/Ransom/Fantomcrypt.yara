rule Ransom_MSIL_Fantomcrypt_A_2147717098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Fantomcrypt.A"
        threat_id = "2147717098"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fantomcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "critical update kb01" ascii //weight: 2
        $x_1_2 = "criticalupdate01" ascii //weight: 1
        $x_1_3 = "ft  corporation" ascii //weight: 1
        $x_1_4 = "critical update" ascii //weight: 1
        $x_1_5 = "lockdir" ascii //weight: 1
        $x_1_6 = "password" ascii //weight: 1
        $x_1_7 = "CreateEncryptor" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

