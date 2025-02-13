rule Ransom_MSIL_Jcrypt_DA_2147772569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Jcrypt.DA!MTB"
        threat_id = "2147772569"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files have been encrypted" ascii //weight: 1
        $x_1_2 = ".jcrypt" ascii //weight: 1
        $x_1_3 = "RECOVER__FILES" ascii //weight: 1
        $x_1_4 = "AFTER PAYMENT IS SENT YOUR FILES WILL BE DECRYPTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Jcrypt_DB_2147773261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Jcrypt.DB!MTB"
        threat_id = "2147773261"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files (count: n) have been encrypted" ascii //weight: 1
        $x_1_2 = "RECOVER__FILES" ascii //weight: 1
        $x_1_3 = "Bitcoin" ascii //weight: 1
        $x_1_4 = ".jcrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Jcrypt_DC_2147774379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Jcrypt.DC!MTB"
        threat_id = "2147774379"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RECOVER__FILES" ascii //weight: 2
        $x_2_2 = "Encrypting" ascii //weight: 2
        $x_2_3 = "No files to encrypt" ascii //weight: 2
        $x_1_4 = ".jcrypt" ascii //weight: 1
        $x_1_5 = ".wannapay" ascii //weight: 1
        $x_1_6 = ".daddycrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

