rule Ransom_MSIL_Sharkcrypt_B_2147717033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Sharkcrypt.B"
        threat_id = "2147717033"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sharkcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your code goes here*" wide //weight: 2
        $x_2_2 = "CreateDecryptor" ascii //weight: 2
        $x_1_3 = "payload_path" ascii //weight: 1
        $x_1_4 = "extensions" ascii //weight: 1
        $x_1_5 = "default_price" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Sharkcrypt_A_2147717034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Sharkcrypt.A"
        threat_id = "2147717034"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sharkcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<encrypt_directory>b__0" ascii //weight: 2
        $x_2_2 = "Shark.exe" ascii //weight: 2
        $x_1_3 = "default_price" ascii //weight: 1
        $x_1_4 = ".locked" wide //weight: 1
        $x_1_5 = "Decryptor.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Sharkcrypt_A_2147717099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Sharkcrypt.A!!Sharkcrypt.gen!A"
        threat_id = "2147717099"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sharkcrypt"
        severity = "Critical"
        info = "Sharkcrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<encrypt_directory>b__0" ascii //weight: 2
        $x_2_2 = "Shark.exe" ascii //weight: 2
        $x_1_3 = "default_price" ascii //weight: 1
        $x_1_4 = ".locked" wide //weight: 1
        $x_1_5 = "Decryptor.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Sharkcrypt_B_2147717100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Sharkcrypt.B!!Sharkcrypt.gen!B"
        threat_id = "2147717100"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sharkcrypt"
        severity = "Critical"
        info = "Sharkcrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your code goes here*" wide //weight: 2
        $x_2_2 = "CreateDecryptor" ascii //weight: 2
        $x_1_3 = "payload_path" ascii //weight: 1
        $x_1_4 = "extensions" ascii //weight: 1
        $x_1_5 = "default_price" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

