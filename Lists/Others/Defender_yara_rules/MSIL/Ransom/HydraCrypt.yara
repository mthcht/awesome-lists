rule Ransom_MSIL_HydraCrypt_DA_2147774380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HydraCrypt.DA!MTB"
        threat_id = "2147774380"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "/C wmic shadowcopy delete" ascii //weight: 1
        $x_1_3 = "do not try to rename encrypted files" ascii //weight: 1
        $x_1_4 = "Algorithms used are AES and RSA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HydraCrypt_DB_2147774382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HydraCrypt.DB!MTB"
        threat_id = "2147774382"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Directory_encryptor" ascii //weight: 1
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "get_Extension" ascii //weight: 1
        $x_1_4 = "EncryptDir" ascii //weight: 1
        $x_1_5 = "EncryptFile" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HydraCrypt_DC_2147774383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HydraCrypt.DC!MTB"
        threat_id = "2147774383"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FolderToEncrypt" ascii //weight: 1
        $x_1_2 = "EncryptFiles" ascii //weight: 1
        $x_1_3 = "password" ascii //weight: 1
        $x_1_4 = "Fucked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HydraCrypt_PA_2147808421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HydraCrypt.PA!MTB"
        threat_id = "2147808421"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".HYDRA" wide //weight: 1
        $x_1_2 = "/HYDRA;component/mainwindow.xaml" wide //weight: 1
        $x_1_3 = "\\HYDRA.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

