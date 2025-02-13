rule Ransom_MSIL_Cryptolocker_PDA_2147776487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDA!MTB"
        threat_id = "2147776487"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WannaLocker" ascii //weight: 1
        $x_1_2 = "@WannaPeace" ascii //weight: 1
        $x_1_3 = "key2.ico" ascii //weight: 1
        $x_1_4 = "Bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDA_2147776487_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDA!MTB"
        threat_id = "2147776487"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2.0" ascii //weight: 1
        $x_1_2 = "ToBase64String" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "ConfuserEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDA_2147776487_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDA!MTB"
        threat_id = "2147776487"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AlbCry 2.0" ascii //weight: 1
        $x_1_2 = "AlbCry.g.resources" ascii //weight: 1
        $x_1_3 = "EncryptedFiles" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDA_2147776487_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDA!MTB"
        threat_id = "2147776487"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_2 = "How To Decrypt Files.txt" ascii //weight: 1
        $x_1_3 = ".Lock" ascii //weight: 1
        $x_1_4 = "EncryptDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDA_2147776487_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDA!MTB"
        threat_id = "2147776487"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Task Manager" ascii //weight: 1
        $x_1_2 = "EncryptFiles" ascii //weight: 1
        $x_1_3 = "GetBitcoinAddress" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "_Encrypted$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDA_2147776487_5
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDA!MTB"
        threat_id = "2147776487"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your All Files Are Decrypted" ascii //weight: 1
        $x_1_2 = "FucktheSystem" ascii //weight: 1
        $x_1_3 = "Encryption Complete" ascii //weight: 1
        $x_1_4 = "Wrong Key Bitch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDA_2147776487_6
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDA!MTB"
        threat_id = "2147776487"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware2.0" ascii //weight: 1
        $x_1_2 = "Rasomware2._0.Properties.Resources" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDA_2147776487_7
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDA!MTB"
        threat_id = "2147776487"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your computer files have been encrypted" ascii //weight: 1
        $x_1_2 = "BitcoinBlackmailer" ascii //weight: 1
        $x_1_3 = "EncryptedFiles" ascii //weight: 1
        $x_1_4 = "ExtensionsToEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDA_2147776487_8
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDA!MTB"
        threat_id = "2147776487"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_2 = ".[Crimsonware@protonmail.ch]" ascii //weight: 1
        $x_1_3 = "files have been encrypted" ascii //weight: 1
        $x_1_4 = "INFO.hta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDB_2147776593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDB!MTB"
        threat_id = "2147776593"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "have been encrypted" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "RECOVER__FILES" ascii //weight: 1
        $x_1_4 = ".jcrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDB_2147776593_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDB!MTB"
        threat_id = "2147776593"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Have fun exploring your corrupted files" ascii //weight: 1
        $x_1_2 = "Key is destroyed" ascii //weight: 1
        $x_1_3 = "Decrypting files" ascii //weight: 1
        $x_1_4 = "Crapsomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDB_2147776593_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDB!MTB"
        threat_id = "2147776593"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X1JlY292ZXJfSW5zdHJ1Y3Rpb25zLnR4dA" ascii //weight: 1
        $x_1_2 = "X1JlY292ZXJfSW5zdHJ1Y3Rpb25zLnBuZw" ascii //weight: 1
        $x_1_3 = "SW5maW5pdHlMb2Nr" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDC_2147776669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDC!MTB"
        threat_id = "2147776669"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2.0" ascii //weight: 1
        $x_1_2 = "_Encrypted$" ascii //weight: 1
        $x_1_3 = "RXhjaXRlUkFOJA" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDC_2147776669_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDC!MTB"
        threat_id = "2147776669"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Files Were Encrypted" ascii //weight: 1
        $x_1_2 = "Encrypted your files successfully" ascii //weight: 1
        $x_1_3 = "Encrypt your files" ascii //weight: 1
        $x_1_4 = ".cryptshield" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDD_2147776900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDD!MTB"
        threat_id = "2147776900"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "birbware" ascii //weight: 1
        $x_1_2 = ".birbb" ascii //weight: 1
        $x_1_3 = "ransom.Properties.Resources" ascii //weight: 1
        $x_1_4 = "Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDD_2147776900_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDD!MTB"
        threat_id = "2147776900"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Success Decrypt" ascii //weight: 1
        $x_1_2 = "Baddy.Resources" ascii //weight: 1
        $x_1_3 = ".baddy" ascii //weight: 1
        $x_1_4 = "Wrong.Hahaha." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDD_2147776900_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDD!MTB"
        threat_id = "2147776900"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Crapsomware.Properties" ascii //weight: 1
        $x_1_2 = "Q3JhcHNvbXdhcmUk" ascii //weight: 1
        $x_1_3 = "GetFiles" ascii //weight: 1
        $x_1_4 = "Encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDD_2147776900_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDD!MTB"
        threat_id = "2147776900"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cryptolocker" ascii //weight: 1
        $x_1_2 = "bitcoin address" ascii //weight: 1
        $x_1_3 = "KEY.cryptolocker" ascii //weight: 1
        $x_1_4 = "Recovery Information.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDD_2147776900_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDD!MTB"
        threat_id = "2147776900"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decrypting your files" ascii //weight: 1
        $x_1_2 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" ascii //weight: 1
        $x_1_4 = ".WeSt Net Fake" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDD_2147776900_5
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDD!MTB"
        threat_id = "2147776900"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "all of your files Are safely Encrypted" ascii //weight: 1
        $x_1_2 = "ransom.jpg" ascii //weight: 1
        $x_1_3 = "@protonmail.com" ascii //weight: 1
        $x_1_4 = ".onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDD_2147776900_6
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDD!MTB"
        threat_id = "2147776900"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files are encrypted" ascii //weight: 1
        $x_1_2 = "Purchase Bitcoin" ascii //weight: 1
        $x_1_3 = "Decryption Key" ascii //weight: 1
        $x_1_4 = "Your files are all now decrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDD_2147776900_7
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDD!MTB"
        threat_id = "2147776900"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decryption Program for Cryptolocker" ascii //weight: 1
        $x_1_2 = "cryptolocker.exe" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Debugger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDE_2147776990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDE!MTB"
        threat_id = "2147776990"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "K4Kransom" ascii //weight: 1
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "FileEncrypt" ascii //weight: 1
        $x_1_4 = "Encrypter" ascii //weight: 1
        $x_1_5 = "Stalin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDE_2147776990_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDE!MTB"
        threat_id = "2147776990"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_2 = "Dark Ransomeware" ascii //weight: 1
        $x_1_3 = "Please_Read.txt" ascii //weight: 1
        $x_1_4 = "@mail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDF_2147777302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDF!MTB"
        threat_id = "2147777302"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your files encrypted" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "ARTEMON RANSOMWARE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDF_2147777302_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDF!MTB"
        threat_id = "2147777302"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "donot cry" ascii //weight: 1
        $x_1_2 = ".cring" ascii //weight: 1
        $x_1_3 = "EncryptFile" ascii //weight: 1
        $x_1_4 = "CryFile" ascii //weight: 1
        $x_1_5 = "deReadMe!!!.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDF_2147777302_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDF!MTB"
        threat_id = "2147777302"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fuck Rats Antivirus" ascii //weight: 1
        $x_1_2 = "HYDRA  Ransomware" ascii //weight: 1
        $x_1_3 = "Decrypt Your Files" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDF_2147777302_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDF!MTB"
        threat_id = "2147777302"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hidden-tear" ascii //weight: 1
        $x_1_2 = "AES_Encrypt" ascii //weight: 1
        $x_1_3 = "EncryptFile" ascii //weight: 1
        $x_1_4 = "encryptDirectory" ascii //weight: 1
        $x_1_5 = "bytesToBeEncrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDF_2147777302_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDF!MTB"
        threat_id = "2147777302"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files have been encrypted" ascii //weight: 1
        $x_1_2 = "AES_Decrypt" ascii //weight: 1
        $x_1_3 = "BigEyes" ascii //weight: 1
        $x_1_4 = "Delete_all_file" ascii //weight: 1
        $x_1_5 = "@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDF_2147777302_5
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDF!MTB"
        threat_id = "2147777302"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your personal files are being deleted" ascii //weight: 1
        $x_1_2 = "ExtensionsToEncrypt" ascii //weight: 1
        $x_1_3 = "BitcoinBlackmailer" ascii //weight: 1
        $x_1_4 = "EncryptedFileList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDG_2147777401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDG!MTB"
        threat_id = "2147777401"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files has been encrypted" ascii //weight: 1
        $x_1_2 = "encryptDirectory" ascii //weight: 1
        $x_1_3 = "EncryptFile" ascii //weight: 1
        $x_1_4 = "AES_Encrypt" ascii //weight: 1
        $x_1_5 = "Zer0Byte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDG_2147777401_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDG!MTB"
        threat_id = "2147777401"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your personal files have been ecrypted" ascii //weight: 1
        $x_1_2 = ".locked" ascii //weight: 1
        $x_1_3 = "EncryptFile" ascii //weight: 1
        $x_1_4 = "encryptDirectory" ascii //weight: 1
        $x_1_5 = "blocky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDG_2147777401_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDG!MTB"
        threat_id = "2147777401"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Annabelle.exe" ascii //weight: 1
        $x_1_2 = "ActionEncrypt" ascii //weight: 1
        $x_1_3 = "GetLogicalDrives" ascii //weight: 1
        $x_1_4 = "GetDirectories" ascii //weight: 1
        $x_1_5 = "GetFiles" ascii //weight: 1
        $x_1_6 = "CFAL Hack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDH_2147777545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDH!MTB"
        threat_id = "2147777545"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ziggy Ransomware" ascii //weight: 1
        $x_1_2 = "Reamaining time:" ascii //weight: 1
        $x_1_3 = "SELECT * FROM Win32_DiskDrive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDH_2147777545_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDH!MTB"
        threat_id = "2147777545"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files have been encrypted" ascii //weight: 1
        $x_1_2 = "RansomeToad" ascii //weight: 1
        $x_1_3 = "Povlsomware" ascii //weight: 1
        $x_1_4 = "Decrypt Files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDH_2147777545_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDH!MTB"
        threat_id = "2147777545"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SS Encrypter" ascii //weight: 1
        $x_1_2 = "unlock your files" ascii //weight: 1
        $x_1_3 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDH_2147777545_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDH!MTB"
        threat_id = "2147777545"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All files deleted" ascii //weight: 1
        $x_1_2 = "Your Files were deleted" ascii //weight: 1
        $x_1_3 = "crypt_engine" ascii //weight: 1
        $x_1_4 = "encrypted_sound.wav" ascii //weight: 1
        $x_1_5 = ".crypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDH_2147777545_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDH!MTB"
        threat_id = "2147777545"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files (count: n) have been encrypted" ascii //weight: 1
        $x_1_2 = "RECOVER__FILES" ascii //weight: 1
        $x_1_3 = "encryptedFileCount" ascii //weight: 1
        $x_1_4 = "FileEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDI_2147777653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDI!MTB"
        threat_id = "2147777653"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All Files on your system has been encrypted" ascii //weight: 1
        $x_1_2 = "how_to_recover" ascii //weight: 1
        $x_1_3 = "hidden tear" ascii //weight: 1
        $x_1_4 = ".HANTA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDI_2147777653_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDI!MTB"
        threat_id = "2147777653"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows Store Download" ascii //weight: 1
        $x_1_2 = ".locked" ascii //weight: 1
        $x_1_3 = "EncryptString" ascii //weight: 1
        $x_1_4 = "FileExtension" ascii //weight: 1
        $x_1_5 = "EncryptAES" ascii //weight: 1
        $x_1_6 = "EncryptKey" ascii //weight: 1
        $x_1_7 = "RSAKey.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDJ_2147777745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDJ!MTB"
        threat_id = "2147777745"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files has been encrypted" ascii //weight: 1
        $x_1_2 = "hidden tear" ascii //weight: 1
        $x_1_3 = "HANTA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDJ_2147777745_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDJ!MTB"
        threat_id = "2147777745"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "How To Decrypt My Files" ascii //weight: 1
        $x_1_2 = ".Encrypted" ascii //weight: 1
        $x_1_3 = "Your BTC Address" ascii //weight: 1
        $x_1_4 = "@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDJ_2147777745_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDJ!MTB"
        threat_id = "2147777745"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net@sh @fir@ewa@ll se@t op@mo@de dis@able" ascii //weight: 1
        $x_1_2 = "Ransom" ascii //weight: 1
        $x_1_3 = "hurry hurry hurry" ascii //weight: 1
        $x_1_4 = "GetExtension" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDJ_2147777745_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDJ!MTB"
        threat_id = "2147777745"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your files have been encrypted" ascii //weight: 1
        $x_1_2 = "bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_3 = "recoveryenabled no" ascii //weight: 1
        $x_1_4 = ".encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDK_2147777834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDK!MTB"
        threat_id = "2147777834"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomwarePOC" ascii //weight: 1
        $x_1_2 = "_Encrypted$" ascii //weight: 1
        $x_1_3 = "V2luZG93c0Zvcm1zQXBwMSU=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDK_2147777834_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDK!MTB"
        threat_id = "2147777834"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files are encrypted" ascii //weight: 1
        $x_1_2 = "Penta ransomware" ascii //weight: 1
        $x_1_3 = "Wirusik_Ransom" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDK_2147777834_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDK!MTB"
        threat_id = "2147777834"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "locked.zip" ascii //weight: 1
        $x_1_2 = "set_Encryption" ascii //weight: 1
        $x_1_3 = "EncryptionAlgorithm" ascii //weight: 1
        $x_1_4 = "Ionic.Zlib" ascii //weight: 1
        $x_1_5 = "GetDirectoryName" ascii //weight: 1
        $x_1_6 = "GetDirectories" ascii //weight: 1
        $x_1_7 = "WriteAllLines" ascii //weight: 1
        $x_1_8 = "Build" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDL_2147778068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDL!MTB"
        threat_id = "2147778068"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your system have been encrypted" ascii //weight: 1
        $x_1_2 = "randomkey.bin" ascii //weight: 1
        $x_1_3 = ".RENSENWARE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDL_2147778068_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDL!MTB"
        threat_id = "2147778068"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decrypt My Files" ascii //weight: 1
        $x_1_2 = "ransom.jpg" ascii //weight: 1
        $x_1_3 = ".Crypted" ascii //weight: 1
        $x_1_4 = "No files decrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDL_2147778068_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDL!MTB"
        threat_id = "2147778068"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "No files to encrypt" ascii //weight: 1
        $x_1_2 = "RECOVER__FILES" ascii //weight: 1
        $x_1_3 = "have been encrypted" ascii //weight: 1
        $x_1_4 = ".ncovid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDL_2147778068_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDL!MTB"
        threat_id = "2147778068"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "all your important filese have are encrypted" ascii //weight: 1
        $x_1_2 = "Ransomware" ascii //weight: 1
        $x_1_3 = ".Lock" ascii //weight: 1
        $x_1_4 = ".onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDL_2147778068_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDL!MTB"
        threat_id = "2147778068"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C sc delete VSS" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "kWYZrzIYZR.html" ascii //weight: 1
        $x_1_4 = "rdpunlocker1@cock.li" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDL_2147778068_5
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDL!MTB"
        threat_id = "2147778068"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All encrypted files are formatted" ascii //weight: 1
        $x_1_2 = "HOW TO DECRYPT FILES" ascii //weight: 1
        $x_1_3 = "ransom.jpg" ascii //weight: 1
        $x_1_4 = ".Crypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDL_2147778068_6
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDL!MTB"
        threat_id = "2147778068"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOW_CAN_GET_FILES_BACK" ascii //weight: 1
        $x_1_2 = "Delete Shadows Finished" ascii //weight: 1
        $x_1_3 = "What The Fuck" ascii //weight: 1
        $x_1_4 = "@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDL_2147778068_7
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDL!MTB"
        threat_id = "2147778068"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypted files" ascii //weight: 1
        $x_1_2 = "decrypt your files" ascii //weight: 1
        $x_1_3 = "/C vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "READ_ME_FILE_ENCRYPTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDM_2147778166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDM!MTB"
        threat_id = "2147778166"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your personal files are encrypted" ascii //weight: 1
        $x_1_2 = "aesencrypted" ascii //weight: 1
        $x_1_3 = "SNSLOCKER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDM_2147778166_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDM!MTB"
        threat_id = "2147778166"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HELP_DECRYPT_YOUR_FILES" ascii //weight: 1
        $x_1_2 = ".encrypted" ascii //weight: 1
        $x_1_3 = "encryptFile" ascii //weight: 1
        $x_1_4 = "EncryptedKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDM_2147778166_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDM!MTB"
        threat_id = "2147778166"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted" ascii //weight: 1
        $x_1_2 = "RECOVER__FILES" ascii //weight: 1
        $x_1_3 = ".locked" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDM_2147778166_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDM!MTB"
        threat_id = "2147778166"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_Encrypted$" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "covid.Properties" ascii //weight: 1
        $x_1_4 = "worm_shield" ascii //weight: 1
        $x_1_5 = "GetDirectories" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDM_2147778166_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDM!MTB"
        threat_id = "2147778166"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptedFileList" ascii //weight: 1
        $x_1_2 = "ExtensionsToEncrypt" ascii //weight: 1
        $x_1_3 = "Your Pc have been fucked" ascii //weight: 1
        $x_1_4 = "Decrypting your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDN_2147778230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDN!MTB"
        threat_id = "2147778230"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "infected with ransomware" ascii //weight: 1
        $x_1_2 = "EncryptedFileList" ascii //weight: 1
        $x_1_3 = "ExtensionsToEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDN_2147778230_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDN!MTB"
        threat_id = "2147778230"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files are encrypted" ascii //weight: 1
        $x_1_2 = "DECRYPT MY FILES" ascii //weight: 1
        $x_1_3 = "/C sc delete VSS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDN_2147778230_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDN!MTB"
        threat_id = "2147778230"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WorkerCrypter2" ascii //weight: 1
        $x_1_2 = "SearchFiles" ascii //weight: 1
        $x_1_3 = "Encrypt" ascii //weight: 1
        $x_1_4 = "GenerateKey" ascii //weight: 1
        $x_1_5 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDO_2147778332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDO!MTB"
        threat_id = "2147778332"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All Your Files Encrypted" ascii //weight: 1
        $x_1_2 = "Jesus Ransom" ascii //weight: 1
        $x_1_3 = "Encryption Completed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDO_2147778332_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDO!MTB"
        threat_id = "2147778332"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptionNotComplet" ascii //weight: 1
        $x_1_2 = "WriteFile" ascii //weight: 1
        $x_1_3 = "lokjhgfder" ascii //weight: 1
        $x_1_4 = "Debugger Detected" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDO_2147778332_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDO!MTB"
        threat_id = "2147778332"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableTaskMgr" ascii //weight: 1
        $x_1_2 = "DisableRegistryTools" ascii //weight: 1
        $x_1_3 = "GetFiles" ascii //weight: 1
        $x_1_4 = "Processhacker" ascii //weight: 1
        $x_1_5 = "powershell" ascii //weight: 1
        $x_1_6 = "AmongUsHorrorEdition" ascii //weight: 1
        $x_1_7 = "Acvi cqaqltgf jj dgoe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDQ_2147778552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDQ!MTB"
        threat_id = "2147778552"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "What happen to my files" ascii //weight: 1
        $x_1_2 = "TrumpLocker" ascii //weight: 1
        $x_1_3 = "RansomNote" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDQ_2147778552_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDQ!MTB"
        threat_id = "2147778552"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DummyRansom" ascii //weight: 1
        $x_1_2 = "encryptDirectory" ascii //weight: 1
        $x_1_3 = "AES_Encrypt" ascii //weight: 1
        $x_1_4 = ".locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDQ_2147778552_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDQ!MTB"
        threat_id = "2147778552"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files has been encrypted" ascii //weight: 1
        $x_1_2 = "AES_Encrypt" ascii //weight: 1
        $x_1_3 = "bitcoins" ascii //weight: 1
        $x_1_4 = "EncryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDQ_2147778552_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDQ!MTB"
        threat_id = "2147778552"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I'm running in Debug mode" ascii //weight: 1
        $x_1_2 = "ExtensionsToEncrypt" ascii //weight: 1
        $x_1_3 = "JigsawRansomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDQ_2147778552_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDQ!MTB"
        threat_id = "2147778552"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All Files on your system has been encrypted" ascii //weight: 1
        $x_1_2 = ".HANTA" ascii //weight: 1
        $x_1_3 = "BTC wallet:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PDQ_2147778552_5
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PDQ!MTB"
        threat_id = "2147778552"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Win32_ShadowCopy" ascii //weight: 1
        $x_1_2 = "EncryptedFileName" ascii //weight: 1
        $x_1_3 = "EncryptedKey" ascii //weight: 1
        $x_1_4 = "Could not delete shadow copy" ascii //weight: 1
        $x_1_5 = "OPEN_ME_TO_RESTORE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_DK_2147779637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DK!MTB"
        threat_id = "2147779637"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your personal files have been ecrypted" ascii //weight: 1
        $x_1_2 = "CRACKED BY MAMO434376" ascii //weight: 1
        $x_1_3 = "READ_IT.txt.locked" ascii //weight: 1
        $x_1_4 = "wannadie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_DK_2147779637_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DK!MTB"
        threat_id = "2147779637"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "66"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "testeransw" ascii //weight: 50
        $x_50_2 = "disk_encoder" ascii //weight: 50
        $x_50_3 = "Ransomware.dll" ascii //weight: 50
        $x_10_4 = ".test" ascii //weight: 10
        $x_10_5 = ".DARXIS" ascii //weight: 10
        $x_10_6 = ".DcRat" ascii //weight: 10
        $x_5_7 = "EncryptAES" ascii //weight: 5
        $x_5_8 = "__KEYGEN" ascii //weight: 5
        $x_5_9 = "Encrypted Files" ascii //weight: 5
        $x_1_10 = "FileEncrypt" ascii //weight: 1
        $x_1_11 = "__ENCRYPTION" ascii //weight: 1
        $x_1_12 = "bytesToBeEncrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DL_2147779723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DL!MTB"
        threat_id = "2147779723"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "66"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "khjf ransomware" ascii //weight: 50
        $x_50_2 = "WannaSmile" ascii //weight: 50
        $x_50_3 = "NitroRansomware" ascii //weight: 50
        $x_50_4 = "Ren Locker" ascii //weight: 50
        $x_10_5 = "Your files have been encrypted" ascii //weight: 10
        $x_10_6 = "Bitcoins" ascii //weight: 10
        $x_10_7 = "your Drive have been encrypted" ascii //weight: 10
        $x_5_8 = "DisableRealtimeMonitoring" ascii //weight: 5
        $x_5_9 = "Bitcoin Payment Adress:" ascii //weight: 5
        $x_5_10 = "Decryption Key:" ascii //weight: 5
        $x_5_11 = "REN_Locker" ascii //weight: 5
        $x_1_12 = "DisableTaskMgr" ascii //weight: 1
        $x_1_13 = "Incorrect Decrypt Key" ascii //weight: 1
        $x_1_14 = "Decrypting files" ascii //weight: 1
        $x_1_15 = "Ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 4 of ($x_5_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DM_2147779724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DM!MTB"
        threat_id = "2147779724"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "66"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "UHJvamVjdEZyaWRheSU" ascii //weight: 50
        $x_50_2 = "FaturaWalker" ascii //weight: 50
        $x_50_3 = "Fatura Bilgilendirme" ascii //weight: 50
        $x_10_4 = "FridayProject.Properties" ascii //weight: 10
        $x_10_5 = "FaturaDecryptor" ascii //weight: 10
        $x_10_6 = "Fatura-master" ascii //weight: 10
        $x_5_7 = "CryptoObfuscator" ascii //weight: 5
        $x_5_8 = "EncryptionKey" ascii //weight: 5
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "encKey.aes" ascii //weight: 1
        $x_1_11 = "RmF0dXJhV2Fsa2VyOTA5MTI" ascii //weight: 1
        $x_1_12 = "EncryptFileFully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DN_2147779868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DN!MTB"
        threat_id = "2147779868"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "66"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "SAYGOODBYE.exe" ascii //weight: 50
        $x_50_2 = "ShellLocker" ascii //weight: 50
        $x_50_3 = "___RECOVER__FILES__.heart.txt" ascii //weight: 50
        $x_10_4 = "YOUR FILES HAVE BEEN  ENCRYPTED" ascii //weight: 10
        $x_10_5 = ".kanmani" ascii //weight: 10
        $x_10_6 = "\\Heartbeat\\keys.json" ascii //weight: 10
        $x_5_7 = "EncryptFiles" ascii //weight: 5
        $x_5_8 = "encryptFile" ascii //weight: 5
        $x_5_9 = "Encrypted Files Count:" ascii //weight: 5
        $x_1_10 = "Black Cat" ascii //weight: 1
        $x_1_11 = "crypt15" ascii //weight: 1
        $x_1_12 = "BTC address:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DO_2147779921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DO!MTB"
        threat_id = "2147779921"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "simple-ransomware" ascii //weight: 50
        $x_50_2 = "your files have been encrypted" ascii //weight: 50
        $x_50_3 = "All your files encrypted" ascii //weight: 50
        $x_20_4 = "files successfully encrypted" ascii //weight: 20
        $x_20_5 = "DECRYPTION_LOG.txt" ascii //weight: 20
        $x_20_6 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 20
        $x_3_7 = ".crypted" ascii //weight: 3
        $x_3_8 = "DisableAntiSpyware" ascii //weight: 3
        $x_3_9 = "DECRYPT_ReadMe1.TXT" ascii //weight: 3
        $x_1_10 = "EncryptFileSimple" ascii //weight: 1
        $x_1_11 = "No files to encrypt" ascii //weight: 1
        $x_1_12 = "HugeMe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DP_2147780069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DP!MTB"
        threat_id = "2147780069"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "your files have been encrypted" ascii //weight: 50
        $x_50_2 = "StonksVirus" ascii //weight: 50
        $x_20_3 = ".hjgkdf" ascii //weight: 20
        $x_20_4 = ".NotStonks" ascii //weight: 20
        $x_3_5 = "DisableRealtimeMonitoring" ascii //weight: 3
        $x_3_6 = "DeletedFilesAmmount.txt" ascii //weight: 3
        $x_1_7 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_8 = "Bitcoin wallet:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DQ_2147780331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DQ!MTB"
        threat_id = "2147780331"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "NitroRansomware" ascii //weight: 50
        $x_50_2 = "friendly.cyber.criminal" ascii //weight: 50
        $x_50_3 = "I will delete 1 file on your desktop" ascii //weight: 50
        $x_50_4 = "This computer has been hacked" ascii //weight: 50
        $x_20_5 = ".givemenitro" ascii //weight: 20
        $x_20_6 = "slamransomwareasistance" ascii //weight: 20
        $x_20_7 = ".deria" ascii //weight: 20
        $x_20_8 = "Your personal files have been ecrypted" ascii //weight: 20
        $x_3_9 = "Your files have been crypted" ascii //weight: 3
        $x_3_10 = "EncryptFile" ascii //weight: 3
        $x_3_11 = "SystemLocker" ascii //weight: 3
        $x_3_12 = "READ_IT.txt.locked" ascii //weight: 3
        $x_1_13 = "Decryption Key:" ascii //weight: 1
        $x_1_14 = "AES_Encrypt" ascii //weight: 1
        $x_1_15 = "ncrypted your" ascii //weight: 1
        $x_1_16 = "ransom.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_20_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DR_2147780431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DR!MTB"
        threat_id = "2147780431"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "vssadmin Delete shadows /all /quiet" ascii //weight: 50
        $x_50_2 = "FridayProject" ascii //weight: 50
        $x_50_3 = "aaa_TouchMeNot_.txt" ascii //weight: 50
        $x_20_4 = "Huzuni" ascii //weight: 20
        $x_20_5 = "ProjectFriday" ascii //weight: 20
        $x_20_6 = ".amogus" ascii //weight: 20
        $x_3_7 = "del /s /f /q C:\\*.VHD" ascii //weight: 3
        $x_3_8 = "DECRYPT FILES" ascii //weight: 3
        $x_3_9 = "___RECOVER__FILES__" ascii //weight: 3
        $x_1_10 = "window.bat" ascii //weight: 1
        $x_1_11 = "DisableTaskMgr" ascii //weight: 1
        $x_1_12 = "No files to encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_RM_2147780486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.RM!MTB"
        threat_id = "2147780486"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UnlockYourFiles.Login" ascii //weight: 1
        $x_1_2 = "DecryptAllFile" ascii //weight: 1
        $x_1_3 = "password" ascii //weight: 1
        $x_1_4 = "AES_Only_Decrypt_File" ascii //weight: 1
        $x_1_5 = "get_DarkGray" ascii //weight: 1
        $x_1_6 = "$8c012645-cc5b-4dff-9c13-812d74abc9b3" ascii //weight: 1
        $x_1_7 = "UnlockYourFiles.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_DS_2147780505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DS!MTB"
        threat_id = "2147780505"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "BaraFucked" ascii //weight: 50
        $x_50_2 = "V2._0.Properties" ascii //weight: 50
        $x_50_3 = "insane_uriel_by_urielstock_4.jpg" ascii //weight: 50
        $x_20_4 = ".kuru" ascii //weight: 20
        $x_20_5 = ".henry217" ascii //weight: 20
        $x_20_6 = "Encryptor" ascii //weight: 20
        $x_3_7 = "barakurumd" ascii //weight: 3
        $x_3_8 = "AESEncrypt" ascii //weight: 3
        $x_3_9 = "encryptToEncryptList" ascii //weight: 3
        $x_1_10 = "desktop.ini" ascii //weight: 1
        $x_1_11 = "EncryptByte" ascii //weight: 1
        $x_1_12 = "VM Detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DT_2147780807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DT!MTB"
        threat_id = "2147780807"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Kernsomware" ascii //weight: 50
        $x_50_2 = "Executioner Ransomware" ascii //weight: 50
        $x_20_3 = ".Kern" ascii //weight: 20
        $x_20_4 = "ransom.jpg" ascii //weight: 20
        $x_3_5 = "Your Files Have Been Encrypted" ascii //weight: 3
        $x_3_6 = "your files Are safely Encrypted" ascii //weight: 3
        $x_1_7 = "Bitcoin" ascii //weight: 1
        $x_1_8 = "@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DV_2147780809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DV!MTB"
        threat_id = "2147780809"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "DiscoRansomware" ascii //weight: 50
        $x_50_2 = "vxCrypter" ascii //weight: 50
        $x_50_3 = "Runcount.cry" ascii //weight: 50
        $x_50_4 = "hidden tear" ascii //weight: 50
        $x_20_5 = "checkip.dyndns.org" ascii //weight: 20
        $x_20_6 = "ALL YOUR FILES ARE ENCRYPTED" ascii //weight: 20
        $x_20_7 = "How To Decrypt My Files" ascii //weight: 20
        $x_20_8 = "i_am_a_dolphin" ascii //weight: 20
        $x_3_9 = "DisableTaskMgr" ascii //weight: 3
        $x_3_10 = "Decrypt files" ascii //weight: 3
        $x_3_11 = "DetectSandboxie" ascii //weight: 3
        $x_3_12 = ".dolphin" ascii //weight: 3
        $x_1_13 = "encrypt" ascii //weight: 1
        $x_1_14 = "Locked" ascii //weight: 1
        $x_1_15 = "DetectDebugger" ascii //weight: 1
        $x_1_16 = "ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_20_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DU_2147780813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DU!MTB"
        threat_id = "2147780813"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Crypto_TheOnlyOne" ascii //weight: 50
        $x_50_2 = "hidden-tear" ascii //weight: 50
        $x_20_3 = "SPLITTTT" ascii //weight: 20
        $x_20_4 = "hidden_tear.Properties" ascii //weight: 20
        $x_3_5 = "LOCKTHAT" ascii //weight: 3
        $x_3_6 = "Wrong Header Signature" ascii //weight: 3
        $x_1_7 = "BTC Address :" ascii //weight: 1
        $x_1_8 = "GetTempPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DW_2147781294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DW!MTB"
        threat_id = "2147781294"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = ".matryoshka" ascii //weight: 50
        $x_50_2 = ".Baphomet" ascii //weight: 50
        $x_50_3 = "hanta_2_0" ascii //weight: 50
        $x_20_4 = "NitroSnypa" ascii //weight: 20
        $x_20_5 = "bapho.jpg" ascii //weight: 20
        $x_20_6 = "hanta_ransom" ascii //weight: 20
        $x_3_7 = "Discord Nitro Sniper" ascii //weight: 3
        $x_3_8 = "yourkey.key" ascii //weight: 3
        $x_3_9 = "how_to_recover" ascii //weight: 3
        $x_1_10 = "btn_CopyWallet" ascii //weight: 1
        $x_1_11 = "ipinfo.io" ascii //weight: 1
        $x_1_12 = "start encryprion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_DY_2147781549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DY!MTB"
        threat_id = "2147781549"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files are encrypted" ascii //weight: 1
        $x_1_2 = "READ_ME.crypted.txt" ascii //weight: 1
        $x_1_3 = "@protonmail.com" ascii //weight: 1
        $x_1_4 = "No files to encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_DZ_2147781553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DZ!MTB"
        threat_id = "2147781553"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Unlock Your Files" ascii //weight: 1
        $x_1_2 = "_Encrypted$" ascii //weight: 1
        $x_1_3 = "VW5sb2NrWW91ckZpbGVzJQ" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "DecryptAllFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_RW_2147782859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.RW!MTB"
        threat_id = "2147782859"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" ascii //weight: 1
        $x_1_2 = "All of your files have been encrypted" ascii //weight: 1
        $x_1_3 = "recoveryenabled no" ascii //weight: 1
        $x_1_4 = "read_it.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_EA_2147784151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EA!MTB"
        threat_id = "2147784151"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = ".palestine" ascii //weight: 50
        $x_50_2 = "All of your files have been encrypted" ascii //weight: 50
        $x_50_3 = "Rasomware2.0" ascii //weight: 50
        $x_50_4 = "hidden-tear" ascii //weight: 50
        $x_20_5 = "erawosnar" ascii //weight: 20
        $x_20_6 = "read_it.txt" ascii //weight: 20
        $x_20_7 = "_Encrypted$" ascii //weight: 20
        $x_3_8 = "UrFile.TXT" ascii //weight: 3
        $x_3_9 = "EncyptedKey" ascii //weight: 3
        $x_3_10 = "S2FzcGVyc2t5JQ==" ascii //weight: 3
        $x_3_11 = "aGlkZGVuLXRlYXIl" ascii //weight: 3
        $x_1_12 = "lolipop" ascii //weight: 1
        $x_1_13 = "encryptedFileExtension" ascii //weight: 1
        $x_1_14 = "EncryptFile" ascii //weight: 1
        $x_1_15 = "JohnDoe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EB_2147784154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EB!MTB"
        threat_id = "2147784154"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {9a 0b 07 14 72 ?? ?? ?? 70 17 8d 03 00 00 01 13 ?? 11 ?? 16 72 ?? ?? ?? 70 a2 11 ?? 14 14 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 2c 02 2b 0b 07 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 ?? 17 d6 13 ?? 11 ?? 11 ?? 8e b7 32 b6}  //weight: 10, accuracy: Low
        $x_1_2 = ".army" ascii //weight: 1
        $x_1_3 = ".arsium" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EC_2147784155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EC!MTB"
        threat_id = "2147784155"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Your files (count: n) are encrypted" ascii //weight: 50
        $x_50_2 = "Rasomware2._0" ascii //weight: 50
        $x_20_3 = "friendly.cyber.criminal" ascii //weight: 20
        $x_20_4 = "project577" ascii //weight: 20
        $x_3_5 = "RECOVER__FILES" ascii //weight: 3
        $x_3_6 = "AES_Encrypt" ascii //weight: 3
        $x_1_7 = ".AES64" ascii //weight: 1
        $x_1_8 = "FreezeMouse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_ED_2147784680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.ED!MTB"
        threat_id = "2147784680"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Your computer has been infected" ascii //weight: 50
        $x_50_2 = "Jasmin_Encrypter" ascii //weight: 50
        $x_50_3 = "JanusLocker" ascii //weight: 50
        $x_50_4 = ".rsjon" ascii //weight: 50
        $x_20_5 = "@protonmail.com" ascii //weight: 20
        $x_20_6 = ".jasmin" ascii //weight: 20
        $x_3_7 = "vssadmin delete shadows /all /quiet" ascii //weight: 3
        $x_3_8 = "unlock your files" ascii //weight: 3
        $x_3_9 = "Your personal files are encrypted" ascii //weight: 3
        $x_3_10 = "proof of payment like shit" ascii //weight: 3
        $x_1_11 = "BTC TO THIS WALLET:" ascii //weight: 1
        $x_1_12 = "error ha bhaiya" ascii //weight: 1
        $x_1_13 = "EncryptedFilesList" ascii //weight: 1
        $x_1_14 = "READ_ME_PLZ.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EE_2147784681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EE!MTB"
        threat_id = "2147784681"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Aplicativo" ascii //weight: 50
        $x_50_2 = "All Of Your Files Are Decrypted" ascii //weight: 50
        $x_20_3 = "tmr_encrypt" ascii //weight: 20
        $x_20_4 = ".malki" ascii //weight: 20
        $x_3_5 = "bytesToBeEncrypted" ascii //weight: 3
        $x_3_6 = "Ransomware virus" ascii //weight: 3
        $x_1_7 = "DisableTaskMgr" ascii //weight: 1
        $x_1_8 = "LockScreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EF_2147784683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EF!MTB"
        threat_id = "2147784683"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "erawosnar" ascii //weight: 50
        $x_50_2 = "DeltaMMMMDCCXCIII_PROCESS" ascii //weight: 50
        $x_20_3 = ".sick" ascii //weight: 20
        $x_20_4 = "Go clean this shit fast" ascii //weight: 20
        $x_3_5 = "UrFile.TXT" ascii //weight: 3
        $x_3_6 = "Ur dumb af retarded 0iq kid" ascii //weight: 3
        $x_1_7 = "YourTxtMsg" ascii //weight: 1
        $x_1_8 = "warning.BackgroundImage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EG_2147785188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EG!MTB"
        threat_id = "2147785188"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "files encrypted securely" ascii //weight: 50
        $x_50_2 = "Chaos Ransomware" ascii //weight: 50
        $x_50_3 = "All Your Important Files Are Encrypted" ascii //weight: 50
        $x_20_4 = "Encrypted Files" ascii //weight: 20
        $x_20_5 = "bytesToBeDecrypted" ascii //weight: 20
        $x_20_6 = "How to Recover My Files" ascii //weight: 20
        $x_3_7 = ".firecrypt" ascii //weight: 3
        $x_3_8 = ".chaos" ascii //weight: 3
        $x_3_9 = ".DarkCry" ascii //weight: 3
        $x_1_10 = "@sigaint.org" ascii //weight: 1
        $x_1_11 = "AES_Decrypt" ascii //weight: 1
        $x_1_12 = "NoCry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EH_2147785189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EH!MTB"
        threat_id = "2147785189"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Your files have been encrypted" ascii //weight: 50
        $x_50_2 = "RansomwareWannaMad" ascii //weight: 50
        $x_50_3 = "Your files are encrypted" ascii //weight: 50
        $x_20_4 = "Nitro Ransomware" ascii //weight: 20
        $x_20_5 = "Files Decrypted" ascii //weight: 20
        $x_20_6 = "vssadmin delete shadows /all /quiet" ascii //weight: 20
        $x_3_7 = ".givemenitro" ascii //weight: 3
        $x_3_8 = "Wrong Key bahaha" ascii //weight: 3
        $x_3_9 = "BiggyLocker" ascii //weight: 3
        $x_1_10 = "NR_decrypt" ascii //weight: 1
        $x_1_11 = "Enter password" ascii //weight: 1
        $x_1_12 = "@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EI_2147786212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EI!MTB"
        threat_id = "2147786212"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Ransomware.exe" ascii //weight: 50
        $x_50_2 = "Stub.Properties.Resources" ascii //weight: 50
        $x_20_3 = "Hello im crypting your files right now" ascii //weight: 20
        $x_20_4 = "BlowfishManaged" ascii //weight: 20
        $x_20_5 = "VirtualBox detected" ascii //weight: 20
        $x_3_6 = ".DEDSEC" ascii //weight: 3
        $x_3_7 = ".deadsecure" ascii //weight: 3
        $x_3_8 = "WMIC BIOS GET SERIALNUMBER" ascii //weight: 3
        $x_1_9 = "AESEncrypt" ascii //weight: 1
        $x_1_10 = "Encrypt" ascii //weight: 1
        $x_1_11 = "GetRandomFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EJ_2147786437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EJ!MTB"
        threat_id = "2147786437"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "All of your files have been encrypted" ascii //weight: 50
        $x_50_2 = "Your personal files have been ecrypted" ascii //weight: 50
        $x_50_3 = "NoCry Discord" ascii //weight: 50
        $x_20_4 = "read_me for your files" ascii //weight: 20
        $x_20_5 = "hidden tear" ascii //weight: 20
        $x_20_6 = "Tm9Dcnkq" ascii //weight: 20
        $x_3_7 = "vssadmin delete shadows /all /quiet" ascii //weight: 3
        $x_3_8 = "Encrypt_Robot" ascii //weight: 3
        $x_3_9 = "NoCry.pdb" ascii //weight: 3
        $x_1_10 = "EncyptedKey" ascii //weight: 1
        $x_1_11 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_12 = "_Encrypted$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EK_2147787200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EK!MTB"
        threat_id = "2147787200"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "Your files (count: n) have been encrypted" ascii //weight: 50
        $x_50_2 = "LegionLocker4" ascii //weight: 50
        $x_50_3 = {4e 69 74 72 6f 52 61 6e 73 6f 6d 77 61 72 65 2e [0-5] 2e 72 65 73 6f 75 72 63 65 73}  //weight: 50, accuracy: Low
        $x_20_4 = ".FancyLeaks" ascii //weight: 20
        $x_20_5 = "bytesToBeEncrypted" ascii //weight: 20
        $x_20_6 = "Discord Nitro" ascii //weight: 20
        $x_3_7 = "FancyLocker" ascii //weight: 3
        $x_3_8 = "LegionLocker4._0" ascii //weight: 3
        $x_3_9 = "Discord Free Nitro" ascii //weight: 3
        $x_1_10 = "No files to encrypt" ascii //weight: 1
        $x_1_11 = "passwordBytes" ascii //weight: 1
        $x_1_12 = "ConfuserEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EL_2147787201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EL!MTB"
        threat_id = "2147787201"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "All your files have been encrypted" ascii //weight: 50
        $x_50_2 = "Existing encrypted files found" ascii //weight: 50
        $x_50_3 = "Files has been encrypted" ascii //weight: 50
        $x_50_4 = "All your important files are encrypted" ascii //weight: 50
        $x_20_5 = "protonmail.com" ascii //weight: 20
        $x_20_6 = "RansomMessage" ascii //weight: 20
        $x_20_7 = "IMPORTANT READ ME.html" ascii //weight: 20
        $x_20_8 = "LegionLocker" ascii //weight: 20
        $x_3_9 = "vssadmin delete shadows /all /quiet" ascii //weight: 3
        $x_3_10 = "mimikatz_trunk.zip" ascii //weight: 3
        $x_3_11 = "Send me 1000$ to this bitcoin address" ascii //weight: 3
        $x_3_12 = "vssadmin Delete Shadows /all /quiet" ascii //weight: 3
        $x_1_13 = "EncyptedKey" ascii //weight: 1
        $x_1_14 = ".encrypted" ascii //weight: 1
        $x_1_15 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_16 = ".Legion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_20_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EM_2147787598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EM!MTB"
        threat_id = "2147787598"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "What can I do to get my files back" ascii //weight: 50
        $x_50_2 = "You personal files are encrypted" ascii //weight: 50
        $x_50_3 = "Your important files videos, music, images, documents ... etc are encrypted with encryption" ascii //weight: 50
        $x_20_4 = "DECRYPTYOURFILES" ascii //weight: 20
        $x_20_5 = "@protonmail.com" ascii //weight: 20
        $x_20_6 = "bitcoin address" ascii //weight: 20
        $x_3_7 = "vssadmin delete shadows /all /quiet" ascii //weight: 3
        $x_3_8 = "DisableTaskMgr" ascii //weight: 3
        $x_3_9 = ".fucking" ascii //weight: 3
        $x_1_10 = "Bitcoin Address:" ascii //weight: 1
        $x_1_11 = "WnCry" ascii //weight: 1
        $x_1_12 = "ransom.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EN_2147787599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EN!MTB"
        threat_id = "2147787599"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "decryptor.exe" ascii //weight: 50
        $x_50_2 = "ALL YOUR DATA HAVE BEEN ENCRYPTED" ascii //weight: 50
        $x_20_3 = "AESDecrypt" ascii //weight: 20
        $x_20_4 = "EncryptedFiles" ascii //weight: 20
        $x_3_5 = "password4567890password456" ascii //weight: 3
        $x_3_6 = "vxLock" ascii //weight: 3
        $x_1_7 = "CipherText" ascii //weight: 1
        $x_1_8 = "RSA_Keys.pub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_PAC_2147787688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PAC!MTB"
        threat_id = "2147787688"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomwarePOC" ascii //weight: 1
        $x_1_2 = "All of your files have been encrypted." ascii //weight: 1
        $x_1_3 = "No files to FUCK." ascii //weight: 1
        $x_1_4 = "READ_THIS_TO_DECRYPT." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_EP_2147787698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EP!MTB"
        threat_id = "2147787698"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Y0ur fi|e$ have been encr#pt" ascii //weight: 1
        $x_1_2 = "RansomeWare.Form1.resources" ascii //weight: 1
        $x_1_3 = "GetDirectories" ascii //weight: 1
        $x_1_4 = "GetFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PAD_2147787775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PAD!MTB"
        threat_id = "2147787775"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Files have been encrypted" wide //weight: 1
        $x_1_2 = "netsh firewall delete allowedprogram \"" wide //weight: 1
        $x_1_3 = "cmd.exe /c ping 0 -n 2 & del \"" wide //weight: 1
        $x_1_4 = "bitcoin to this address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_EO_2147787832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EO!MTB"
        threat_id = "2147787832"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "rk-2.exe" ascii //weight: 50
        $x_50_2 = "WindowsFormsApp6" ascii //weight: 50
        $x_50_3 = "You personal files are encrypted" ascii //weight: 50
        $x_20_4 = "/C icacls %USERPROFILE%\\Documents\\* /grant Everyone:F /T /C /Q" ascii //weight: 20
        $x_20_5 = "Test\\READ_IT.txt" ascii //weight: 20
        $x_20_6 = "@protonmail.com" ascii //weight: 20
        $x_3_7 = "wearenotcobaltthanks" ascii //weight: 3
        $x_3_8 = ".encrypted" ascii //weight: 3
        $x_3_9 = "WnCryMode" ascii //weight: 3
        $x_1_10 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_11 = "encryptDirectory" ascii //weight: 1
        $x_1_12 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EQ_2147788264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EQ!MTB"
        threat_id = "2147788264"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "HACKERRANSOMWARE" ascii //weight: 50
        $x_50_2 = "Your important files videos, music, images, documents ... etc are encrypted with encryption" ascii //weight: 50
        $x_50_3 = "RansomDecry0r" ascii //weight: 50
        $x_50_4 = "YJSNPIL0cker" ascii //weight: 50
        $x_20_5 = "EncryptFile" ascii //weight: 20
        $x_20_6 = "Message.txt" ascii //weight: 20
        $x_20_7 = "bitcoin Help" ascii //weight: 20
        $x_20_8 = "Tor\\explorer.exe" ascii //weight: 20
        $x_3_9 = "vssadmin delete shadows /all /quiet" ascii //weight: 3
        $x_3_10 = "Send bitcoins to this address" ascii //weight: 3
        $x_3_11 = "RansomHOS" ascii //weight: 3
        $x_3_12 = "aaaabbbbaaaabbbbaaaabbbbaaaabbbb" ascii //weight: 3
        $x_1_13 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_14 = "ranso4.jpg" ascii //weight: 1
        $x_1_15 = "Heroes of the Storm" ascii //weight: 1
        $x_1_16 = ".onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_20_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_ER_2147788486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.ER!MTB"
        threat_id = "2147788486"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "All your files like pictures, databases, documents,aplications and other are encrypted" ascii //weight: 50
        $x_50_2 = "Your personal files are being deleted" ascii //weight: 50
        $x_20_3 = ".deltapaymentbitcoin" ascii //weight: 20
        $x_20_4 = "FileToEncrypt" ascii //weight: 20
        $x_3_5 = "Nopyfy_Ransomware" ascii //weight: 3
        $x_3_6 = "Jigsaw" ascii //weight: 3
        $x_1_7 = "You Are Hacked" ascii //weight: 1
        $x_1_8 = "Encryption Complete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_ES_2147789268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.ES!MTB"
        threat_id = "2147789268"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "erawosnar" ascii //weight: 50
        $x_50_2 = "Silver Encryptor" ascii //weight: 50
        $x_50_3 = "All of your music has been encrypted" ascii //weight: 50
        $x_20_4 = "killer@killercom" ascii //weight: 20
        $x_20_5 = "unlock your files.lnk" ascii //weight: 20
        $x_20_6 = "vssadmin delete shadows /all /quiet" ascii //weight: 20
        $x_3_7 = ".sick" ascii //weight: 3
        $x_3_8 = "LnNvdmlldA" ascii //weight: 3
        $x_3_9 = "what_happened_to_my_music.txt" ascii //weight: 3
        $x_1_10 = "Encryption Key" ascii //weight: 1
        $x_1_11 = "FileEncryption" ascii //weight: 1
        $x_1_12 = "EncryptedKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EU_2147793098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EU!MTB"
        threat_id = "2147793098"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unlock your files.lnk" ascii //weight: 1
        $x_1_2 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_3 = "files/alertmsg.zip" ascii //weight: 1
        $x_1_4 = "FileEncryption" ascii //weight: 1
        $x_1_5 = "ro@tb@la@u.@eu@:1@53" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_EV_2147793142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EV!MTB"
        threat_id = "2147793142"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "All your files have been encrypted" ascii //weight: 50
        $x_50_2 = "Your computer has been infected by a Ransomware" ascii //weight: 50
        $x_20_3 = "vssadmin delete shadows /all /quiet" ascii //weight: 20
        $x_3_4 = "@tutanota.com " ascii //weight: 3
        $x_3_5 = "recoveryscmyfiles" ascii //weight: 3
        $x_1_6 = "EncryptedKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EW_2147793344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EW!MTB"
        threat_id = "2147793344"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "ALL YOUR FILES HAS BEEN ENCRYPTED" ascii //weight: 50
        $x_50_2 = "All of your files have been encrypted" ascii //weight: 50
        $x_20_3 = "No files to encrypt" ascii //weight: 20
        $x_20_4 = "Bitcoin Address" ascii //weight: 20
        $x_3_5 = "___RECOVER__FILES__" ascii //weight: 3
        $x_3_6 = "vssadmin delete shadows /all /quiet" ascii //weight: 3
        $x_1_7 = "LOCK CRYPTOR" ascii //weight: 1
        $x_1_8 = "EncryptedKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_EX_2147793345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.EX!MTB"
        threat_id = "2147793345"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Windows\\Temp\\Magix.exe" ascii //weight: 1
        $x_1_2 = "video_pro_x.exe" ascii //weight: 1
        $x_1_3 = "ophos" ascii //weight: 1
        $x_1_4 = "kaspersky" ascii //weight: 1
        $x_1_5 = "norton" ascii //weight: 1
        $x_1_6 = "CrackGen" ascii //weight: 1
        $x_1_7 = "/_/_/_/_/_/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PAG_2147794519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PAG!MTB"
        threat_id = "2147794519"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomwarePOC.covidblo" ascii //weight: 1
        $x_1_2 = "All of your files have been encrypted." ascii //weight: 1
        $x_1_3 = ".porn.txt" ascii //weight: 1
        $x_1_4 = "friendly.cyber.criminal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PAI_2147795376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PAI!MTB"
        threat_id = "2147795376"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PUSSIE RANSOMWARE" ascii //weight: 1
        $x_1_2 = "Pussie Locker.pdb" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "Processhacker" wide //weight: 1
        $x_1_5 = "kill virus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PAL_2147798424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PAL!MTB"
        threat_id = "2147798424"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "surprise" ascii //weight: 1
        $x_1_2 = "biorain@protonmail.com" ascii //weight: 1
        $x_1_3 = "infected with a ransomware" ascii //weight: 1
        $x_1_4 = "ALL OF YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_PAM_2147808901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.PAM!MTB"
        threat_id = "2147808901"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Crazy" ascii //weight: 1
        $x_1_2 = "Warning.txt" wide //weight: 1
        $x_1_3 = "File is already encrypted." wide //weight: 1
        $x_1_4 = "All of your files have been encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_MA_2147809797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.MA!MTB"
        threat_id = "2147809797"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e74fef62-688b-4681-ba71-4a4deb08ca16" ascii //weight: 1
        $x_1_2 = "/DP_Decrypter.exe" wide //weight: 1
        $x_1_3 = "/ExtraKey.dp" wide //weight: 1
        $x_1_4 = "/t:winexe" wide //weight: 1
        $x_1_5 = "DECRYPT MY FILES" wide //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "admKeyTB" ascii //weight: 1
        $x_1_9 = "puthTB" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "get_DP_Keygen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_AA_2147895896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.AA!MTB"
        threat_id = "2147895896"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "SOFTWARE\\Malwarebytes\\Ekati\\" ascii //weight: 20
        $x_1_2 = "/c vssadmin.exe delete shadows" ascii //weight: 1
        $x_1_3 = ".encrypted" ascii //weight: 1
        $x_1_4 = "Encrypt Desktop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Cryptolocker_DX_2147899389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.DX!MTB"
        threat_id = "2147899389"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = ".sick" ascii //weight: 50
        $x_50_2 = "NewRanSmWare" ascii //weight: 50
        $x_20_3 = "erawosnar" ascii //weight: 20
        $x_20_4 = "RipForYou" ascii //weight: 20
        $x_3_5 = "ghostbin.com" ascii //weight: 3
        $x_3_6 = "password123" ascii //weight: 3
        $x_1_7 = "HELP.txt" ascii //weight: 1
        $x_1_8 = "DisableTaskMgr" ascii //weight: 1
        $x_1_9 = "ransom.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 2 of ($x_3_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Cryptolocker_AYA_2147922983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cryptolocker.AYA!MTB"
        threat_id = "2147922983"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Payload.LockForm.resources" ascii //weight: 2
        $x_1_2 = "Crypto Locker\\Payload\\obj\\Release\\Payload.pdb" ascii //weight: 1
        $x_1_3 = "KillAllProcesses" ascii //weight: 1
        $x_1_4 = "$644fc53e-14b9-4dad-9097-73637c4f7b4d" ascii //weight: 1
        $x_1_5 = "RemoveFromStartup.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

