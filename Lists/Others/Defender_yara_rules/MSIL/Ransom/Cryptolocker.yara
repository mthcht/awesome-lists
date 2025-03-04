rule Ransom_MSIL_CryptoLocker_DA_2147772878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DA!MTB"
        threat_id = "2147772878"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_2 = "Bitcoin" ascii //weight: 1
        $x_1_3 = ".encrypted" ascii //weight: 1
        $x_1_4 = "ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DA_2147772878_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DA!MTB"
        threat_id = "2147772878"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransomware.exe" ascii //weight: 1
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "desktop.ini" ascii //weight: 1
        $x_1_4 = "Password" ascii //weight: 1
        $x_1_5 = "123456" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DB_2147772880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DB!MTB"
        threat_id = "2147772880"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files (count: n) have been encrypted" ascii //weight: 1
        $x_1_2 = "friendly.cyber.criminal@gmail.com" ascii //weight: 1
        $x_1_3 = "RECOVER__FILES" ascii //weight: 1
        $x_1_4 = ".locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DB_2147772880_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DB!MTB"
        threat_id = "2147772880"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IEFMTCBZT1VSIEZJTEVTIEhBVkUgQkVFTiBFTkNSWVBURUQ" ascii //weight: 1
        $x_1_2 = "TmVlZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IEJpdGNvaW4" ascii //weight: 1
        $x_1_3 = "ZGVjcnlwdF9zYWRAcHJvdG9ubWFpbC5jb20" ascii //weight: 1
        $x_1_4 = "WU9VUiBQRVJTT05BTCBJREVOVElGSUNBVElPTjog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DC_2147772923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DC!MTB"
        threat_id = "2147772923"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XBundlerTlsHelper.pdb" ascii //weight: 1
        $x_1_2 = "Ghost.exe" ascii //weight: 1
        $x_1_3 = "Themida" ascii //weight: 1
        $x_1_4 = "showinstance" ascii //weight: 1
        $x_1_5 = "deactivate" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DC_2147772923_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DC!MTB"
        threat_id = "2147772923"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "erawosnar.exe" ascii //weight: 1
        $x_1_2 = "erawosnar.g.resources" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DD_2147773119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DD!MTB"
        threat_id = "2147773119"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableTaskMgr" ascii //weight: 1
        $x_1_2 = "Ransom" ascii //weight: 1
        $x_1_3 = "AES_Encrypt" ascii //weight: 1
        $x_1_4 = "EncryptionFile" ascii //weight: 1
        $x_1_5 = "DECRYPT FILES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DD_2147773119_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DD!MTB"
        threat_id = "2147773119"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All your important files are encrypted" ascii //weight: 2
        $x_2_2 = "Desktop\\readme.txt" ascii //weight: 2
        $x_2_3 = "BabaYaga" ascii //weight: 2
        $x_1_4 = ".locked" ascii //weight: 1
        $x_1_5 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_CryptoLocker_DE_2147773125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DE!MTB"
        threat_id = "2147773125"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoLocker" ascii //weight: 1
        $x_1_2 = "Encrypted" ascii //weight: 1
        $x_1_3 = ".locked" ascii //weight: 1
        $x_1_4 = "Files Decrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DE_2147773125_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DE!MTB"
        threat_id = "2147773125"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files (count: n) have been encrypted" ascii //weight: 1
        $x_1_2 = "RECOVER__FILES__.locked.txt" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" ascii //weight: 1
        $x_1_4 = "BitcoinAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DF_2147773186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DF!MTB"
        threat_id = "2147773186"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2._0.Properties" ascii //weight: 1
        $x_1_2 = "Alo Minegames ransomware" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DF_2147773186_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DF!MTB"
        threat_id = "2147773186"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Your files have been encryted" ascii //weight: 5
        $x_5_2 = "Ransom1.Properties.Resources" ascii //weight: 5
        $x_5_3 = "Povlsomware" ascii //weight: 5
        $x_1_4 = "ReadmeForDecryption" ascii //weight: 1
        $x_1_5 = "Pen_etr_ate_Fir_ewa_ll" ascii //weight: 1
        $x_1_6 = "encryptedFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_CryptoLocker_DG_2147773297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DG!MTB"
        threat_id = "2147773297"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_2 = "StartEncryptionProcess" ascii //weight: 1
        $x_1_3 = "NamasteUnlock" ascii //weight: 1
        $x_1_4 = "FileEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DG_2147773297_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DG!MTB"
        threat_id = "2147773297"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_40_1 = "DisableTaskMgr" ascii //weight: 40
        $x_10_2 = "DisableRegistryTools" ascii //weight: 10
        $x_10_3 = "Ransom - Backup" ascii //weight: 10
        $x_10_4 = "Adam Locker" ascii //weight: 10
        $x_5_5 = "DisableLockWorkstation" ascii //weight: 5
        $x_5_6 = "bytesToBeEncrypted" ascii //weight: 5
        $x_5_7 = "Encryption Complete" ascii //weight: 5
        $x_1_8 = "Legion.Properties.Resources" ascii //weight: 1
        $x_1_9 = "FridayProject" ascii //weight: 1
        $x_1_10 = "adm_64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_40_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_40_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_40_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_40_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_CryptoLocker_DH_2147773298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DH!MTB"
        threat_id = "2147773298"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_40_1 = "Povlsomware" ascii //weight: 40
        $x_40_2 = "Rasomware2._0" ascii //weight: 40
        $x_10_3 = "ToBase64String" ascii //weight: 10
        $x_10_4 = "_Encrypted$" ascii //weight: 10
        $x_5_5 = "PayM3" ascii //weight: 5
        $x_5_6 = "UmFzb213YXJlMi4wJA==" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_40_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_40_*) and 2 of ($x_10_*))) or
            ((2 of ($x_40_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_CryptoLocker_DH_2147773298_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DH!MTB"
        threat_id = "2147773298"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decryptor.exe" ascii //weight: 1
        $x_1_2 = "NamasteUnlock" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "DecodeWithMatchByte" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "ConfuserEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DI_2147775158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DI!MTB"
        threat_id = "2147775158"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your files will be encrypted" ascii //weight: 1
        $x_1_2 = "CryptoLocker" ascii //weight: 1
        $x_1_3 = "bictoins" ascii //weight: 1
        $x_1_4 = "/C vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DI_2147775158_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DI!MTB"
        threat_id = "2147775158"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_40_1 = ".Annabelle" ascii //weight: 40
        $x_40_2 = ".bagli" ascii //weight: 40
        $x_40_3 = ".LOCKED_BY_WAANNACRY" ascii //weight: 40
        $x_40_4 = "T255eExvY2tlci" ascii //weight: 40
        $x_5_5 = "Encryption Files" ascii //weight: 5
        $x_5_6 = "Bitcoin address:" ascii //weight: 5
        $x_5_7 = "ExtensionsToEncrypt" ascii //weight: 5
        $x_5_8 = "OnyxLocker" ascii //weight: 5
        $x_1_9 = "HACKED" ascii //weight: 1
        $x_1_10 = "ExcellToPdf" ascii //weight: 1
        $x_1_11 = "btc.blockr.io" ascii //weight: 1
        $x_1_12 = "_Encrypted$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_40_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_40_*) and 2 of ($x_5_*))) or
            ((2 of ($x_40_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_CryptoLocker_DJ_2147775308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DJ!MTB"
        threat_id = "2147775308"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "happyWallet" ascii //weight: 1
        $x_1_2 = "RSAEncrypt" ascii //weight: 1
        $x_1_3 = "get_Extension" ascii //weight: 1
        $x_1_4 = "BITCOIN_ADDRESS" ascii //weight: 1
        $x_1_5 = "fuck360" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoLocker_DJ_2147775308_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoLocker.DJ!MTB"
        threat_id = "2147775308"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "rainbowcrypter" ascii //weight: 20
        $x_20_2 = ".REYPTSON" ascii //weight: 20
        $x_10_3 = ".locked" ascii //weight: 10
        $x_10_4 = ".onion" ascii //weight: 10
        $x_5_5 = "EncryptFile" ascii //weight: 5
        $x_5_6 = "encryptedUsername" ascii //weight: 5
        $x_1_7 = "aesencrypted" ascii //weight: 1
        $x_1_8 = "Como_Recuperar_Tus_Ficheros.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

