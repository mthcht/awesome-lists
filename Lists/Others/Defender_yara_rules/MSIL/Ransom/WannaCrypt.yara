rule Ransom_MSIL_WannaCrypt_DC_2147773126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaCrypt.DC!MTB"
        threat_id = "2147773126"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files have been encrypted" ascii //weight: 1
        $x_1_2 = "Encrypted Files" ascii //weight: 1
        $x_1_3 = "Cry.img" ascii //weight: 1
        $x_1_4 = "@toututa.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WannaCrypt_DD_2147775154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaCrypt.DD!MTB"
        threat_id = "2147775154"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All Your Files Are Encrypted" ascii //weight: 1
        $x_1_2 = "How To Decrypt My Files" ascii //weight: 1
        $x_1_3 = "Encrypted Files" ascii //weight: 1
        $x_1_4 = "NoCry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WannaCrypt_DE_2147775155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaCrypt.DE!MTB"
        threat_id = "2147775155"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WannaHappy" ascii //weight: 1
        $x_1_2 = "AES_Encrypt" ascii //weight: 1
        $x_1_3 = "fileEncrypted" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WannaCrypt_PA_2147792996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaCrypt.PA!MTB"
        threat_id = "2147792996"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".aes" wide //weight: 1
        $x_1_2 = "\\bg.png" wide //weight: 1
        $x_1_3 = "\\Readme.txt" wide //weight: 1
        $x_1_4 = "\\EncryptedKey.txt" wide //weight: 1
        $x_1_5 = "Your important files are encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WannaCrypt_PAC_2147796155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaCrypt.PAC!MTB"
        threat_id = "2147796155"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WannaCryptor" ascii //weight: 1
        $x_1_2 = "Wrong.Hahaha" ascii //weight: 1
        $x_1_3 = "File have been encrypted" ascii //weight: 1
        $x_1_4 = "disable your antivirus for a while" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WannaCrypt_PD_2147798525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaCrypt.PD!MTB"
        threat_id = "2147798525"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hello From Main...I Don't Do Anything" wide //weight: 1
        $x_1_2 = "Hello There From Uninstall" wide //weight: 1
        $x_1_3 = "I shouldn't really execute" wide //weight: 1
        $x_1_4 = "$0547ff40-5255-42a2-beb7-2ff0dbf7d3ba" ascii //weight: 1
        $x_1_5 = "\\AllTheThings.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_WannaCrypt_PE_2147807392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaCrypt.PE!MTB"
        threat_id = "2147807392"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WANNA CRY Padlock" wide //weight: 1
        $x_1_2 = "Wana_Decrypt_Or_2._0" wide //weight: 1
        $x_3_3 = "your files have been encrypted!" wide //weight: 3
        $x_1_4 = "\\WannaCry.pdb" ascii //weight: 1
        $x_1_5 = "\\Wana Decrypt Or 2.0.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_WannaCrypt_BA_2147958846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaCrypt.BA!MTB"
        threat_id = "2147958846"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Playground/ransomware" ascii //weight: 1
        $x_1_2 = "Desktop\\t.wncry" ascii //weight: 1
        $x_1_3 = "dialog wannacry.txt" ascii //weight: 1
        $x_1_4 = "Ooops, your files have been encrypted!" ascii //weight: 1
        $x_1_5 = "Your files will be lost on" ascii //weight: 1
        $x_1_6 = "How to buy bitcoin?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

