rule Ransom_MSIL_Jigsaw_A_2147771727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Jigsaw.A!MSR"
        threat_id = "2147771727"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jigsaw"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HAHA THIS IS NOT DECRYPTION PSWD" wide //weight: 1
        $x_1_2 = "ITS FOR DUMBASS LIKE PEAPLE ON VM" wide //weight: 1
        $x_1_3 = "All your files have been highly encrypted!" wide //weight: 1
        $x_1_4 = "\\DeleteItself.bat" wide //weight: 1
        $x_1_5 = "EncryptedFileList.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Jigsaw_AJY_2147771841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Jigsaw.AJY!MSR"
        threat_id = "2147771841"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jigsaw"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BitcoinBlackmailer\\BitcoinBlackmailer\\bin\\Release\\BitcoinBlackmailer.pdb" ascii //weight: 1
        $x_1_2 = "BitcoinBlackmailer.exe" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "Qml0Y29pbkJsYWNrbWFpbGVyJQ==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

