rule Ransom_MSIL_Xncrypt_2147721268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Xncrypt"
        threat_id = "2147721268"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xncrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your computer has been infected" ascii //weight: 1
        $x_1_2 = "password to encrypt all your files" ascii //weight: 1
        $x_1_3 = "Bitcoin Wallet" ascii //weight: 1
        $x_1_4 = "Attention" ascii //weight: 1
        $x_1_5 = "All Files Encrypted" ascii //weight: 1
        $x_1_6 = "Microsoft.VisualBasic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

