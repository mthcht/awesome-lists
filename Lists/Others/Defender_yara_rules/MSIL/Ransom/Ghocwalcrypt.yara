rule Ransom_MSIL_Ghocwalcrypt_A_2147709115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ghocwalcrypt.A"
        threat_id = "2147709115"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ghocwalcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "READ_THIS_FILE.txt" wide //weight: 1
        $x_1_2 = "Files have been encrypted by " wide //weight: 1
        $x_1_3 = "Once we will receive the payment the decryption key will be issued to you and your files will be decrypted." wide //weight: 1
        $x_1_4 = "Android users must download the application called Bitcoin Wallet. iOS users must download the application called Copay" wide //weight: 1
        $x_1_5 = "You must than send the BitCoins bought to one of the following accounts." wide //weight: 1
        $x_1_6 = "GhostCrypt" wide //weight: 1
        $x_1_7 = ".CWall" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Ghocwalcrypt_B_2147709219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ghocwalcrypt.B"
        threat_id = "2147709219"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ghocwalcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_README.txt" wide //weight: 1
        $x_1_2 = "All of your files have been encrypted and sent to our secure server." wide //weight: 1
        $x_1_3 = "Upon payment you will receive your key and decrypter" wide //weight: 1
        $x_1_4 = "To recover your files please get in touch by email:" wide //weight: 1
        $x_1_5 = "KryptoLocked" wide //weight: 1
        $x_1_6 = ".krypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

