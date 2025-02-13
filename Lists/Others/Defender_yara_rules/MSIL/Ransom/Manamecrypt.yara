rule Ransom_MSIL_Manamecrypt_A_2147709116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Manamecrypt.A"
        threat_id = "2147709116"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Manamecrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Format menu above ^^^^ and click Word Wrap" wide //weight: 1
        $x_1_2 = "\\ransom.jpg" wide //weight: 1
        $x_1_3 = "\\Decrypter.exe" wide //weight: 1
        $x_1_4 = ".tax2015" wide //weight: 1
        $x_1_5 = ".locked" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Manamecrypt_A_2147709116_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Manamecrypt.A"
        threat_id = "2147709116"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Manamecrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted and are unuseable and inaccessable." wide //weight: 1
        $x_1_2 = "How to Pay Unlock Fee" wide //weight: 1
        $x_1_3 = "This software is the only way to get your files back!" wide //weight: 1
        $x_1_4 = "Your Computers Files have been Encrypted and Locked!" wide //weight: 1
        $x_1_5 = "select * from Win32_BaseBoard" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Manamecrypt_A_2147716919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Manamecrypt.A!!Manamecrypt.gen!A"
        threat_id = "2147716919"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Manamecrypt"
        severity = "Critical"
        info = "Manamecrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Format menu above ^^^^ and click Word Wrap" wide //weight: 1
        $x_1_2 = "\\ransom.jpg" wide //weight: 1
        $x_1_3 = "\\Decrypter.exe" wide //weight: 1
        $x_1_4 = ".tax2015" wide //weight: 1
        $x_1_5 = ".locked" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

