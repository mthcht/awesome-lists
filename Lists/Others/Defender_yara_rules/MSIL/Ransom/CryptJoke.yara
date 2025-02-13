rule Ransom_MSIL_CryptJoke_A_2147721824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptJoke.A!bit"
        threat_id = "2147721824"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptJoke"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\FileCrypterJoke\\obj\\Debug\\FileCrypterJoke.pdb" ascii //weight: 1
        $x_1_2 = "InitializeRandomXorKey" ascii //weight: 1
        $x_1_3 = "CryptAllFilesInFolder" ascii //weight: 1
        $x_1_4 = "*.crypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptJoke_B_2147723217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptJoke.B!bit"
        threat_id = "2147723217"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptJoke"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoJoker\\CryptoJokerGUI\\obj\\Debug\\CryptoJoker.pdb" ascii //weight: 1
        $x_1_2 = "Bitcoin Address" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "click me to decrypt your files" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

