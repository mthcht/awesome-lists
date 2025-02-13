rule Ransom_MSIL_CryptJoker_PA_2147845129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptJoker.PA!MTB"
        threat_id = "2147845129"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptJoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoJoker.Properties" wide //weight: 1
        $x_1_2 = "JokerIsNotRunning" ascii //weight: 1
        $x_1_3 = "CryptJokerWalker90912" wide //weight: 1
        $x_1_4 = "\\CryptoJoker.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptJoker_ARA_2147891509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptJoker.ARA!MTB"
        threat_id = "2147891509"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptJoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 06 08 03 08 91 04 07 91 59 d2 9c 04 07 17 58 91 16 fe 01 0d 09 2c 04 16 0b 2b 04 07 17 58 0b 00 08 17 58 0c 08 03 8e 69 fe 04 13 04 11 04 2d cf}  //weight: 2, accuracy: High
        $x_6_2 = "CryptoJokerMessage" ascii //weight: 6
        $x_3_3 = "Ransomware" ascii //weight: 3
        $x_3_4 = "BitcoinAdress" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

