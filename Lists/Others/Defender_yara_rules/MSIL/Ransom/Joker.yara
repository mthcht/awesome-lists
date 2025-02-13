rule Ransom_MSIL_Joker_DA_2147768062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Joker.DA!MTB"
        threat_id = "2147768062"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoJoker.exe" ascii //weight: 1
        $x_1_2 = "CryptoJoker.Properties" ascii //weight: 1
        $x_1_3 = "jokingwithyou.cryptojoker" ascii //weight: 1
        $x_1_4 = ".cryptojoker" ascii //weight: 1
        $x_1_5 = "JokerIsNotRunning" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Joker_DB_2147771536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Joker.DB!MTB"
        threat_id = "2147771536"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoJokerMessage" ascii //weight: 1
        $x_1_2 = "get_CryptoJoker" ascii //weight: 1
        $x_1_3 = "EncryptionKey" ascii //weight: 1
        $x_1_4 = "NoCryCryptor" ascii //weight: 1
        $x_1_5 = "CryptoJoker.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Joker_DC_2147789093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Joker.DC!MTB"
        threat_id = "2147789093"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoJokerDecryptor" ascii //weight: 1
        $x_1_2 = "@protonmail.com" ascii //weight: 1
        $x_1_3 = "Dark Matter Recovery Information.txt" ascii //weight: 1
        $x_1_4 = "jokingwithyou" ascii //weight: 1
        $x_1_5 = "Bitcoin Address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

