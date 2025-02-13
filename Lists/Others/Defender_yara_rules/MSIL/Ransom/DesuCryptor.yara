rule Ransom_MSIL_DesuCryptor_DA_2147773124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/DesuCryptor.DA!MTB"
        threat_id = "2147773124"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DesuCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your system is not encrypted" ascii //weight: 1
        $x_1_2 = "decrypt" ascii //weight: 1
        $x_1_3 = "desu_cryptor" ascii //weight: 1
        $x_1_4 = ".desu" ascii //weight: 1
        $x_1_5 = "meme.jpeg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

