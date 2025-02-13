rule Ransom_MSIL_Heracles_YAA_2147917339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Heracles.YAA!MTB"
        threat_id = "2147917339"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 6f 15 00 00 0a 0b 38 2c 00 00 00 07 17 59 0b 06 07 17 58 6f 16 00 00 0a 0c 02 08 6f 17 00 00 0a 0d 02 08 02 07 6f 17 00 00 0a 6f 18 00 00 0a 02}  //weight: 1, accuracy: High
        $x_1_2 = "ColdCryptor" ascii //weight: 1
        $x_1_3 = "RandomNumberGenerator" ascii //weight: 1
        $x_1_4 = "EncryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

