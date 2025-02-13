rule Ransom_MSIL_RUsom_DA_2147905030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RUsom.DA!MTB"
        threat_id = "2147905030"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RUsom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RU_Ransom" wide //weight: 1
        $x_1_2 = "encryptAllDirectory" ascii //weight: 1
        $x_1_3 = "getEncryptedAesKey" ascii //weight: 1
        $x_1_4 = "AES_Encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

