rule Ransom_MSIL_Fantom_MAZ_2147966978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Fantom.MAZ!MTB"
        threat_id = "2147966978"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fantom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Attention ! All your files" ascii //weight: 2
        $x_2_2 = "Due encrypting was used algoritm RSA-4096 and AES-256, used for protection military secrets" ascii //weight: 2
        $x_2_3 = "RESTORE YOU DATA POSIBLE ONLY BUYING decryption passwords" ascii //weight: 2
        $x_1_4 = "destroy you data permanetly" ascii //weight: 1
        $x_1_5 = "We Cant hold you decryption passwords forever" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

