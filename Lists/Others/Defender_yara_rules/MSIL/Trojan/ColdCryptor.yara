rule Trojan_MSIL_ColdCryptor_A_2147956663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ColdCryptor.A!MTB"
        threat_id = "2147956663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ColdCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ColdCryptor" wide //weight: 1
        $x_1_2 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_3 = "EncryptFile" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

