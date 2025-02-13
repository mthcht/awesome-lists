rule Trojan_MSIL_CryptolockerV2_A_2147849923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptolockerV2.A!MTB"
        threat_id = "2147849923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptolockerV2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Cryptolocker 2.0" wide //weight: 2
        $x_2_2 = "unique public key RSA-4096" wide //weight: 2
        $x_2_3 = "Encrypted files" wide //weight: 2
        $x_2_4 = "Validate payment" wide //weight: 2
        $x_2_5 = "Payment for private key" wide //weight: 2
        $x_2_6 = "Decrypt files" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

