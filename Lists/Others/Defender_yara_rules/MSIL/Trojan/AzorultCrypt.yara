rule Trojan_MSIL_AzorultCrypt_SK_2147756491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AzorultCrypt.SK!MTB"
        threat_id = "2147756491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AzorultCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {02 6f 7b 00 00 0a 0a 16 0b 38 43 00 00 00 06 07 9a 0c 00 08 6f 7c 00 00 0a 72 c6 19 00 70 28 7d 00 00 0a 0d 09 39 22 00 00 00 00 08 72 c6 19 00 70 20 00 01 00 00 14 14 14 6f 7e 00 00 0a 26 00 28 7f 00 00 0a 6f 80 00 00 0a 00 00 00 07 17 58 0b 07 06 8e 69 3f b4 ff ff ff 2a}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

