rule Trojan_MSIL_AgenslaCrypt_SK_2147756422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgenslaCrypt.SK!MTB"
        threat_id = "2147756422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgenslaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 28 25 02 00 06 20 b3 0f 46 8c 28 03 00 00 2b 7e b5 00 00 04 28 2d 02 00 06 0a 06 74 58 00 00 01 0b 2b 00 07 2a}  //weight: 2, accuracy: High
        $x_2_2 = {00 28 25 02 00 06 20 18 84 09 58 28 01 00 00 2b 7e b5 00 00 04 28 2d 02 00 06 0a 06 74 0d 00 00 1b 0b 2b 00 07 2a}  //weight: 2, accuracy: High
        $x_1_3 = {02 28 28 02 00 06 20 55 09 6e 7d 28 04 00 00 2b 28 d5 01 00 06 0a 06 28 d7 01 00 06 0b 07 28 d8 01 00 06 17 9a 0c 08 20 88 ab 77 82 28 04 00 00 2b 20 00 01 00 00 14 14 18 8d 02 00 00 01 25 16 7e ac 00 00 04 a2 25 17 20 0d c0 5b d6 28 01 00 00 2b a2 28 d9 01 00 06 26 16 28 da 01 00 06 00 16 0d 2b 00 09 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

