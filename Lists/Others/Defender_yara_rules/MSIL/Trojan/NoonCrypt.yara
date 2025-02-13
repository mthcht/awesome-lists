rule Trojan_MSIL_NoonCrypt_SK_2147756848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NoonCrypt.SK!MTB"
        threat_id = "2147756848"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NoonCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 02 00 00 06 72 ed 01 00 70 6f 30 00 00 0a 74 04 00 00 1b 28 02 00 00 06 72 fd 01 00 70 6f 30 00 00 0a 74 04 00 00 1b}  //weight: 2, accuracy: High
        $x_2_2 = {20 00 01 00 00 8d 39 00 00 01 80 cd 01 00 04 16 0b 38 4e 00 00 00 00 07 6a 0a 1e 0c 38 29 00 00 00 00 06 17 6a 5f 17 6a fe 01 0d 09 39 10 00 00 00 06 17 64 20 20 83 b8 ed 6e 61 0a 38 04 00 00 00 06 17 64 0a 00 08 17 59 0c 08 16 fe 02 13 04 11 04 3a ca ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

