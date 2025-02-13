rule Trojan_MSIL_InjectLK_DA_2147740498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectLK.DA!MTB"
        threat_id = "2147740498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectLK"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 08 1f 0c 63 08 61 20 ff 0f 00 00 5f 13 04 20 00 10 00 00 8d 0d 00 00 01 11 04 91 13 05 16 13 0d 38 29 ff ff ff 16 13 06 16 13 07 16 13 08 16 16 73 0c 00 00 0a 13 09 18 13 0d 38 0f ff ff ff 11 09 74 02 00 00 1b 11 04 11 08 28 0d 00 00 0a 13 0a 08 d2 06 74 01}  //weight: 1, accuracy: High
        $x_1_2 = {02 06 8f 0d 00 00 01 25 47 03 06 03 8e 69 5d 91 61 d2 52 1b 0c 2b b4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

