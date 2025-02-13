rule Trojan_MSIL_AgentT_OI_2147743089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgentT.OI!MTB"
        threat_id = "2147743089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 8e 69 1f 10 da 17 da 17 d6 8d 22 00 00 01 0a 02 1f 10 06 16 06 8e 69 28 27 00 00 0a 00 06 8e 69 17 da 0b}  //weight: 1, accuracy: High
        $x_1_2 = {16 0c 2b 18 00 06 08 8f 22 00 00 01 25 47 02 08 1f 10 5d 91 61 d2 52 00 08 17 d6 0c 08 07 fe 02 16 fe 01 0d 09 2d dd 06 13 04 2b 00 11 04 2a}  //weight: 1, accuracy: High
        $x_1_3 = {28 17 00 00 0a 09 6f 18 00 00 0a 13 04 11 04 6f 19 00 00 0a 13 05 11 05 14 14 6f 1a 00 00 0a 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

