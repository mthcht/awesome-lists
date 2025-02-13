rule Trojan_MSIL_AgentTeslaFEM_2147920255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgentTeslaFEM!MTB"
        threat_id = "2147920255"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTeslaFEM"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 11 06 6f 33 00 00 0a 13 07 08 12 07 28 34 00 00 0a 6f 35 00 00 0a 00 08 12 07 28 36 00 00 0a 6f 35 00 00 0a 00 08 12 07 28 37 00 00 0a 6f 35 00 00 0a 00 07 08 20 00 1c 01 00 28 0f 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

