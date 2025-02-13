rule Trojan_MSIL_DLAgent_RDA_2147888809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DLAgent.RDA!MTB"
        threat_id = "2147888809"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DLAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 16 00 00 0a 25 07 6f 17 00 00 0a 6f 18 00 00 0a 26}  //weight: 2, accuracy: High
        $x_1_2 = "W32Time" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

