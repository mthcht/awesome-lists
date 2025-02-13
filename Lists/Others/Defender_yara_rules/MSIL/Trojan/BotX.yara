rule Trojan_MSIL_BotX_RDQ_2147846098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BotX.RDQ!MTB"
        threat_id = "2147846098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BotX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 06 07 11 06 91 20 fa 00 00 00 61 d2 9c 11 06 17 58 13 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

