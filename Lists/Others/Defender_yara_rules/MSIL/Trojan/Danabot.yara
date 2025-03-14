rule Trojan_MSIL_Danabot_A_2147935983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Danabot.A!MTB"
        threat_id = "2147935983"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Danabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 06 09 91 09 1f 25 5a 20 00 01 00 00 5d d2 61 d2 9c 08 09 8f 16 00 00 01 25 47 07 09 07 8e 69 5d 91 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

