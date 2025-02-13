rule Trojan_MSIL_Kugbot_A_2147650389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kugbot.A"
        threat_id = "2147650389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kugbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sniff_hit" wide //weight: 1
        $x_1_2 = "AGBot.app.manifest" ascii //weight: 1
        $x_1_3 = "action=USB Drive explorer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

