rule Backdoor_MSIL_Sisbot_A_2147683229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Sisbot.A"
        threat_id = "2147683229"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sisbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!ddos" wide //weight: 1
        $x_1_2 = "!stopddos" wide //weight: 1
        $x_1_3 = "!irc" wide //weight: 1
        $x_1_4 = "!stopirc" wide //weight: 1
        $x_1_5 = "!mirc" wide //weight: 1
        $x_1_6 = "Shit_IRC_Storm" wide //weight: 1
        $x_1_7 = "!youtube" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

