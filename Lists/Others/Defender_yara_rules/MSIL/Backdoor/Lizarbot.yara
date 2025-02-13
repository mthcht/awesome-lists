rule Backdoor_MSIL_Lizarbot_A_2147688944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Lizarbot.A"
        threat_id = "2147688944"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lizarbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ddos (start|stop) type ip port delay <socketNumber>" wide //weight: 1
        $x_1_2 = ".dl directLink (true|false) <fileName>" wide //weight: 1
        $x_1_3 = ".steal (start|stop) type <keyword>" wide //weight: 1
        $x_1_4 = ".info <toSend>" wide //weight: 1
        $x_1_5 = ".visit (start|stop) directlink 0 <(true|false)>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

