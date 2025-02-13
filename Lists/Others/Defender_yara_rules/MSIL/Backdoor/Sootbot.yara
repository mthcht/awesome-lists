rule Backdoor_MSIL_Sootbot_A_2147686234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Sootbot.A"
        threat_id = "2147686234"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sootbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DlExecute" ascii //weight: 1
        $x_1_2 = "tcpRandom" ascii //weight: 1
        $x_1_3 = "udpRandom" ascii //weight: 1
        $x_1_4 = "Slowloris" ascii //weight: 1
        $x_1_5 = "FLOOD_STOP" ascii //weight: 1
        $x_1_6 = {1f 1d 12 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Sootbot_A_2147686234_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Sootbot.A"
        threat_id = "2147686234"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sootbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DlExecute" ascii //weight: 1
        $x_1_2 = "tcpRandom" ascii //weight: 1
        $x_1_3 = "udpRandom" ascii //weight: 1
        $x_1_4 = "Slowloris" ascii //weight: 1
        $x_1_5 = "s00tb0t" wide //weight: 1
        $x_1_6 = "Flood started @@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Sootbot_B_2147686335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Sootbot.B"
        threat_id = "2147686335"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sootbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 1d 12 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_2 = {06 08 06 25 13 05 08 25 13 06 11 05 11 06 6f ?? ?? ?? ?? 07 d2 59 d2 25 13 07 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {0b 06 07 16 07 8e 69 16 6f ?? ?? ?? ?? 26 14 0b 7e ?? ?? ?? ?? 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

