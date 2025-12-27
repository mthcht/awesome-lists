rule Trojan_MSIL_Flooder_GPA_2147947036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Flooder.GPA!MTB"
        threat_id = "2147947036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Flooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "slowloris" ascii //weight: 1
        $x_1_2 = "httpflood" ascii //weight: 1
        $x_1_3 = "udpflood" ascii //weight: 1
        $x_1_4 = "dnsamp" ascii //weight: 1
        $x_1_5 = "Opened pornhub on victim PC" ascii //weight: 1
        $x_1_6 = "!webcam" ascii //weight: 1
        $x_1_7 = "!ddos" ascii //weight: 1
        $x_1_8 = "disabling Windows Defender" ascii //weight: 1
        $x_1_9 = "running rat as administrator" ascii //weight: 1
        $x_2_10 = "!killdefender" ascii //weight: 2
        $x_2_11 = "keyloggerstart" ascii //weight: 2
        $x_2_12 = "screenshot.png" ascii //weight: 2
        $x_2_13 = "Discord.WebSocket" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

