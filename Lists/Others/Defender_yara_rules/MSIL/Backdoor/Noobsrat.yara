rule Backdoor_MSIL_Noobsrat_A_2147686117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noobsrat.A"
        threat_id = "2147686117"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noobsrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TCP Stresser Enabled..." wide //weight: 1
        $x_1_2 = "Slowloris Stresser Enabled..." wide //weight: 1
        $x_1_3 = "INF|Anti-Virus|" wide //weight: 1
        $x_1_4 = "LIVELOG|" wide //weight: 1
        $x_1_5 = "FIM|FILE|" wide //weight: 1
        $x_1_6 = "Killing Bots..." wide //weight: 1
        $x_1_7 = "Initiating RusKill..." wide //weight: 1
        $x_1_8 = "Remote Webcam..." wide //weight: 1
        $x_1_9 = "Sending Logs..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

