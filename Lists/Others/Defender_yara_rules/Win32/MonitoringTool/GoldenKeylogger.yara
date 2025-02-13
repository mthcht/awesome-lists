rule MonitoringTool_Win32_GoldenKeylogger_17666_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/GoldenKeylogger"
        threat_id = "17666"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GoldenKeylogger"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GOLDEN KEYLOGGER" ascii //weight: 10
        $x_1_2 = "- - Details - -" ascii //weight: 1
        $x_1_3 = "Password in window \"%s\"" ascii //weight: 1
        $x_1_4 = "http://spyarsenal.com/cgi-bin/reg.pl?p=GKL&key=%s&v=%s&email=%s" ascii //weight: 1
        $x_1_5 = {53 54 41 52 54 20 4c 4f 47 47 49 4e 47 00 53 54 4f 50 20 4c 4f 47 47 49 4e 47}  //weight: 1, accuracy: High
        $x_1_6 = "ALL ACTIVITIES ON THIS SYSTEM ARE MONITORED." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

