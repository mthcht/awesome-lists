rule MonitoringTool_MSIL_RedEyesKeylogger_205067_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/RedEyesKeylogger"
        threat_id = "205067"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedEyesKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Red Eyes Keylogger" wide //weight: 1
        $x_1_2 = "Upload log to FTP server:" wide //weight: 1
        $x_1_3 = "Run on Windows startup:" wide //weight: 1
        $x_1_4 = "Hide process" wide //weight: 1
        $x_1_5 = "/Picture/prtscr.bmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

