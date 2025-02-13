rule MonitoringTool_MSIL_TBKeylogger_205024_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/TBKeylogger"
        threat_id = "205024"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TBKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger_TheBestKeylogger" ascii //weight: 1
        $x_1_2 = "EnableKeystrokeLogging" ascii //weight: 1
        $x_1_3 = "TakeScreenshotonMouseClick" ascii //weight: 1
        $x_1_4 = "EmailSendKeystroke" ascii //weight: 1
        $x_1_5 = "FTPSendScreenshot" ascii //weight: 1
        $x_1_6 = "UsbSendFilewatcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_MSIL_TBKeylogger_205024_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/TBKeylogger"
        threat_id = "205024"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TBKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger_TheBestKeylogger" wide //weight: 1
        $x_1_2 = "This is invisible form." wide //weight: 1
        $x_1_3 = "This computer is currently being logged by The Best Keylogger." wide //weight: 1
        $x_1_4 = "Take screenshot when visiting a website" wide //weight: 1
        $x_1_5 = "Keylogger-SysDir" wide //weight: 1
        $x_1_6 = "Microsoft 2011" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

