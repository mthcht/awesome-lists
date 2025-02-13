rule MonitoringTool_MSIL_SimpleKeylogger_205052_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/SimpleKeylogger"
        threat_id = "205052"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SimpleKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SimpleKeloggerWindows" ascii //weight: 1
        $x_1_2 = "Frm_SImpleLogger" ascii //weight: 1
        $x_1_3 = "NKL_reportViwer" ascii //weight: 1
        $x_1_4 = "Click To view KeyStroke Report" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_MSIL_SimpleKeylogger_205052_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/SimpleKeylogger"
        threat_id = "205052"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SimpleKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uninstall Simple Key Logger" wide //weight: 1
        $x_1_2 = "You will receive the log file to the above email address at:" wide //weight: 1
        $x_1_3 = "Hides this application.  Press CTRL + SHIFT + ALT + F10 to show the program again" wide //weight: 1
        $x_1_4 = "Enable screen capture on keyboard return" wide //weight: 1
        $x_1_5 = "Start logging all keyboard activities" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

