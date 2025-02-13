rule MonitoringTool_MSIL_FreeFacebookMonitoring_205063_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/FreeFacebookMonitoring"
        threat_id = "205063"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FreeFacebookMonitoring"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Free Facebook Monitoring" wide //weight: 1
        $x_1_2 = "Key logger Log file !" wide //weight: 1
        $x_1_3 = "Automatically email result log file" wide //weight: 1
        $x_1_4 = "To return from hidden mode press Ctrl+Alt+Shift" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

