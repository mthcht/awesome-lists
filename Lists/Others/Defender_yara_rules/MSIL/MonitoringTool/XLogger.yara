rule MonitoringTool_MSIL_XLogger_224380_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/XLogger"
        threat_id = "224380"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XLogger.Properties" ascii //weight: 1
        $x_1_2 = "ENABLE_KEYLOGGER" ascii //weight: 1
        $x_1_3 = "ENABLE_SCREENSHOT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

