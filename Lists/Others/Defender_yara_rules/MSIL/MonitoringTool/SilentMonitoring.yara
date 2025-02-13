rule MonitoringTool_MSIL_SilentMonitoring_205061_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/SilentMonitoring"
        threat_id = "205061"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SilentMonitoring"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CGetImagesSurveillanceMethod" ascii //weight: 1
        $x_1_2 = "CKeyLoggerSurveillanceMethod" ascii //weight: 1
        $x_1_3 = "CWebsitesLoggerMethod" ascii //weight: 1
        $x_1_4 = "silentmonitoring.com" wide //weight: 1
        $x_1_5 = "shomer.co.il" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

