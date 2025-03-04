rule MonitoringTool_AndroidOS_EasyLogger_C_340516_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/EasyLogger.C!MTB"
        threat_id = "340516"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "EasyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PhoneUsageReportActivity" ascii //weight: 2
        $x_2_2 = "ChildMapActivity" ascii //weight: 2
        $x_2_3 = "uninstallForceCloseReceiver" ascii //weight: 2
        $x_2_4 = "simChangeReceiver" ascii //weight: 2
        $x_2_5 = "loSimInfoloSimInfo" ascii //weight: 2
        $x_2_6 = "SendSOSAlertActivity" ascii //weight: 2
        $x_1_7 = "/easylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

