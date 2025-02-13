rule MonitoringTool_AndroidOS_Speceb_A_340521_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Speceb.A!MTB"
        threat_id = "340521"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Speceb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/spectorsoft/android/monitor" ascii //weight: 1
        $x_1_2 = "MonitorControlledTask" ascii //weight: 1
        $x_1_3 = "LogcatMonitor" ascii //weight: 1
        $x_1_4 = "PhonecallObserver" ascii //weight: 1
        $x_1_5 = "UserSmsCapture" ascii //weight: 1
        $x_1_6 = "UrlObserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

