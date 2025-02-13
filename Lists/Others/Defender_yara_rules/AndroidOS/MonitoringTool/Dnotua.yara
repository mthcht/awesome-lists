rule MonitoringTool_AndroidOS_Dnotua_B_361804_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Dnotua.B!MTB"
        threat_id = "361804"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Dnotua"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenChancedReceiver" ascii //weight: 1
        $x_1_2 = "com/spappm_mondow/alarm/ChildLocator" ascii //weight: 1
        $x_1_3 = "remote_wipe" ascii //weight: 1
        $x_1_4 = "TrackLocation" ascii //weight: 1
        $x_1_5 = "NotificationListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Dnotua_C_369004_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Dnotua.C!MTB"
        threat_id = "369004"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Dnotua"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "log_checker.txt" ascii //weight: 1
        $x_1_2 = "StartLogFile" ascii //weight: 1
        $x_1_3 = "Lcom/monitorchecker/MonitorChecker" ascii //weight: 1
        $x_1_4 = "CheckAnroidMonitor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

