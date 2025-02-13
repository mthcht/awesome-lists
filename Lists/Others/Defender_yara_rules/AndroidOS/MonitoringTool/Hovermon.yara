rule MonitoringTool_AndroidOS_Hovermon_A_301083_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Hovermon.A!MTB"
        threat_id = "301083"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Hovermon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSSCREENSHOTS" ascii //weight: 1
        $x_1_2 = "MonitorHInstall.apk" ascii //weight: 1
        $x_1_3 = "api.snoopza.com" ascii //weight: 1
        $x_1_4 = "monitored_logs" ascii //weight: 1
        $x_1_5 = "WEBSCREENSHOTS" ascii //weight: 1
        $x_1_6 = "hide_launcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Hovermon_B_332607_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Hovermon.B!MTB"
        threat_id = "332607"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Hovermon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MIPKOMONITOR" ascii //weight: 1
        $x_1_2 = "Monitoring enabled" ascii //weight: 1
        $x_1_3 = "a.hws.icu" ascii //weight: 1
        $x_1_4 = "CHATREC" ascii //weight: 1
        $x_1_5 = "SMSSCREENSHOTS" ascii //weight: 1
        $x_1_6 = "WEBSCREENSHOTS" ascii //weight: 1
        $x_1_7 = "hide_launcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

