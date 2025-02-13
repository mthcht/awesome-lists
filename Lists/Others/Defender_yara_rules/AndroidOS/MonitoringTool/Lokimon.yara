rule MonitoringTool_AndroidOS_Lokimon_A_301082_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Lokimon.A!MTB"
        threat_id = "301082"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Lokimon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LokiActivity" ascii //weight: 1
        $x_1_2 = "hide_app_icon" ascii //weight: 1
        $x_1_3 = "charge_sms_send" ascii //weight: 1
        $x_1_4 = "com.mobile.loki" ascii //weight: 1
        $x_1_5 = "service_command_sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

