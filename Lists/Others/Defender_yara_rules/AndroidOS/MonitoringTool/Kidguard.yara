rule MonitoringTool_AndroidOS_Kidguard_A_346430_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Kidguard.A!MTB"
        threat_id = "346430"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Kidguard"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KidsAccessibilityService" ascii //weight: 1
        $x_1_2 = "start_monitoring_msg" ascii //weight: 1
        $x_1_3 = "text_sms_permission" ascii //weight: 1
        $x_1_4 = "getUser_login" ascii //weight: 1
        $x_1_5 = "handlerCallsLog" ascii //weight: 1
        $x_1_6 = "intercept_accessibility" ascii //weight: 1
        $x_1_7 = "ScreenShotActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule MonitoringTool_AndroidOS_Kidguard_B_365717_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Kidguard.B!MTB"
        threat_id = "365717"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Kidguard"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "text_location_and_sms_permission" ascii //weight: 1
        $x_1_2 = "permission_screen_capture_mess" ascii //weight: 1
        $x_1_3 = "com/kids/pro" ascii //weight: 1
        $x_1_4 = "KidsHttpLog" ascii //weight: 1
        $x_1_5 = "tip_not_permission_draw_overlays" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

