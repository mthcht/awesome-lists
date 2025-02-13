rule MonitoringTool_AndroidOS_AnMon_A_350794_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/AnMon.A!MTB"
        threat_id = "350794"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "AnMon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ANDROID_MONITOR_CHECKER" ascii //weight: 1
        $x_1_2 = "screen_capture_request" ascii //weight: 1
        $x_1_3 = "dowload_monitorchecker" ascii //weight: 1
        $x_1_4 = "KeyLoggerApps" ascii //weight: 1
        $x_1_5 = "rec_screen_cam_whatch" ascii //weight: 1
        $x_1_6 = "send_data_to_server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

