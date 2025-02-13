rule MonitoringTool_AndroidOS_MobTool_B_305598_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobTool.B!MTB"
        threat_id = "305598"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobTool"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wipeData" ascii //weight: 1
        $x_1_2 = "sms_cmd_service_restarting" ascii //weight: 1
        $x_1_3 = "record_calls" ascii //weight: 1
        $x_1_4 = "track_geo" ascii //weight: 1
        $x_1_5 = "upload_history" ascii //weight: 1
        $x_1_6 = "out_sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

