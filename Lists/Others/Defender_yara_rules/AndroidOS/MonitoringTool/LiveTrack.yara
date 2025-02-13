rule MonitoringTool_AndroidOS_LiveTrack_A_344605_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/LiveTrack.A!MTB"
        threat_id = "344605"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "LiveTrack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "installedappslog" ascii //weight: 1
        $x_1_2 = "backup_call_log" ascii //weight: 1
        $x_1_3 = "upload Browser Hist" ascii //weight: 1
        $x_1_4 = "is_upload_sms_log" ascii //weight: 1
        $x_1_5 = "upload Contacts" ascii //weight: 1
        $x_1_6 = "com.device.system" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

