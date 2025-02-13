rule MonitoringTool_AndroidOS_Publ_A_418742_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Publ.A!MTB"
        threat_id = "418742"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Publ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.pbl.settingsservice" ascii //weight: 1
        $x_1_2 = "setting_activity_tracking" ascii //weight: 1
        $x_1_3 = "setting_gps_tracking" ascii //weight: 1
        $x_1_4 = "setting_sms_recorder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

