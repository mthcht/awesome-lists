rule MonitoringTool_AndroidOS_Phonespy_B_325503_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Phonespy.B!MTB"
        threat_id = "325503"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Phonespy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "call_phone_list" ascii //weight: 1
        $x_1_2 = "force_internet" ascii //weight: 1
        $x_1_3 = "sms_phone_list" ascii //weight: 1
        $x_1_4 = "remote_wipe" ascii //weight: 1
        $x_1_5 = "stop_wifi" ascii //weight: 1
        $x_1_6 = "disable_root" ascii //weight: 1
        $x_1_7 = "lock_phone" ascii //weight: 1
        $x_1_8 = "getInstalledApplications" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

