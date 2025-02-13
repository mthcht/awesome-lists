rule MonitoringTool_AndroidOS_XoloSale_A_359780_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/XoloSale.A!MTB"
        threat_id = "359780"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "XoloSale"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mIsSimCard0Listenning" ascii //weight: 1
        $x_1_2 = "KEY_REGIST_MSG_SHOWING" ascii //weight: 1
        $x_1_3 = "TrackerAlarmService" ascii //weight: 1
        $x_1_4 = "SmsSendingClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

