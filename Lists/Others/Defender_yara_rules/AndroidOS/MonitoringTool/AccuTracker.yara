rule MonitoringTool_AndroidOS_AccuTracker_A_325120_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/AccuTracker.A!MTB"
        threat_id = "325120"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "AccuTracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/accutracking/AccuTracking" ascii //weight: 2
        $x_1_2 = "TrackingBroadcastReceiver" ascii //weight: 1
        $x_1_3 = "Sending data" ascii //weight: 1
        $x_1_4 = "gateway.accutracking.us" ascii //weight: 1
        $x_1_5 = "bPwdProtected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

