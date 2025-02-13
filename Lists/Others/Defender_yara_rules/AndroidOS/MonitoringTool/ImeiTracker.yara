rule MonitoringTool_AndroidOS_ImeiTracker_A_357610_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/ImeiTracker.A!MTB"
        threat_id = "357610"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "ImeiTracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IMEI Tracker Receiver" ascii //weight: 1
        $x_1_2 = "destinationPhoneNumber" ascii //weight: 1
        $x_1_3 = "Lcom/lge/lgmits" ascii //weight: 1
        $x_1_4 = "LgmitsReceiver" ascii //weight: 1
        $x_1_5 = "onImeiTrackerStart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

