rule MonitoringTool_AndroidOS_Traca_B_356839_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Traca.B!MTB"
        threat_id = "356839"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Traca"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TrackingController" ascii //weight: 1
        $x_1_2 = "HideNotificationService" ascii //weight: 1
        $x_1_3 = "traccar.db" ascii //weight: 1
        $x_1_4 = "stopTrackingService" ascii //weight: 1
        $x_1_5 = "LocationListener" ascii //weight: 1
        $x_1_6 = "removeLauncherIcon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Traca_C_431367_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Traca.C!MTB"
        threat_id = "431367"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Traca"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "traccar.db" ascii //weight: 1
        $x_1_2 = "org.traccar.client" ascii //weight: 1
        $x_1_3 = "TrackingController" ascii //weight: 1
        $x_1_4 = "stopTrackingService" ascii //weight: 1
        $x_1_5 = "startTrackingService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

