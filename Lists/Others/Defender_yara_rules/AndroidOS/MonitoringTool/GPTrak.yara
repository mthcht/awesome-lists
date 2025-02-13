rule MonitoringTool_AndroidOS_GPTrak_A_346020_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/GPTrak.A!MTB"
        threat_id = "346020"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "GPTrak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "org.traccar.client" ascii //weight: 1
        $x_1_2 = "startUpdates" ascii //weight: 1
        $x_1_3 = "removeLauncherIcon" ascii //weight: 1
        $x_1_4 = "startTrackingService" ascii //weight: 1
        $x_1_5 = "processLocation" ascii //weight: 1
        $x_1_6 = "HideNotificationService" ascii //weight: 1
        $x_1_7 = "TrackingController" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

