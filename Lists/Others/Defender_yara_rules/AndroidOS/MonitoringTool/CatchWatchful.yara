rule MonitoringTool_AndroidOS_CatchWatchful_C_418744_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/CatchWatchful.C!MTB"
        threat_id = "418744"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "CatchWatchful"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "swtchScreenCapture" ascii //weight: 5
        $x_5_2 = "wosc.play.Launcher" ascii //weight: 5
        $x_5_3 = "CatWatchful" ascii //weight: 5
        $x_1_4 = "swtchPlayStoreNotifications" ascii //weight: 1
        $x_1_5 = "lastKeyLogFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

