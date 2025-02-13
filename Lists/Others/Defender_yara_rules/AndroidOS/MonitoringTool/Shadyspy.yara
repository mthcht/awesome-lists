rule MonitoringTool_AndroidOS_Shadyspy_A_423285_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Shadyspy.A!MTB"
        threat_id = "423285"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Shadyspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.shadyspy.monitor" ascii //weight: 5
        $x_1_2 = "CALL_INCOMING_LOST" ascii //weight: 1
        $x_1_3 = "hideDetails" ascii //weight: 1
        $x_1_4 = "ACTIVITYSHADYSPY" ascii //weight: 1
        $x_1_5 = "notif_phonelog" ascii //weight: 1
        $x_1_6 = "shady_notifications" ascii //weight: 1
        $x_1_7 = "shady_download_channel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

