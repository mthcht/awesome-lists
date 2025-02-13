rule MonitoringTool_AndroidOS_TalkLog_A_297273_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TalkLog.A!MTB"
        threat_id = "297273"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TalkLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Download/talklog.apk" ascii //weight: 1
        $x_1_2 = "tchsrvce.com" ascii //weight: 1
        $x_1_3 = "/ObserverService/ChromeObserverService" ascii //weight: 1
        $x_1_4 = "InComingSmsBroadReceiver" ascii //weight: 1
        $x_1_5 = "current_monitoring" ascii //weight: 1
        $x_1_6 = "hidden_icon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_TalkLog_B_332363_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TalkLog.B!MTB"
        threat_id = "332363"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TalkLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "current_monitoring" ascii //weight: 1
        $x_1_2 = "ttps://tchsrvce.com/con233.php" ascii //weight: 1
        $x_1_3 = "ObserverOutcomingSMS" ascii //weight: 1
        $x_1_4 = "post/hook.php" ascii //weight: 1
        $x_1_5 = "post/file.php" ascii //weight: 1
        $x_1_6 = "Talklog Tools" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_TalkLog_C_343878_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/TalkLog.C!MTB"
        threat_id = "343878"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "TalkLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "talklog.net" ascii //weight: 1
        $x_1_2 = "deleteOldApp" ascii //weight: 1
        $x_1_3 = "CollectBrowserService" ascii //weight: 1
        $x_1_4 = "CollectCallService" ascii //weight: 1
        $x_1_5 = "CollectMmsService" ascii //weight: 1
        $x_1_6 = "CollectPhotoService" ascii //weight: 1
        $x_1_7 = "CollectSmsService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

