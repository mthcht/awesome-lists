rule MonitoringTool_AndroidOS_MobileTracker_DS_304033_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobileTracker.DS!MTB"
        threat_id = "304033"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobileTracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "trackSMS" ascii //weight: 1
        $x_1_2 = "screencaptureEnabled" ascii //weight: 1
        $x_1_3 = "site/insertSiteHistory.php" ascii //weight: 1
        $x_1_4 = "remoteControl/setLog.php" ascii //weight: 1
        $x_1_5 = "configRecordCalls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MobileTracker_B_324039_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobileTracker.B!MTB"
        threat_id = "324039"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobileTracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsAlertKeyword.db" ascii //weight: 1
        $x_1_2 = "ScreenshootActivity" ascii //weight: 1
        $x_1_3 = "trackSocialNetwork" ascii //weight: 1
        $x_1_4 = "mms/insertMMSV2.php" ascii //weight: 1
        $x_1_5 = "recordCallsV3/insertCallRecord" ascii //weight: 1
        $x_1_6 = "GetMessageWhatsApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MobileTracker_B_324039_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobileTracker.B!MTB"
        threat_id = "324039"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobileTracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/vionika/mobivement/ui/childmanagement/phoneoptions" ascii //weight: 1
        $x_1_2 = "chmod %d %s" ascii //weight: 1
        $x_1_3 = "mobivementAgentUpgrade.apk" ascii //weight: 1
        $x_1_4 = "NotificationListenerService" ascii //weight: 1
        $x_1_5 = "isAdminActive" ascii //weight: 1
        $x_1_6 = "resetPassword" ascii //weight: 1
        $x_1_7 = "lockNow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MobileTracker_DT_456978_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobileTracker.DT!MTB"
        threat_id = "456978"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobileTracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "trackSnapchatNoRoot" ascii //weight: 1
        $x_1_2 = "trackYoutubeHistory" ascii //weight: 1
        $x_1_3 = "trackLocGPS" ascii //weight: 1
        $x_1_4 = "myappmobile2019" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

