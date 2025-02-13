rule MonitoringTool_AndroidOS_DroidWatcher_DS_304708_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/DroidWatcher.DS!MTB"
        threat_id = "304708"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "DroidWatcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "times_contacted" ascii //weight: 1
        $x_1_2 = "last_contact_time" ascii //weight: 1
        $x_1_3 = "/sdcard/spyier/Logs/" ascii //weight: 1
        $x_1_4 = "startWatching......" ascii //weight: 1
        $x_1_5 = "uploadMobileInfo" ascii //weight: 1
        $x_1_6 = "FileMonitor has already started!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_DroidWatcher_B_367658_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/DroidWatcher.B!MTB"
        threat_id = "367658"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "DroidWatcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/delemento/services" ascii //weight: 1
        $x_1_2 = "clipboard-history.txt" ascii //weight: 1
        $x_1_3 = "sendCallLog" ascii //weight: 1
        $x_1_4 = "sendSmsLog" ascii //weight: 1
        $x_1_5 = "copyBrowserToDWDB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_DroidWatcher_C_428356_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/DroidWatcher.C!MTB"
        threat_id = "428356"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "DroidWatcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/telegrus/ServerMessanger" ascii //weight: 1
        $x_1_2 = "startRecordCALL" ascii //weight: 1
        $x_1_3 = "copySMSToDWDB" ascii //weight: 1
        $x_1_4 = "getBrowserHistory" ascii //weight: 1
        $x_1_5 = "addCliboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_DroidWatcher_D_434443_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/DroidWatcher.D!MTB"
        threat_id = "434443"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "DroidWatcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/watchmydroid/receivers" ascii //weight: 1
        $x_1_2 = "Kate_messages.db" ascii //weight: 1
        $x_1_3 = "OutgoingCallReceiver" ascii //weight: 1
        $x_1_4 = "RECORD_CALLS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_DroidWatcher_F_444327_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/DroidWatcher.F!MTB"
        threat_id = "444327"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "DroidWatcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DeleteCallLog" ascii //weight: 1
        $x_1_2 = "HiddenCam" ascii //weight: 1
        $x_1_3 = "startRecordCALL" ascii //weight: 1
        $x_1_4 = "getBrowserHistory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

