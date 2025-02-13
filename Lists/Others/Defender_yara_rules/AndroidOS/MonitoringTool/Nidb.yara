rule MonitoringTool_AndroidOS_Nidb_B_331946_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Nidb.B!MTB"
        threat_id = "331946"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Nidb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setHideADevice" ascii //weight: 1
        $x_1_2 = "appspy.net/cp/server" ascii //weight: 1
        $x_1_3 = "ACallWatcher" ascii //weight: 1
        $x_1_4 = "getSMSHistory" ascii //weight: 1
        $x_1_5 = "ATrackerWatcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Nidb_D_333751_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Nidb.D!MTB"
        threat_id = "333751"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Nidb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendAllNewMessagesDataToServer" ascii //weight: 1
        $x_1_2 = "sendAllAppLogsDataToServer" ascii //weight: 1
        $x_1_3 = "isRecordingCall" ascii //weight: 1
        $x_1_4 = "checkAppChatInstalled" ascii //weight: 1
        $x_1_5 = "isCoreSpyServiceRunning" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Nidb_E_360473_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Nidb.E!MTB"
        threat_id = "360473"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Nidb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "guestspy" ascii //weight: 1
        $x_1_2 = "thetruthspy" ascii //weight: 1
        $x_1_3 = "/log_call.aspx" ascii //weight: 1
        $x_1_4 = "com/ispyoo/common/monitor" ascii //weight: 1
        $x_1_5 = "monitor-telephone-number" ascii //weight: 1
        $x_1_6 = "has_remote_command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

