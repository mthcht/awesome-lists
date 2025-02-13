rule MonitoringTool_AndroidOS_Ikeymon_B_328192_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Ikeymon.B!MTB"
        threat_id = "328192"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Ikeymon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallHistory_Delete.txt" ascii //weight: 1
        $x_1_2 = "OutgoingCallObserver" ascii //weight: 1
        $x_1_3 = "CallAudioRecord" ascii //weight: 1
        $x_1_4 = "GetAllVoiceInfo_facebook" ascii //weight: 1
        $x_1_5 = "ChromeLogging" ascii //weight: 1
        $x_1_6 = "Begin_Screenshot" ascii //weight: 1
        $x_1_7 = "Chrome_WebHistr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule MonitoringTool_AndroidOS_Ikeymon_C_345573_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Ikeymon.C!MTB"
        threat_id = "345573"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Ikeymon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keyLoggerlogs" ascii //weight: 1
        $x_1_2 = "callhistory" ascii //weight: 1
        $x_1_3 = "Prefs_AppBlockerActivity" ascii //weight: 1
        $x_1_4 = "CallingRecord_Service" ascii //weight: 1
        $x_1_5 = "/data/com.as.monitoringapp" ascii //weight: 1
        $x_1_6 = "bk_readLogs.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Ikeymon_D_358339_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Ikeymon.D!MTB"
        threat_id = "358339"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Ikeymon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LIMIT_SCREEN_SHOTS" ascii //weight: 1
        $x_1_2 = "CommanMethod" ascii //weight: 1
        $x_1_3 = "sendAllCallHistory" ascii //weight: 1
        $x_1_4 = "getIsWebLogs" ascii //weight: 1
        $x_1_5 = "getIsSMSLog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

