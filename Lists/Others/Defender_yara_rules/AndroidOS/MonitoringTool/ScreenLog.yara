rule MonitoringTool_AndroidOS_ScreenLog_A_416183_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/ScreenLog.A!MTB"
        threat_id = "416183"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "ScreenLog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/wultra/app" ascii //weight: 1
        $x_1_2 = "RecordingObservable" ascii //weight: 1
        $x_1_3 = "storeLogEntry" ascii //weight: 1
        $x_1_4 = "screenlogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

