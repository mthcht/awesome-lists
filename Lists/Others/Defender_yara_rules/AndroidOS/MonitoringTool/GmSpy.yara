rule MonitoringTool_AndroidOS_GmSpy_B_331737_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/GmSpy.B!MTB"
        threat_id = "331737"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "GmSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpyCameraService" ascii //weight: 1
        $x_1_2 = "downloadMonitorService" ascii //weight: 1
        $x_1_3 = "stopWatching" ascii //weight: 1
        $x_1_4 = "apppicker" ascii //weight: 1
        $x_1_5 = "ScreenRecorderService" ascii //weight: 1
        $x_1_6 = "DataUploadReceiver" ascii //weight: 1
        $x_1_7 = "videoCapturer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

