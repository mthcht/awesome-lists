rule MonitoringTool_AndroidOS_Ratker_A_430427_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Ratker.A!MTB"
        threat_id = "430427"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Ratker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSDummyCompose" ascii //weight: 1
        $x_1_2 = "CallRecorderService" ascii //weight: 1
        $x_1_3 = "com/tracer/activity" ascii //weight: 1
        $x_1_4 = "SMSCommandService" ascii //weight: 1
        $x_1_5 = "RemoteCommandsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

