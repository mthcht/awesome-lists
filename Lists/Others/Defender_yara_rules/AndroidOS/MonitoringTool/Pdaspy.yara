rule MonitoringTool_AndroidOS_Pdaspy_A_298508_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Pdaspy.A!MTB"
        threat_id = "298508"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Pdaspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Application turn invisible spy mode right now" ascii //weight: 1
        $x_1_2 = "pdaspy" ascii //weight: 1
        $x_1_3 = "callLogging" ascii //weight: 1
        $x_1_4 = "readMsgInbox" ascii //weight: 1
        $x_1_5 = "spyLog" ascii //weight: 1
        $x_1_6 = "CallSMS Monitor method" ascii //weight: 1
        $x_1_7 = "startSMSMonitoring" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

