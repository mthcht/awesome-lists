rule MonitoringTool_AndroidOS_Caivs_A_330056_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Caivs.A!MTB"
        threat_id = "330056"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Caivs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/android/caivs/app/CallLogsObserver" ascii //weight: 1
        $x_1_2 = "startSendSmsServer" ascii //weight: 1
        $x_1_3 = "registerSmsReceiver" ascii //weight: 1
        $x_1_4 = "delayRemoveSelf" ascii //weight: 1
        $x_1_5 = "getSendCount" ascii //weight: 1
        $x_1_6 = "wolftel_caivs/logs.data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

