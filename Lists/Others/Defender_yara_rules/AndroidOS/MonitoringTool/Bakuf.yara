rule MonitoringTool_AndroidOS_Bakuf_A_336208_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Bakuf.A!MTB"
        threat_id = "336208"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Bakuf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LogEmailMessage" ascii //weight: 1
        $x_1_2 = "OutgoingCallReceiver" ascii //weight: 1
        $x_1_3 = "LogBrowserurl" ascii //weight: 1
        $x_1_4 = "LogSms" ascii //weight: 1
        $x_1_5 = "CLEANTRACKWHENSCREENOFF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

