rule MonitoringTool_AndroidOS_Folme_A_418745_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Folme.A!MTB"
        threat_id = "418745"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Folme"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/fmee/fmeeserv" ascii //weight: 1
        $x_1_2 = "/fmeeserv_stealth.apk" ascii //weight: 1
        $x_1_3 = "RouteMonitor" ascii //weight: 1
        $x_1_4 = "OutgoingCallReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

