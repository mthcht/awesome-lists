rule MonitoringTool_AndroidOS_Spyc_A_314209_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spyc.A!MTB"
        threat_id = "314209"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chk_outgoing_sms" ascii //weight: 1
        $x_1_2 = "getLocationLogFromDatabase" ascii //weight: 1
        $x_1_3 = "CALLS_FDURATION" ascii //weight: 1
        $x_1_4 = "CHK_INCOMING_CALL" ascii //weight: 1
        $x_1_5 = "Lcom/bluumi/spycontrol" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

