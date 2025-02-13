rule MonitoringTool_AndroidOS_NickyRCP_A_303154_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/NickyRCP.A!MTB"
        threat_id = "303154"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "NickyRCP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "remote-control-phone" ascii //weight: 1
        $x_1_2 = "sendSMSWait" ascii //weight: 1
        $x_1_3 = "getLastKnownLocation" ascii //weight: 1
        $x_1_4 = "fakeCallerRequest" ascii //weight: 1
        $x_1_5 = "smsmatcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

