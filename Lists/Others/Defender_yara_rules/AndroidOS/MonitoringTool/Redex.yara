rule MonitoringTool_AndroidOS_Redex_A_408758_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Redex.A!MTB"
        threat_id = "408758"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Redex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HIDE_APP" ascii //weight: 1
        $x_1_2 = "IP_MONITORING" ascii //weight: 1
        $x_1_3 = "HiddenCam" ascii //weight: 1
        $x_1_4 = "HiddenSpyActivity" ascii //weight: 1
        $x_1_5 = "uploadDeviceInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

