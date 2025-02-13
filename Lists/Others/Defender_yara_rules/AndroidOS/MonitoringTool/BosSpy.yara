rule MonitoringTool_AndroidOS_BosSpy_A_359866_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/BosSpy.A!MTB"
        threat_id = "359866"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "BosSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendDataOfSMSToWebsite" ascii //weight: 1
        $x_1_2 = "spyCallNumber" ascii //weight: 1
        $x_1_3 = "SpyooService" ascii //weight: 1
        $x_1_4 = "clipboardBypass" ascii //weight: 1
        $x_1_5 = "KeylogService" ascii //weight: 1
        $x_1_6 = "etMonitoringPhone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

