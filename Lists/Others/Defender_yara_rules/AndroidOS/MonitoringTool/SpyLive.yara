rule MonitoringTool_AndroidOS_SpyLive_B_336209_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyLive.B!MTB"
        threat_id = "336209"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyLive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/mobile/upload/remotephoto" ascii //weight: 1
        $x_1_2 = "keylogger" ascii //weight: 1
        $x_1_3 = "HideApp" ascii //weight: 1
        $x_1_4 = "Lcom/wifi0/activities" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

