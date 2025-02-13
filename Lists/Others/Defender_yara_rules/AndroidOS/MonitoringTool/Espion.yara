rule MonitoringTool_AndroidOS_Espion_A_419331_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Espion.A!MTB"
        threat_id = "419331"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Espion"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenCaptureService" ascii //weight: 1
        $x_1_2 = "com.espion.mosquito" ascii //weight: 1
        $x_1_3 = "take_video" ascii //weight: 1
        $x_1_4 = "info@espion.link" ascii //weight: 1
        $x_1_5 = "wsServerList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

