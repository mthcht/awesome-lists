rule MonitoringTool_AndroidOS_SpyHide_A_346064_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyHide.A!MTB"
        threat_id = "346064"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyHide"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cellphone-remote-tracker" ascii //weight: 1
        $x_1_2 = "com.l2celltracker.mobiletracker" ascii //weight: 1
        $x_1_3 = "sendPhoto" ascii //weight: 1
        $x_1_4 = "uploadAmbient" ascii //weight: 1
        $x_1_5 = "sendRecordCallNew" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

