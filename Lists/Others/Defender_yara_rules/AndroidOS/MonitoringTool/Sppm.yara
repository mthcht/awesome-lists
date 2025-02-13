rule MonitoringTool_AndroidOS_Sppm_A_339921_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Sppm.A!MTB"
        threat_id = "339921"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Sppm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SppmWatchReceiver" ascii //weight: 1
        $x_1_2 = "AllowInstallingUnknownAppsActivity" ascii //weight: 1
        $x_1_3 = "isAppMonitoring" ascii //weight: 1
        $x_5_4 = "jp.co.axseed.sppm_setup" ascii //weight: 5
        $x_1_5 = "sppmcallctrl" ascii //weight: 1
        $x_1_6 = "WIPECALLNO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

