rule MonitoringTool_AndroidOS_Secneo_A_303915_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Secneo.A!MTB"
        threat_id = "303915"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Secneo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WxMonitorApplication" ascii //weight: 1
        $x_1_2 = "hd.fish.WxMonitor" ascii //weight: 1
        $x_1_3 = "com.secneo.tmp" ascii //weight: 1
        $x_1_4 = "SecShell" ascii //weight: 1
        $x_1_5 = "Lcom/secshell/secData/FilesFileObserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

