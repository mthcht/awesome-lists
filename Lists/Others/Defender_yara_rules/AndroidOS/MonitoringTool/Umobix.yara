rule MonitoringTool_AndroidOS_Umobix_A_332166_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Umobix.A!MTB"
        threat_id = "332166"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Umobix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppActivityMonitor" ascii //weight: 1
        $x_1_2 = "KeyloggerScanner" ascii //weight: 1
        $x_1_3 = "screen_reader" ascii //weight: 1
        $x_1_4 = "AppBlockerActivity" ascii //weight: 1
        $x_1_5 = "browser_history" ascii //weight: 1
        $x_1_6 = "ENABLE_DISPLAY_RECORDER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

