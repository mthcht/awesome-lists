rule MonitoringTool_AndroidOS_WebWatcher_B_354606_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/WebWatcher.B!MTB"
        threat_id = "354606"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "WebWatcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppMonitoringSetupActivity" ascii //weight: 1
        $x_1_2 = "com.awti.slc" ascii //weight: 1
        $x_1_3 = "RecordedData" ascii //weight: 1
        $x_1_4 = "WebMonitoringSetupActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

