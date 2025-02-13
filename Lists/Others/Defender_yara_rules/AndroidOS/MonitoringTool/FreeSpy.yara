rule MonitoringTool_AndroidOS_FreeSpy_DS_302687_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/FreeSpy.DS!MTB"
        threat_id = "302687"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "FreeSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BrowserHistoryCollector" ascii //weight: 1
        $x_1_2 = "KeylogStateMonitor" ascii //weight: 1
        $x_1_3 = "ContactObserver" ascii //weight: 1
        $x_1_4 = "CallMonitor" ascii //weight: 1
        $x_1_5 = "SmsMonitor" ascii //weight: 1
        $x_1_6 = "FacebookMessageExtractor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

