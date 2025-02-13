rule MonitoringTool_AndroidOS_Itracker_A_407641_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Itracker.A!MTB"
        threat_id = "407641"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Itracker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iTracker" ascii //weight: 1
        $x_1_2 = "StartUpUpdater" ascii //weight: 1
        $x_1_3 = "br.com.hataba.itrackerfree2" ascii //weight: 1
        $x_1_4 = "ReceberSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

