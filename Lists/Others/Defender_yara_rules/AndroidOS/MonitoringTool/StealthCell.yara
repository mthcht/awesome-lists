rule MonitoringTool_AndroidOS_StealthCell_A_331728_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/StealthCell.A!MTB"
        threat_id = "331728"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "StealthCell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getCallSummaryAndUpdateView" ascii //weight: 1
        $x_1_2 = "smsobserver" ascii //weight: 1
        $x_1_3 = "wipedata" ascii //weight: 1
        $x_5_4 = "mobistealth" ascii //weight: 5
        $x_1_5 = "CALLS_Data" ascii //weight: 1
        $x_1_6 = "hideapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

