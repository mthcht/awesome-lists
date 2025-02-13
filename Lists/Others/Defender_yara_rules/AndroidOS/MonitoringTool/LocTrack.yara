rule MonitoringTool_AndroidOS_LocTrack_A_357606_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/LocTrack.A!MTB"
        threat_id = "357606"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "LocTrack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Lcom/av/rrgdfgdg/finder" ascii //weight: 10
        $x_1_2 = "LocationListener" ascii //weight: 1
        $x_1_3 = "hideOnContentScroll" ascii //weight: 1
        $x_1_4 = "onTaskRemoved" ascii //weight: 1
        $x_1_5 = "Lcom/av/david/finder/Send_to" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

