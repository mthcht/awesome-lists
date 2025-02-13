rule MonitoringTool_AndroidOS_Trackme_A_301077_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Trackme.A!MTB"
        threat_id = "301077"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Trackme"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.tracking_smartphon" ascii //weight: 1
        $x_1_2 = "trackingsmartphone.com" ascii //weight: 1
        $x_1_3 = "CellTracker" ascii //weight: 1
        $x_1_4 = "executesmscommands" ascii //weight: 1
        $x_1_5 = "callandsmslogs" ascii //weight: 1
        $x_1_6 = "urlhistory" ascii //weight: 1
        $x_1_7 = "wipeout" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

