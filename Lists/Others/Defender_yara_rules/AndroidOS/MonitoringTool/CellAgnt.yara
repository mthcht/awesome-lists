rule MonitoringTool_AndroidOS_CellAgnt_A_347620_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/CellAgnt.A!MTB"
        threat_id = "347620"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "CellAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallLogObserver" ascii //weight: 1
        $x_1_2 = "deleteCallLog" ascii //weight: 1
        $x_1_3 = "com.itheima.killall" ascii //weight: 1
        $x_1_4 = "ApplockObserver" ascii //weight: 1
        $x_1_5 = "LostFindActivity" ascii //weight: 1
        $x_1_6 = "killedTaskInfos" ascii //weight: 1
        $x_1_7 = "wipeData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

