rule MonitoringTool_AndroidOS_Spyzie_DS_311706_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spyzie.DS!MTB"
        threat_id = "311706"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spyzie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploadmonitorbrowser" ascii //weight: 1
        $x_1_2 = "uploadVideo: start" ascii //weight: 1
        $x_1_3 = "sp_wifi_logger" ascii //weight: 1
        $x_1_4 = "spyphone_data" ascii //weight: 1
        $x_1_5 = "zipUploadDb start upload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Spyzie_A_359869_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spyzie.A!MTB"
        threat_id = "359869"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spyzie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "last_backup_time" ascii //weight: 1
        $x_1_2 = "ttps://my.spyzie.com/app/spyzie.json" ascii //weight: 1
        $x_1_3 = "SpyziePicture/" ascii //weight: 1
        $x_1_4 = "Spyzie_Start" ascii //weight: 1
        $x_1_5 = "lastMonitorDevice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

