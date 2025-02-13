rule MonitoringTool_AndroidOS_Lynep_A_333900_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Lynep.A!MTB"
        threat_id = "333900"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Lynep"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "track_phonumber" ascii //weight: 1
        $x_1_2 = "apps/appsdata.php" ascii //weight: 1
        $x_1_3 = "lastcheckal" ascii //weight: 1
        $x_1_4 = "needSendToTrackApp" ascii //weight: 1
        $x_1_5 = "trackappdata" ascii //weight: 1
        $x_1_6 = "send_device_data" ascii //weight: 1
        $x_1_7 = "/stats.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_Lynep_B_419330_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Lynep.B!MTB"
        threat_id = "419330"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Lynep"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "trackphone.mobi" ascii //weight: 1
        $x_1_2 = "getSMSHistory" ascii //weight: 1
        $x_1_3 = "track_phonumber" ascii //weight: 1
        $x_1_4 = "calls.db" ascii //weight: 1
        $x_1_5 = "trcak_call_duration" ascii //weight: 1
        $x_1_6 = "/smart_php/stats.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

