rule MonitoringTool_AndroidOS_Easylogger_B_303898_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Easylogger.B!MTB"
        threat_id = "303898"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Easylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "app/EasyLogger" ascii //weight: 2
        $x_1_2 = "http://logger.mobi" ascii //weight: 1
        $x_1_3 = "HideApp" ascii //weight: 1
        $x_1_4 = "InsertLogHistoryManager" ascii //weight: 1
        $x_1_5 = "CallLog" ascii //weight: 1
        $x_1_6 = "EasyLoggerLog.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

