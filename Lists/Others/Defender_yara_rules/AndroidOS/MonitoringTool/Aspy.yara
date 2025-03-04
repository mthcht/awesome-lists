rule MonitoringTool_AndroidOS_ASpy_A_327308_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/ASpy.A!MTB"
        threat_id = "327308"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "ASpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.as.urllogger" ascii //weight: 1
        $x_1_2 = "DataBase.DeleteAll" ascii //weight: 1
        $x_1_3 = "PowerOptClick" ascii //weight: 1
        $x_1_4 = "Lapk/urllogger/MainActivity" ascii //weight: 1
        $x_1_5 = "AutoDelete" ascii //weight: 1
        $x_1_6 = "GetLastRecord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_ASpy_B_328716_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/ASpy.B!MTB"
        threat_id = "328716"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "ASpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.as.screenrecorder" ascii //weight: 1
        $x_1_2 = "/system/bin/screencap -p" ascii //weight: 1
        $x_1_3 = "AutoDelete" ascii //weight: 1
        $x_1_4 = "RecordScreenRoot" ascii //weight: 1
        $x_1_5 = "HideNotificationClick" ascii //weight: 1
        $x_1_6 = "actacc" ascii //weight: 1
        $x_1_7 = "deletedall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

