rule MonitoringTool_AndroidOS_Anlost_A_301074_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Anlost.A!MTB"
        threat_id = "301074"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Anlost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getting Sms details" ascii //weight: 1
        $x_1_2 = "SMS_READ_COLUMN" ascii //weight: 1
        $x_1_3 = "lostapp" ascii //weight: 1
        $x_1_4 = "Wipe phone" ascii //weight: 1
        $x_1_5 = "SMS GPS initiated" ascii //weight: 1
        $x_1_6 = "androidlost wipe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Anlost_B_305593_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Anlost.B!MTB"
        threat_id = "305593"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Anlost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System app removal success!" ascii //weight: 1
        $x_1_2 = "androidlost" ascii //weight: 1
        $x_1_3 = "Let us hope you did not mess something up" ascii //weight: 1
        $x_1_4 = "backupsms" ascii //weight: 1
        $x_1_5 = "SMS erase SD card" ascii //weight: 1
        $x_1_6 = "Wipe phone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Anlost_C_407671_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Anlost.C!MTB"
        threat_id = "407671"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Anlost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sms gps initiated" ascii //weight: 1
        $x_1_2 = "com/androidlost/lostapp" ascii //weight: 1
        $x_1_3 = "wipedata" ascii //weight: 1
        $x_1_4 = "isadminactive" ascii //weight: 1
        $x_1_5 = "lockNow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

