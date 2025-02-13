rule MonitoringTool_AndroidOS_Toreoc_A_301162_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Toreoc.A!MTB"
        threat_id = "301162"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Toreoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S2CallRec_dont_show" ascii //weight: 1
        $x_1_2 = "Fix call recording" ascii //weight: 1
        $x_1_3 = "phone_picker_apply_for_outgoing" ascii //weight: 1
        $x_1_4 = "Record saved to" ascii //weight: 1
        $x_1_5 = "PersistenceManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Toreoc_B_330437_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Toreoc.B!MTB"
        threat_id = "330437"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Toreoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hidenotification" ascii //weight: 1
        $x_1_2 = "phone_picker_apply_for_outgoing" ascii //weight: 1
        $x_1_3 = "CALL_LOG" ascii //weight: 1
        $x_1_4 = "allowRecordViaSms" ascii //weight: 1
        $x_1_5 = "hideRecordingStrategy" ascii //weight: 1
        $x_1_6 = "recordAfterCallStart" ascii //weight: 1
        $x_1_7 = "S2CallRec_dont_show" ascii //weight: 1
        $x_1_8 = "ttps://www.killermobilesoftware.com/for/devices/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

