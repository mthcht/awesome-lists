rule MonitoringTool_AndroidOS_ManaMon_A_331738_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/ManaMon.A!MTB"
        threat_id = "331738"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "ManaMon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsInfo" ascii //weight: 1
        $x_1_2 = "MSG_OUTBOXCONTENT" ascii //weight: 1
        $x_1_3 = "UPLOAD_SERVER" ascii //weight: 1
        $x_1_4 = "callRecordInfo" ascii //weight: 1
        $x_1_5 = "uploadRecoder" ascii //weight: 1
        $x_1_6 = "manageri_call_send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

