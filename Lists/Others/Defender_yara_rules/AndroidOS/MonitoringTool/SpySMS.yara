rule MonitoringTool_AndroidOS_SpySMS_A_353933_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpySMS.A!MTB"
        threat_id = "353933"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpySMS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "contactsRead" ascii //weight: 1
        $x_1_2 = "net.softbrain.smsdivertor" ascii //weight: 1
        $x_1_3 = "smsSend" ascii //weight: 1
        $x_1_4 = "content://sms/conversations/" ascii //weight: 1
        $x_1_5 = "DivertorReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

