rule MonitoringTool_AndroidOS_Remosm_A_305596_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Remosm.A!MTB"
        threat_id = "305596"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Remosm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sms_lock" ascii //weight: 1
        $x_1_2 = "Lcom/grrzzz/remotesmsfull/RemoteSMS" ascii //weight: 1
        $x_1_3 = "/cache/contacts.dat" ascii //weight: 1
        $x_1_4 = "sms_thread_delete.htm" ascii //weight: 1
        $x_1_5 = "sms_max" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

