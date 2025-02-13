rule MonitoringTool_AndroidOS_MobiSafe_A_406900_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobiSafe.A!MTB"
        threat_id = "406900"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobiSafe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallSmsSafeActivity" ascii //weight: 1
        $x_1_2 = "lv_callsms_safe" ascii //weight: 1
        $x_1_3 = "ll_add_number_tips" ascii //weight: 1
        $x_1_4 = "CallLogObserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

