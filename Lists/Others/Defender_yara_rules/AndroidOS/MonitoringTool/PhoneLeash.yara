rule MonitoringTool_AndroidOS_PhoneLeash_A_357163_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneLeash.A!MTB"
        threat_id = "357163"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneLeash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOGGER_ROOT" ascii //weight: 1
        $x_1_2 = "phoneleash.log" ascii //weight: 1
        $x_1_3 = "startMainPhoneLeashService" ascii //weight: 1
        $x_1_4 = "lastOutgoingSmsTime" ascii //weight: 1
        $x_1_5 = "com.gearandroid.phoneleashfree" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

