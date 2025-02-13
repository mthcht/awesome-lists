rule MonitoringTool_AndroidOS_MIPKO_A_343877_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MIPKO.A!MTB"
        threat_id = "343877"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MIPKO"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MIPKO MONITOR" ascii //weight: 1
        $x_1_2 = "EnableMonitor" ascii //weight: 1
        $x_1_3 = "EnableContacts" ascii //weight: 1
        $x_1_4 = "EnableChats" ascii //weight: 1
        $x_1_5 = "EnableSMS" ascii //weight: 1
        $x_1_6 = "HIDE_PASSWORD" ascii //weight: 1
        $x_1_7 = "RcOtgCll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

