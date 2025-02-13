rule MonitoringTool_AndroidOS_Onespy_A_300149_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Onespy.A!MTB"
        threat_id = "300149"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Onespy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PhoneCallSpyListener" ascii //weight: 1
        $x_1_2 = "Add content observer for incoming sms" ascii //weight: 1
        $x_1_3 = "PULLREQUEST_skypelog" ascii //weight: 1
        $x_1_4 = "sendAllChatMessages" ascii //weight: 1
        $x_1_5 = "sendTwitterHistory" ascii //weight: 1
        $x_1_6 = "too early to send gmail db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

