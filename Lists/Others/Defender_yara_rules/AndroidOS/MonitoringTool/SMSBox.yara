rule MonitoringTool_AndroidOS_SMSBox_A_309276_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SMSBox.A!MTB"
        threat_id = "309276"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SMSBox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsBoxActivity" ascii //weight: 1
        $x_1_2 = "smartgpsworld.com/SmsBox" ascii //weight: 1
        $x_1_3 = "SMS_AUTOSTART" ascii //weight: 1
        $x_1_4 = "sms and calls history saved on the web" ascii //weight: 1
        $x_1_5 = "sendCallInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

