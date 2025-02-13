rule MonitoringTool_AndroidOS_HelloSpy_A_299527_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/HelloSpy.A!MTB"
        threat_id = "299527"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "HelloSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HelloSpy" ascii //weight: 1
        $x_1_2 = "flushdbd.maxxspy.com" ascii //weight: 1
        $x_1_3 = "RemoteAccessCmd" ascii //weight: 1
        $x_1_4 = "RecordCallService" ascii //weight: 1
        $x_1_5 = "SendDataManagerForWhatsapp" ascii //weight: 1
        $x_1_6 = "ContentObserverForSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_HelloSpy_B_329161_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/HelloSpy.B!MTB"
        threat_id = "329161"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "HelloSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpyToApp" ascii //weight: 1
        $x_1_2 = "CATCH PHOTO LOG" ascii //weight: 1
        $x_1_3 = "FORCE START CORESPYSERVICE" ascii //weight: 1
        $x_1_4 = "SendDataManagerForWhatsapp" ascii //weight: 1
        $x_1_5 = "/syncdata/UpdatePhoneInfo/" ascii //weight: 1
        $x_1_6 = "ContentObserverForSms" ascii //weight: 1
        $x_1_7 = "observerAppLog" ascii //weight: 1
        $x_1_8 = "SMS_OUTGOING_LOG" ascii //weight: 1
        $x_1_9 = "RecordCallService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

