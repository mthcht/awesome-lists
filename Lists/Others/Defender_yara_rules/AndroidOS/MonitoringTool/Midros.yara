rule MonitoringTool_AndroidOS_Midros_A_332435_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Midros.A!MTB"
        threat_id = "332435"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Midros"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MonitorService" ascii //weight: 1
        $x_1_2 = "startAppChecker" ascii //weight: 1
        $x_1_3 = "smsService" ascii //weight: 1
        $x_1_4 = "getCapturePhoto" ascii //weight: 1
        $x_1_5 = "Lcom/my/spy/app/receiver/CallsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Midros_A_332435_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Midros.A!MTB"
        threat_id = "332435"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Midros"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keyLogger" ascii //weight: 1
        $x_1_2 = "/audioCalls" ascii //weight: 1
        $x_1_3 = "sendFileCall" ascii //weight: 1
        $x_1_4 = "InteractorSms" ascii //weight: 1
        $x_1_5 = "InteractorCalls" ascii //weight: 1
        $x_1_6 = "getShowOrHideApp" ascii //weight: 1
        $x_1_7 = "getLockPin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

