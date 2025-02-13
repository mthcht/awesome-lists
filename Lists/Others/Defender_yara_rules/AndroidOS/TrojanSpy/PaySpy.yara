rule TrojanSpy_AndroidOS_PaySpy_A_2147818193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/PaySpy.A!MTB"
        threat_id = "2147818193"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "PaySpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "paynotice" ascii //weight: 1
        $x_1_2 = "CustomNotificationListenerService" ascii //weight: 1
        $x_1_3 = "LongRunningService" ascii //weight: 1
        $x_1_4 = "Lcom/tencent/mobileqq/SmsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

