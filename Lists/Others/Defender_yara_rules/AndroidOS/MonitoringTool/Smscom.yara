rule MonitoringTool_AndroidOS_Smscom_A_313894_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Smscom.A!MTB"
        threat_id = "313894"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Smscom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateFromSmsMessage" ascii //weight: 1
        $x_1_2 = "setSmsServiceListener" ascii //weight: 1
        $x_1_3 = "getAllUsedPhones" ascii //weight: 1
        $x_1_4 = "SMSReceiverService" ascii //weight: 1
        $x_1_5 = "saveUserData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

