rule MonitoringTool_AndroidOS_SmsWatcher_A_299066_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SmsWatcher.A!MTB"
        threat_id = "299066"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SmsWatcher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/rjblackbox/swl/SMSActivity" ascii //weight: 1
        $x_1_2 = "Sent by SMS Watcher Lite" ascii //weight: 1
        $x_1_3 = "getContactNameFromNumber" ascii //weight: 1
        $x_1_4 = "SmsDispatcher" ascii //weight: 1
        $x_1_5 = "SMS Guardian" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

