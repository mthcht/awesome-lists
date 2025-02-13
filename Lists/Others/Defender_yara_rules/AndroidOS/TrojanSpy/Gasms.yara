rule TrojanSpy_AndroidOS_Gasms_A_2147783555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Gasms.A!MTB"
        threat_id = "2147783555"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Gasms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/gambler/SendSMS/SMSMonitor" ascii //weight: 1
        $x_1_2 = "SMSMonitorNum" ascii //weight: 1
        $x_1_3 = "SMSMonitorEmail" ascii //weight: 1
        $x_1_4 = "incomingNumber ==" ascii //weight: 1
        $x_1_5 = "SMSMonitorCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

