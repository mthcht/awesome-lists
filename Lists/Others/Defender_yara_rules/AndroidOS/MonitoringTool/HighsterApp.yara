rule MonitoringTool_AndroidOS_HighsterApp_A_334546_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/HighsterApp.A!MTB"
        threat_id = "334546"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "HighsterApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "evt17.com/iphone/new_android_services" ascii //weight: 1
        $x_1_2 = "highster" ascii //weight: 1
        $x_1_3 = "patSpy22.db" ascii //weight: 1
        $x_1_4 = "Lorg/secure/smsgps/HighsterApp" ascii //weight: 1
        $x_1_5 = "Lorg/sufficientlysecure/rootcommands" ascii //weight: 1
        $x_1_6 = "getLatestCalls" ascii //weight: 1
        $x_1_7 = "getLatestSms" ascii //weight: 1
        $x_1_8 = "getWhatsappEarliestMsgId" ascii //weight: 1
        $x_1_9 = "doInBackground" ascii //weight: 1
        $x_1_10 = "Lorg/secure/smsgps/task/daily" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

