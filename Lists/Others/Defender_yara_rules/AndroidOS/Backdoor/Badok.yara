rule Backdoor_AndroidOS_Badok_A_2147832911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Badok.A!MTB"
        threat_id = "2147832911"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Badok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NetwrokMonitor" ascii //weight: 1
        $x_1_2 = "Backdoor/phone_num_submit" ascii //weight: 1
        $x_1_3 = "/Backdoor/task_query" ascii //weight: 1
        $x_1_4 = "allNetworkInfo" ascii //weight: 1
        $x_1_5 = "SENT_SMS_ACTION" ascii //weight: 1
        $x_1_6 = "setComponentEnabledSetting" ascii //weight: 1
        $x_1_7 = "Send SMS report" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

