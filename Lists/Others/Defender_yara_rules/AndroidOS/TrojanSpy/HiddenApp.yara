rule TrojanSpy_AndroidOS_HiddenApp_A_2147786799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/HiddenApp.A!MTB"
        threat_id = "2147786799"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "HiddenApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "activity_keypress" ascii //weight: 1
        $x_1_2 = "timercalls" ascii //weight: 1
        $x_1_3 = "SIM.Toolkits" ascii //weight: 1
        $x_1_4 = "FindByMail" ascii //weight: 1
        $x_1_5 = "bot token.txt" ascii //weight: 1
        $x_1_6 = "SmsInterceptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

