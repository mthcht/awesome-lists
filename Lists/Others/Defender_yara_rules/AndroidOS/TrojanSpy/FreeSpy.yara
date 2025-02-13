rule TrojanSpy_AndroidOS_FreeSpy_A_2147758390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FreeSpy.A!MTB"
        threat_id = "2147758390"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FreeSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "freeandroidspy.com" ascii //weight: 1
        $x_1_2 = "module_keylog_state_change" ascii //weight: 1
        $x_1_3 = "play_protect_status" ascii //weight: 1
        $x_1_4 = "TelegramMessageMonitor" ascii //weight: 1
        $x_1_5 = "SmsMonitor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

