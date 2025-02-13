rule TrojanSpy_AndroidOS_GoldDream_A_2147827627_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/GoldDream.A!MTB"
        threat_id = "2147827627"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "GoldDream"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PHONECALL_FILE_NAME" ascii //weight: 1
        $x_1_2 = "SMS_FILE_NAME" ascii //weight: 1
        $x_1_3 = "income_phoneNumber" ascii //weight: 1
        $x_1_4 = "IsWatchSms" ascii //weight: 1
        $x_1_5 = "uploadAllFiles" ascii //weight: 1
        $x_1_6 = "KEY_ZJ_UPLOADWATCHFILES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

