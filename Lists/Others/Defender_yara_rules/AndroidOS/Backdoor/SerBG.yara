rule Backdoor_AndroidOS_SerBG_A_2147783794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/SerBG.A!MTB"
        threat_id = "2147783794"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "SerBG"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PrivilegedSmsReceiver" ascii //weight: 1
        $x_1_2 = "block the sms" ascii //weight: 1
        $x_1_3 = "reply the sms with num" ascii //weight: 1
        $x_1_4 = "FakeLanucherActivity" ascii //weight: 1
        $x_1_5 = "savePhoneInfo" ascii //weight: 1
        $x_1_6 = "one round sms send receiver" ascii //weight: 1
        $x_1_7 = "sms_block_time" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

