rule Trojan_AndroidOS_FakePlayer_A_2147756822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakePlayer.A!MTB"
        threat_id = "2147756822"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakePlayer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app_queue_message_list" ascii //weight: 1
        $x_1_2 = "dwap.db" ascii //weight: 1
        $x_1_3 = "sendQueueSMS" ascii //weight: 1
        $x_1_4 = "app_queue_index" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

