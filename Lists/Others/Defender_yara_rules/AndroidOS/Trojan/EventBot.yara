rule Trojan_AndroidOS_EventBot_B_2147798810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/EventBot.B!MTB"
        threat_id = "2147798810"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "EventBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot] [access] onAccessibilityEventFired" ascii //weight: 1
        $x_1_2 = "gate_cb8a5aea1ab302f0" ascii //weight: 1
        $x_1_3 = "com.example.eventbot" ascii //weight: 1
        $x_1_4 = "studiolegalebasili.com" ascii //weight: 1
        $x_1_5 = "func] [service] onStartCommand" ascii //weight: 1
        $x_1_6 = "com/example/eventbot/recvPushMsg" ascii //weight: 1
        $x_1_7 = "Lcom/libInterface$injectEvent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

