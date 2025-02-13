rule Trojan_AndroidOS_Maistealer_A_2147782885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Maistealer.A!MTB"
        threat_id = "2147782885"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Maistealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tubeflic_es_comActivity" ascii //weight: 1
        $x_1_2 = "com/tubeflic_es/com" ascii //weight: 1
        $x_1_3 = "hasSentFirstSMS" ascii //weight: 1
        $x_1_4 = "SmsReceiverHelper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Maistealer_A_2147782885_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Maistealer.A!MTB"
        threat_id = "2147782885"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Maistealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mailaddress get!" ascii //weight: 1
        $x_1_2 = "strMailList" ascii //weight: 1
        $x_1_3 = "addresscap/list.log" ascii //weight: 1
        $x_1_4 = "consumeContent" ascii //weight: 1
        $x_1_5 = "postMailList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

