rule Trojan_AndroidOS_JSmsHider_A_2147783557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/JSmsHider.A!MTB"
        threat_id = "2147783557"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "JSmsHider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "show.calllog" ascii //weight: 1
        $x_1_2 = "dial.call" ascii //weight: 1
        $x_1_3 = "location/PhoneNumberQuery.dat" ascii //weight: 1
        $x_1_4 = "sms_isreceivedsmsreceiver" ascii //weight: 1
        $x_1_5 = "mCardNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_JSmsHider_B_2147845149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/JSmsHider.B!MTB"
        threat_id = "2147845149"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "JSmsHider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mobile.3gwldh.com" ascii //weight: 1
        $x_1_2 = "HandingCallListener" ascii //weight: 1
        $x_1_3 = "ACTION_LISTEN_SMS" ascii //weight: 1
        $x_1_4 = "SMSObserver" ascii //weight: 1
        $x_1_5 = "INTENAL_ACTION_PhoneCallRecord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

