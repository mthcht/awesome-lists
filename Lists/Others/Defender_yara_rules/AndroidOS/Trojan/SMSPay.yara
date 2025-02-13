rule Trojan_AndroidOS_SMSPay_A_2147835019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSPay.A!MTB"
        threat_id = "2147835019"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSPay"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tx.ittun.com/weixin" ascii //weight: 2
        $x_1_2 = "pay sms" ascii //weight: 1
        $x_1_3 = "ISendMessageListener" ascii //weight: 1
        $x_1_4 = "hasReadMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SMSPay_B_2147844750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSPay.B!MTB"
        threat_id = "2147844750"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSPay"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/veniso/mtrussliband" ascii //weight: 1
        $x_1_2 = "developerPayload" ascii //weight: 1
        $x_1_3 = "MTLibSMSReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

