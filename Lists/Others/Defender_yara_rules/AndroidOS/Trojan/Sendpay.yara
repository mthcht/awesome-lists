rule Trojan_AndroidOS_SendPay_A_2147830158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SendPay.A!MTB"
        threat_id = "2147830158"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SendPay"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/talkweb/imoney/LoadMain" ascii //weight: 1
        $x_1_2 = "guaguadate" ascii //weight: 1
        $x_1_3 = "imoney.db" ascii //weight: 1
        $x_1_4 = "com/talkweb/imoney/almanac" ascii //weight: 1
        $x_1_5 = "ballBuyLog" ascii //weight: 1
        $x_1_6 = "BallBeanChoice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SendPay_B_2147830159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SendPay.B!MTB"
        threat_id = "2147830159"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SendPay"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/talkweb/easy/LoginActivity" ascii //weight: 1
        $x_1_2 = "destined_xhalf_free" ascii //weight: 1
        $x_1_3 = "free_astro_shapy" ascii //weight: 1
        $x_1_4 = "pay_astro_shapy" ascii //weight: 1
        $x_1_5 = "wiad_cache" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SendPay_E_2147831107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SendPay.E!MTB"
        threat_id = "2147831107"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SendPay"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/heroit/tzuwei/lite/MessageActivity" ascii //weight: 1
        $x_1_2 = "cn/mobile/Client/apk/imoney" ascii //weight: 1
        $x_1_3 = "sendMultipartTextMessage" ascii //weight: 1
        $x_1_4 = "mLuckMenShow" ascii //weight: 1
        $x_1_5 = "text/x-sms-number" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

