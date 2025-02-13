rule Trojan_AndroidOS_Hyspu_A_2147784804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hyspu.A!MTB"
        threat_id = "2147784804"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hyspu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PayEntry" ascii //weight: 1
        $x_1_2 = "sms delete ctrl" ascii //weight: 1
        $x_1_3 = "rem_fee_begin" ascii //weight: 1
        $x_1_4 = "sms_rem_interval" ascii //weight: 1
        $x_1_5 = "newpaysdk" ascii //weight: 1
        $x_1_6 = "cnfSmsFilter match" ascii //weight: 1
        $x_1_7 = "SmsSendCallback onSendSuccess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

