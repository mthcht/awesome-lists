rule Trojan_AndroidOS_SMSSend_A_2147785043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSSend.A!xp"
        threat_id = "2147785043"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSSend"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsapi.hejupay.com/getSmsSend.php" ascii //weight: 1
        $x_1_2 = "StartSmsPay]" ascii //weight: 1
        $x_1_3 = "SmsObserver" ascii //weight: 1
        $x_2_4 = "cmcc/g/online/s2sAutoChargeSMS?taskId=$taskId&pid=$pid&version=$version" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SMSSend_C_2147792914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSSend.C!xp"
        threat_id = "2147792914"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSSend"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deleteSendSms thread start" ascii //weight: 1
        $x_1_2 = "deleteSms -> " ascii //weight: 1
        $x_1_3 = "sendsms" ascii //weight: 1
        $x_1_4 = "appbox.db" ascii //weight: 1
        $x_1_5 = "DELIVERED_SMS_ACTION" ascii //weight: 1
        $x_1_6 = "SENT_SMS_ACTION" ascii //weight: 1
        $x_1_7 = "sendstatus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SMSSend_C_2147793792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSSend.C"
        threat_id = "2147793792"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSSend"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/reg/MainRegActivity" ascii //weight: 1
        $x_1_2 = "needShowLinkForm" ascii //weight: 1
        $x_1_3 = "displayFakeProgress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

