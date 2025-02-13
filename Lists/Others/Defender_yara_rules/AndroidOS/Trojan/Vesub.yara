rule Trojan_AndroidOS_Vesub_A_2147819194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Vesub.A!MTB"
        threat_id = "2147819194"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Vesub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sys/modobom/sub/MainActivity" ascii //weight: 1
        $x_1_2 = "modobom.services/api/subs" ascii //weight: 1
        $x_1_3 = "notifi/NotificationPushMassage" ascii //weight: 1
        $x_1_4 = "sub/services/SmsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Vesub_M_2147898985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Vesub.M"
        threat_id = "2147898985"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Vesub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sys.modobom.sms2.services" ascii //weight: 1
        $x_1_2 = "NotificationPushMassage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

