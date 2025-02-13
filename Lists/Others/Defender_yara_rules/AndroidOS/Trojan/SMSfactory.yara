rule Trojan_AndroidOS_SMSfactory_A_2147902066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSfactory.A!MTB"
        threat_id = "2147902066"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSfactory"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StacksSMSListener" ascii //weight: 1
        $x_1_2 = "sentSMS" ascii //weight: 1
        $x_1_3 = "androidapkworld.ads.mobilelinks" ascii //weight: 1
        $x_1_4 = "sms.service.mobilelinks.xyz" ascii //weight: 1
        $x_1_5 = "YANDEX_SMS_EVENT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

