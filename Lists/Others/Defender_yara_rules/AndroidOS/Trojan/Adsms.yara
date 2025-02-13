rule Trojan_AndroidOS_Adsms_A_2147783788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Adsms.A!MTB"
        threat_id = "2147783788"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Adsms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Evan.BackgroundSMS" ascii //weight: 1
        $x_1_2 = "IMICHAT_SERVICE" ascii //weight: 1
        $x_1_3 = "adsms.itodo.cn/Submit" ascii //weight: 1
        $x_1_4 = "IsFuckSend" ascii //weight: 1
        $x_1_5 = "killinstall" ascii //weight: 1
        $x_1_6 = "qqtlive.apk" ascii //weight: 1
        $x_1_7 = "SmsConfigURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

