rule Trojan_AndroidOS_SMSFlooder_A_2147786172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSFlooder.A!xp"
        threat_id = "2147786172"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSFlooder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w4.duoyi.com/p_user/DoNewActCards.aspx?gate=sw&jsoncallback=jQuery" ascii //weight: 1
        $x_1_2 = "www.loho88.com/activ_check_mobile.php?" ascii //weight: 1
        $x_1_3 = "zhg.zhuyousoft.com/index.php?s=/Sms/sendSms&phone" ascii //weight: 1
        $x_1_4 = "smsType=remoteLoginCtrlMsg" ascii //weight: 1
        $x_1_5 = "com.happy.papapa" ascii //weight: 1
        $x_1_6 = "takeScreenShot" ascii //weight: 1
        $x_1_7 = "www.fcbox.com/noshiro/retrievePhoneMessagePreventAttacks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

