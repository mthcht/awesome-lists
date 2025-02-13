rule Trojan_AndroidOS_uupay_A_2147784833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/uupay.A"
        threat_id = "2147784833"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "uupay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "downloadSuccessAd" ascii //weight: 2
        $x_2_2 = "key_ignore_uninstall_rubbish_tips" ascii //weight: 2
        $x_2_3 = "key_pro_killer_white_list" ascii //weight: 2
        $x_2_4 = "PUSH_CHECK_PERIOID" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

