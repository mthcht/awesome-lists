rule Trojan_iPhoneOS_YiSpecter_A_2147751585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/YiSpecter.A!MTB"
        threat_id = "2147751585"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "YiSpecter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.weiying.hiddenIconLaunch" ascii //weight: 2
        $x_1_2 = "iosnoico.bb800.com" ascii //weight: 1
        $x_1_3 = "HiddenIconRunBackground" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

