rule Trojan_AndroidOS_Jocker_E_2147829148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Jocker.E!MTB"
        threat_id = "2147829148"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Jocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskloader.lock" ascii //weight: 1
        $x_1_2 = "dx-ads.s3.us-east-2.amazonaws.com" ascii //weight: 1
        $x_1_3 = "com.third.A" ascii //weight: 1
        $x_1_4 = "cdn.healthcheckerout.com" ascii //weight: 1
        $x_1_5 = "toNotificationSettingsUI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

