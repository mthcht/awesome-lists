rule Trojan_AndroidOS_MMrat_A_2147891907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MMrat.A!MTB"
        threat_id = "2147891907"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MMrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Lcom/mm/user/ui/activity" ascii //weight: 10
        $x_1_2 = "uploadLockScreenPassword" ascii //weight: 1
        $x_1_3 = "cancelNoticeService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

