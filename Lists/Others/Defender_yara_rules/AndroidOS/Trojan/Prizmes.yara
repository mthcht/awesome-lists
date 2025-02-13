rule Trojan_AndroidOS_Prizmes_A_2147915778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Prizmes.A!MTB"
        threat_id = "2147915778"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Prizmes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoSendSmsService" ascii //weight: 1
        $x_1_2 = "CTelephoneInfo" ascii //weight: 1
        $x_1_3 = "dt.szprize.cn/mbinfo.php" ascii //weight: 1
        $x_1_4 = "interceptSmsReciever" ascii //weight: 1
        $x_1_5 = "updateTimesOfSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

