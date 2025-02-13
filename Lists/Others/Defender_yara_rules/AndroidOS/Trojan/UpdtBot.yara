rule Trojan_AndroidOS_UpdtBot_A_2147782635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/UpdtBot.A!MTB"
        threat_id = "2147782635"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "UpdtBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aimSms" ascii //weight: 1
        $x_1_2 = "Interface/GetAndroidSms.ashx" ascii //weight: 1
        $x_1_3 = "nokia-upgrade.com" ascii //weight: 1
        $x_1_4 = "GetAndroidCall" ascii //weight: 1
        $x_1_5 = "TRANSACTION_getCallState" ascii //weight: 1
        $x_1_6 = "smstelphoneapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

