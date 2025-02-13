rule Trojan_AndroidOS_Revive_A_2147824156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Revive.A"
        threat_id = "2147824156"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Revive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "startKeyLister" ascii //weight: 10
        $x_10_2 = "readKeyLog" ascii //weight: 10
        $x_10_3 = "keylog_table" ascii //weight: 10
        $x_10_4 = "getKeyLogs" ascii //weight: 10
        $x_1_5 = "/sms/insert" ascii //weight: 1
        $x_1_6 = "/keylog/insert" ascii //weight: 1
        $x_1_7 = "SmsReciver" ascii //weight: 1
        $x_1_8 = "keylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

