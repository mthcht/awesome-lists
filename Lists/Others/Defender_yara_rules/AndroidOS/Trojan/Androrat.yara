rule Trojan_AndroidOS_Androrat_A_2147744790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Androrat.A!MTB"
        threat_id = "2147744790"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Androrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsWatch.db" ascii //weight: 1
        $x_1_2 = "Lutils/PhoneMonitor;" ascii //weight: 1
        $x_1_3 = "STOP_MONITOR_SMS" ascii //weight: 1
        $x_1_4 = "delete from t_sms where id=?" ascii //weight: 1
        $x_1_5 = "hideInstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

