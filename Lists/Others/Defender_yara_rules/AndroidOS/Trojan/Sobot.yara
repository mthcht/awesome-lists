rule Trojan_AndroidOS_Sobot_A_2147894954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Sobot.A"
        threat_id = "2147894954"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Sobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "statusMesaj" ascii //weight: 1
        $x_1_2 = "AppService$LocalUserInfo" ascii //weight: 1
        $x_1_3 = "timerStopRefreshing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

