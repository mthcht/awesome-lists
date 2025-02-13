rule Trojan_AndroidOS_Golf_A_2147794753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Golf.A"
        threat_id = "2147794753"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Golf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "in SelfKiller kill" ascii //weight: 2
        $x_2_2 = "Camera file saved" ascii //weight: 2
        $x_2_3 = "getCallLogList" ascii //weight: 2
        $x_2_4 = "going to record video" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

