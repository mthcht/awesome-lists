rule Backdoor_AndroidOS_Colimas_A_2147827426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Colimas.A!MTB"
        threat_id = "2147827426"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Colimas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "findAccessibilityNodeInfosByViewId" ascii //weight: 1
        $x_1_2 = "Brsower_Record" ascii //weight: 1
        $x_1_3 = "com.css.adbclient" ascii //weight: 1
        $x_1_4 = "TelephoneInfo" ascii //weight: 1
        $x_1_5 = "backupApp" ascii //weight: 1
        $x_1_6 = "callsmsend" ascii //weight: 1
        $x_1_7 = "PHONE_WIFI_TRACK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

