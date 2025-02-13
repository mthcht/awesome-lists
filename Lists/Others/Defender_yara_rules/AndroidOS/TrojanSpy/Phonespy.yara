rule TrojanSpy_AndroidOS_Phonespy_A_2147795488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Phonespy.A"
        threat_id = "2147795488"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Phonespy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "uploadCallLogs" ascii //weight: 2
        $x_2_2 = "LAST_CALL_LOG_NUM" ascii //weight: 2
        $x_2_3 = "ALREADY_HIDE_ICON" ascii //weight: 2
        $x_2_4 = "LAST_SMS_NUM" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

