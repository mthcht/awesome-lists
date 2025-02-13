rule TrojanSpy_AndroidOS_AndroRAT_A_2147809014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/AndroRAT.A!MTB"
        threat_id = "2147809014"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "AndroRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STOP_MONITOR_SMS" ascii //weight: 1
        $x_1_2 = "GET_CALL_LOGS" ascii //weight: 1
        $x_1_3 = "DATA_MONITOR_CALL" ascii //weight: 1
        $x_1_4 = "ACK_GIVE_CALL" ascii //weight: 1
        $x_1_5 = "KEY_SEND_MMS_NUMBER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

