rule TrojanSpy_AndroidOS_Mogap_A_2147833054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mogap.A!MTB"
        threat_id = "2147833054"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mogap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMS_OFF_MSG" ascii //weight: 1
        $x_1_2 = "SMSSendJob" ascii //weight: 1
        $x_1_3 = "JHINMsgReceiver" ascii //weight: 1
        $x_1_4 = "com/servicejg/sec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

