rule TrojanSpy_AndroidOS_Recal_A_2147824162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Recal.A!MTB"
        threat_id = "2147824162"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Recal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "calldelete" ascii //weight: 1
        $x_1_2 = "sendSMS2Long" ascii //weight: 1
        $x_1_3 = "sendHttpGetNumbers" ascii //weight: 1
        $x_1_4 = "sendHttpGetMsgs" ascii //weight: 1
        $x_1_5 = "ImHereReceiver" ascii //weight: 1
        $x_1_6 = "cmd_getcontact" ascii //weight: 1
        $x_10_7 = "Lcom/example/callrecorder" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

