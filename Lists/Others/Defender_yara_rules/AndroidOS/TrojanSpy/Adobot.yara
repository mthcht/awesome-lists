rule TrojanSpy_AndroidOS_Adobot_C_2147831934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Adobot.C!MTB"
        threat_id = "2147831934"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Adobot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsForceUpload" ascii //weight: 1
        $x_1_2 = "TransferBotTask" ascii //weight: 1
        $x_1_3 = "SmsRecorderTask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

