rule TrojanSpy_AndroidOS_Monocle_B_2147816204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Monocle.B!MTB"
        threat_id = "2147816204"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Monocle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onAccessibilityEvent" ascii //weight: 1
        $x_1_2 = "keylog_messenger" ascii //weight: 1
        $x_1_3 = "NotifyMessenger" ascii //weight: 1
        $x_1_4 = "OtherNotify" ascii //weight: 1
        $x_1_5 = "keylog_other" ascii //weight: 1
        $x_1_6 = "AppendLineLongClickM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

