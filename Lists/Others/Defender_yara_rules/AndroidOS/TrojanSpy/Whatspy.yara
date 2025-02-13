rule TrojanSpy_AndroidOS_Whatspy_A_2147888108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Whatspy.A!MTB"
        threat_id = "2147888108"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Whatspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hideAppIcon" ascii //weight: 1
        $x_1_2 = "Lcom/notifier/hidden" ascii //weight: 1
        $x_1_3 = "notifier.log" ascii //weight: 1
        $x_1_4 = "Lcom/internalapp/logger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

