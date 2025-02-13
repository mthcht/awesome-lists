rule TrojanSpy_AndroidOS_HiddApp_A_2147764012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/HiddApp.A!MTB"
        threat_id = "2147764012"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "HiddApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "com/example/skysploit/Payloads" ascii //weight: 3
        $x_1_2 = "hideAppIcon" ascii //weight: 1
        $x_3_3 = "apaya-25263.portmap.io" ascii //weight: 3
        $x_1_4 = "content://call_log/calls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

