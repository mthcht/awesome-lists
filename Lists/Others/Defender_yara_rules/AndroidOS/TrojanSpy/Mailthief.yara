rule TrojanSpy_AndroidOS_Mailthief_A_2147830297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mailthief.A!MTB"
        threat_id = "2147830297"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mailthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isSpyCallEnabled" ascii //weight: 1
        $x_1_2 = "SPOOF_SMS" ascii //weight: 1
        $x_1_3 = "CAPTURE_CALLLOG" ascii //weight: 1
        $x_1_4 = "RemoteCameraActivity" ascii //weight: 1
        $x_1_5 = "CALL_WATCH_NOTIFICATION" ascii //weight: 1
        $x_1_6 = "CAPTURE_PASSWORD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

