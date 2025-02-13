rule MonitoringTool_AndroidOS_ICall_A_405910_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/ICall.A!MTB"
        threat_id = "405910"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "ICall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AudioMicSave" ascii //weight: 1
        $x_1_2 = "GPS_GET" ascii //weight: 1
        $x_1_3 = "ScreenOnReceiver" ascii //weight: 1
        $x_1_4 = "outTelno" ascii //weight: 1
        $x_1_5 = "startRecoding" ascii //weight: 1
        $x_10_6 = "com.google.android.ssl" ascii //weight: 10
        $x_10_7 = "com.google.ssl" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

