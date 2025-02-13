rule MonitoringTool_AndroidOS_SpyApp_B_331793_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyApp.B!MTB"
        threat_id = "331793"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "waitScreenOnForRecord" ascii //weight: 1
        $x_1_2 = "createScreenCaptureIntent" ascii //weight: 1
        $x_1_3 = "stopscreensharing activity" ascii //weight: 1
        $x_1_4 = "_SmsRec_" ascii //weight: 1
        $x_1_5 = "notifyInCall" ascii //weight: 1
        $x_5_6 = "spyapp." ascii //weight: 5
        $x_1_7 = "unlookAudioCall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

