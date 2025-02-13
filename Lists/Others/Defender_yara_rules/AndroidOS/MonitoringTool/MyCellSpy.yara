rule MonitoringTool_AndroidOS_MyCellSpy_A_330436_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MyCellSpy.A!MTB"
        threat_id = "330436"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MyCellSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "captureCall" ascii //weight: 1
        $x_1_2 = "takePhotoScreenLock" ascii //weight: 1
        $x_1_3 = "ChatUpload" ascii //weight: 1
        $x_1_4 = "hideicon" ascii //weight: 1
        $x_1_5 = "send_sms" ascii //weight: 1
        $x_1_6 = "delete_t_chat_history" ascii //weight: 1
        $x_1_7 = "createscreencaptureintent" ascii //weight: 1
        $x_1_8 = "my.cellInfo." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

